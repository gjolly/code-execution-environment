package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	executorSocket = "/run/execsock/exec.sock"
	// Host portion of the URL is ignored by the unix-socket dialer, but
	// http.NewRequest still needs a syntactically-valid URL.
	executorURL = "http://executor"

	// shimUpstreamIP is the address cvmimage pins for the shim's upstream
	// container (internal/containernet.ShimUpstreamIP). Binding the control
	// listener to it specifically — rather than to all interfaces — is what
	// keeps /exec and /audit/* unreachable from the sandbox network.
	shimUpstreamIP = "172.31.255.2"

	// shimNetCIDR is the fixed subnet of that private hop, excluded when
	// discovering our sandbox-facing address.
	shimNetCIDR = "172.31.255.0/30"

	proxyPort = "3128"
)

// 120s budget to cover  /snapshot and /restore bulk transfers at the
// /workspace tmpfs ceiling (512 MB plaintext → ~683 MB after base64 in the JSON body).
// It's the responsibility of the upstream caller to enforce a ceiling on eg tool calls
var executorClient = &http.Client{
	Timeout: 120 * time.Second,
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", executorSocket)
		},
	},
}

// lifecycle is the container's session state.
//
//   - warm: no user traffic yet. /restore is allowed (idempotent retry);
//     /exec, /read, /write, /snapshot transition to active.
//   - active: user traffic has begun. /restore returns 410; everything
//     else proceeds. A successful /snapshot transitions to killed.
//   - killed: snapshot taken, session over. Every call returns 410.
type lifecycle int

const (
	lifecycleWarm lifecycle = iota
	lifecycleActive
	lifecycleKilled
)

func (l lifecycle) String() string {
	switch l {
	case lifecycleWarm:
		return "warm"
	case lifecycleActive:
		return "active"
	case lifecycleKilled:
		return "killed"
	}
	return "unknown"
}

// gate is the container's per-lifetime access policy.
type gate struct {
	mu    sync.Mutex
	token string
	state lifecycle
}

var g = &gate{state: lifecycleWarm}

const authTokenHeader = "X-Code-Execution-Container-Auth-Token"

// checkAuth enforces the auth-token lock. First caller's non-empty
// token locks the gate; later callers must match.
//
// Status
//   - 401 missing token
//   - 403 token mismatch
func (g *gate) checkAuth(tok string) (status int, msg string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok == "" {
		return http.StatusUnauthorized, "missing container auth token", false
	}
	if g.token == "" {
		g.token = tok
		return 0, "", true
	}
	if subtle.ConstantTimeCompare([]byte(g.token), []byte(tok)) != 1 {
		return http.StatusForbidden, "container auth token mismatch", false
	}
	return 0, "", true
}

// checkLifecycle enforces only the state machine
//
// Status
//   - 410 lifecycle disallows this call
func (g *gate) checkLifecycle(path string) (status int, msg string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.state {
	case lifecycleKilled:
		return http.StatusGone, "container session ended", false
	case lifecycleActive:
		if path == "/restore" {
			return http.StatusGone, "restore window closed", false
		}
	case lifecycleWarm:
		// /restore is idempotent and stays in warm
		switch path {
		case "/restore":
			// idempotent - stay warm
		case "/snapshot":
			return http.StatusGone, "cannot snapshot a warm container", false
		default:
			g.state = lifecycleActive
		}
	}
	return 0, "", true
}

// check runs auth + lifecycle for user-driven paths.
func (g *gate) check(path, tok string) (status int, msg string, ok bool) {
	if status, msg, ok := g.checkAuth(tok); !ok {
		return status, msg, false
	}
	return g.checkLifecycle(path)
}

// markKilled is called after a successful /snapshot transfer to close
// the container for any further calls.
func (g *gate) markKilled() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = lifecycleKilled
}

// writeJSONError responds with a JSON {"error": "<msg>"} body and the
// given status. Uses %q so quotes/control characters in msg are escaped.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

// auditRecorder is set at startup; nil only in tests that exercise the gate
// alone.
var auditRecorder *AuditLog

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := r.URL.Path

	// Every path takes the same auth + lifecycle gate. /snapshot used to skip
	// the auth-token check, which let anyone who could reach this port
	// exfiltrate the workspace and permanently kill the session. The
	// orchestrator already holds the token when it snapshots.
	status, msg, ok := g.check(path, r.Header.Get(authTokenHeader))
	if !ok {
		log.Printf("api-server: gating %s — %s (%d)", path, msg, status)
		writeJSONError(w, status, msg)
		return
	}

	// Buffer the request for the small, audit-relevant paths so the command
	// or file path can be recorded in the clear. Bulk transfers stream.
	var reqBody []byte
	body := r.Body
	if auditableRequest(path) {
		var err error
		reqBody, err = io.ReadAll(io.LimitReader(r.Body, maxAuditableBody))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "reading request: "+err.Error())
			return
		}
		body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// Inherit the inbound request's context so the orchestrator's
	// cancellation/deadline propagates to the executor — otherwise the
	// executor keeps churning on a request whose result is already
	// going to be discarded.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, executorURL+path, body)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := executorClient.Do(req)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "executor unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Resend trailer showing streaming finished
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	var copyErr error
	if auditableRequest(path) {
		var respBody []byte
		respBody, copyErr = io.ReadAll(io.LimitReader(resp.Body, maxAuditableBody))
		if copyErr == nil {
			_, copyErr = w.Write(respBody)
		}
		recordToolCall(path, reqBody, respBody, resp.StatusCode, time.Since(start))
	} else {
		// Bulk paths: hash the stream rather than hold it.
		salt := NewSalt()
		hc := salt.Hasher()
		_, copyErr = io.Copy(io.MultiWriter(w, hc), resp.Body)
		recordBulk(path, salt, hc, resp.StatusCode, time.Since(start))
	}

	// resp.Trailer values are populated only after the body has been
	// fully read.
	maps.Copy(w.Header(), resp.Trailer)

	// A successful /snapshot is the terminal event in the container's
	// lifecycle. The executor signals clean completion via the snapshot
	// trailer
	if path == "/snapshot" &&
		resp.StatusCode == http.StatusOK &&
		copyErr == nil &&
		resp.Trailer.Get(snapshotTrailer) == "ok" {
		g.markKilled()
	}
}

// maxAuditableBody bounds what we are willing to buffer in order to record a
// structured entry. Beyond it we fall back to hashing the stream.
const maxAuditableBody = 32 << 20

func auditableRequest(path string) bool {
	switch path {
	case "/exec", "/read", "/write", "/sync-uploads/manifest", "/sync-uploads/blobs":
		return true
	}
	return false
}

// recordToolCall appends the audit entry for one tool call. Commands and paths
// are recorded in the clear — they are the action being audited. Outputs are
// recorded only as salted hashes and lengths: the caller already holds the
// bytes, so the hash lets them prove an entry matches what they received.
func recordToolCall(path string, reqBody, respBody []byte, status int, dur time.Duration) {
	if auditRecorder == nil {
		return
	}
	salt := NewSalt()

	switch path {
	case "/exec":
		var req struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(reqBody, &req)
		var resp struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int    `json:"exit_code"`
		}
		parsed := json.Unmarshal(respBody, &resp) == nil

		_, err := auditRecorder.Append(EntryExec, salt, struct {
			Command    string `json:"command"`
			ExitCode   int    `json:"exit_code"`
			StdoutSHA  string `json:"stdout_sha256"`
			StdoutLen  int    `json:"stdout_bytes"`
			StderrSHA  string `json:"stderr_sha256"`
			StderrLen  int    `json:"stderr_bytes"`
			DurationMS int64  `json:"duration_ms"`
			Parsed     bool   `json:"parsed"`
			Status     int    `json:"status"`
		}{
			Command:    req.Command,
			ExitCode:   resp.ExitCode,
			StdoutSHA:  salt.Hash([]byte(resp.Stdout)),
			StdoutLen:  len(resp.Stdout),
			StderrSHA:  salt.Hash([]byte(resp.Stderr)),
			StderrLen:  len(resp.Stderr),
			DurationMS: dur.Milliseconds(),
			Parsed:     parsed,
			Status:     status,
		})
		if err != nil {
			log.Printf("api-server: audit append failed for /exec: %v", err)
		}

	case "/read", "/write":
		var req struct {
			Path     string `json:"path"`
			Contents string `json:"contents"`
		}
		_ = json.Unmarshal(reqBody, &req)
		typ := EntryFileRead
		payload := respBody
		if path == "/write" {
			typ = EntryFileWrite
			payload = []byte(req.Contents)
		}
		_, err := auditRecorder.Append(typ, salt, struct {
			Path       string `json:"path"`
			SHA256     string `json:"sha256"`
			Bytes      int    `json:"bytes"`
			Status     int    `json:"status"`
			DurationMS int64  `json:"duration_ms"`
		}{req.Path, salt.Hash(payload), len(payload), status, dur.Milliseconds()})
		if err != nil {
			log.Printf("api-server: audit append failed for %s: %v", path, err)
		}

	default: // /sync-uploads/*
		_, err := auditRecorder.Append(EntryUpload, salt, struct {
			Path       string `json:"path"`
			SHA256     string `json:"sha256"`
			Bytes      int    `json:"bytes"`
			Status     int    `json:"status"`
			DurationMS int64  `json:"duration_ms"`
		}{path, salt.Hash(reqBody), len(reqBody), status, dur.Milliseconds()})
		if err != nil {
			log.Printf("api-server: audit append failed for %s: %v", path, err)
		}
	}
}

func recordBulk(path string, salt Salt, hc *HashCounter, status int, dur time.Duration) {
	if auditRecorder == nil {
		return
	}
	_, err := auditRecorder.Append(EntrySnapshot, salt, struct {
		Path       string `json:"path"`
		SHA256     string `json:"sha256"`
		Bytes      int64  `json:"bytes"`
		Status     int    `json:"status"`
		DurationMS int64  `json:"duration_ms"`
	}{path, hc.Sum(), hc.Count(), status, dur.Milliseconds()})
	if err != nil {
		log.Printf("api-server: audit append failed for %s: %v", path, err)
	}
}

// snapshotTrailer must match executor's snapshot trailer name. Kept as a
// string here so api-server doesn't have to import the executor package.
const snapshotTrailer = "X-Snapshot-Status"

// healthHandler reports api-server health AND executor health. Returns
// 200 only when both are reachable; otherwise 503
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !executorHealthy(r.Context()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// executorHealthy probes the executor's /health over the unix socket
func executorHealthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, executorURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := executorClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// pushSessionInit hands the executor its proxy address and the interception CA.
//
// The executor cannot learn these on its own: user-declared Docker networks get
// dynamic IPAM (only shim-net is pinned by cvmimage), so the proxy address is
// not knowable at image-build time, and with no resolver in the sandbox there
// is nothing to look it up with. Pushing over the existing unix socket keeps
// the direction of trust intact — api-server to executor, never the reverse.
func pushSessionInit(ctx context.Context, proxyURL, caPEM string) {
	payload, err := json.Marshal(map[string]string{
		"proxy_url": proxyURL,
		"ca_pem":    caPEM,
		"no_proxy":  "localhost,127.0.0.1",
	})
	if err != nil {
		log.Printf("api-server: marshaling session init: %v", err)
		return
	}

	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			executorURL+"/session/init", bytes.NewReader(payload))
		if err != nil {
			log.Printf("api-server: building session init: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := executorClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("api-server: executor session init ok (proxy=%s)", proxyURL)
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		if attempt%10 == 1 {
			log.Printf("api-server: session init not yet accepted (%v), retrying", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// sandboxIP finds the address the executor should send proxy traffic to: our
// IPv4 on some bridge other than the private shim hop.
func sandboxIP() (string, error) {
	_, shimNet, err := net.ParseCIDR(shimNetCIDR)
	if err != nil {
		return "", err
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || shimNet.Contains(ip) {
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("no sandbox-facing IPv4 address found")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	audit := NewAuditLog()
	auditRecorder = audit

	// Blocks until cvmimage's boot has written the key; see checkpoint.go for
	// why this container holds it at all.
	signer, err := LoadSigner(3 * time.Minute)
	if err != nil {
		log.Fatalf("api-server: %v", err)
	}
	signer.logReady()

	ca, err := NewCA()
	if err != nil {
		log.Fatalf("api-server: %v", err)
	}
	log.Printf("api-server: egress CA ready, sha256=%s", ca.Fingerprint())

	proxy := NewEgressProxy(audit, ca)
	api := &auditAPI{audit: audit, signer: signer, proxy: proxy, ca: ca}

	// Control mux: tool calls plus the audit surface. Bound to the shim-net
	// address only, so nothing on the sandbox network can reach it.
	control := http.NewServeMux()
	control.HandleFunc("/exec", proxyHandler)
	control.HandleFunc("/read", proxyHandler)
	control.HandleFunc("/write", proxyHandler)
	control.HandleFunc("/snapshot", proxyHandler)
	control.HandleFunc("/restore", proxyHandler)
	control.HandleFunc("/sync-uploads/manifest", proxyHandler)
	control.HandleFunc("/sync-uploads/blobs", proxyHandler)
	control.HandleFunc("/health", healthHandler)
	control.HandleFunc("/audit/head", api.handleHead)
	control.HandleFunc("/audit/log", api.handleLog)
	control.HandleFunc("/audit/session", api.handleSession)
	control.HandleFunc("/audit/resume", api.handleResume)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tell the executor where to send its traffic. Best-effort discovery: in
	// local dev without the sandbox bridge, the proxy is still served, it just
	// cannot be advertised.
	if ip, err := sandboxIP(); err != nil {
		log.Printf("api-server: %v; executor will not be given a proxy", err)
	} else {
		go pushSessionInit(ctx, "http://"+net.JoinHostPort(ip, proxyPort), ca.CertPEM())
	}

	go func() {
		addr := envOr("PROXY_LISTEN", ":"+proxyPort)
		log.Printf("api-server: egress proxy listening on %s", addr)
		srv := &http.Server{Addr: addr, Handler: proxy}
		log.Fatalf("api-server: egress proxy: %v", srv.ListenAndServe())
	}()

	// CONTROL_LISTEN exists for local dev; in the CVM this must stay pinned to
	// the shim-net address. Binding to all interfaces here would expose /exec
	// and the transcript to the sandbox.
	addr := envOr("CONTROL_LISTEN", shimUpstreamIP+":8000")
	log.Printf("api-server: control listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, control))
}

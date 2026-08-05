// The egress proxy: the sandbox's only route to the internet, and therefore
// the only place a complete record of that traffic can be made.
//
// Completeness is not enforced here — it is enforced by nftables. The executor
// sits on a network declared `egress: closed` in tinfoil-config.yml, so the
// bridge has no forward rule and packets that skip this proxy are dropped by
// the kernel. The HTTP_PROXY variables handed to bash are ergonomics: they
// decide whether bypassing the proxy fails *usefully* rather than whether it
// is possible. That distinction is what lets the audit log claim completeness,
// and it is covered by the launch measurement.
//
// This listener binds to the sandbox-facing interface and serves proxy
// protocol only. It must never expose the control mux (/exec, /audit/*): the
// executor is untrusted and must not be able to read the transcript or alter
// the policy that governs it.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	originDialTimeout   = 10 * time.Second
	originTLSTimeout    = 10 * time.Second
	defaultMaxRespBytes = 256 << 20
)

// headerValueAllowlist names the request headers whose *values* are safe to
// record. Every header name is always recorded; values are not, because the
// sandbox's own credentials travel in them and the transcript is readable by
// the orchestrator. Authorization and Cookie are hashed instead.
var headerValueAllowlist = map[string]bool{
	"content-type":    true,
	"content-length":  true,
	"user-agent":      true,
	"accept":          true,
	"accept-encoding": true,
}

var hashedHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
	"x-api-key":           true,
}

// EgressProxy serves the sandbox-facing forward proxy.
type EgressProxy struct {
	audit  *AuditLog
	ca     *CA
	policy atomic.Pointer[EffectivePolicy]
}

func NewEgressProxy(audit *AuditLog, ca *CA) *EgressProxy {
	return &EgressProxy{audit: audit, ca: ca}
}

// SetPolicy swaps the enforced policy. Called from the control listener only.
func (p *EgressProxy) SetPolicy(e *EffectivePolicy) { p.policy.Store(e) }

func (p *EgressProxy) currentPolicy() *EffectivePolicy { return p.policy.Load() }

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Absolute-form request line: a plain-HTTP proxy request. Anything else is
	// an origin-form request, which means something tried to talk to this
	// listener as if it were a web server. There is nothing here to serve.
	if !r.URL.IsAbs() {
		http.Error(w, "this port serves the egress proxy only", http.StatusBadRequest)
		return
	}
	p.handlePlain(w, r)
}

// refuse denies a request before it leaves, recording why.
func (p *EgressProxy) refuse(rawurl, method, rule, reason string) {
	salt := NewSalt()
	if _, err := p.audit.Append(EntryNetDeny, salt, struct {
		Method string `json:"method"`
		URL    string `json:"url"`
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}{method, rawurl, rule, reason}); err != nil {
		log.Printf("api-server: audit append failed for denial of %s: %v", rawurl, err)
	}
}

// gate applies the fail-closed checks common to every egress attempt.
func (p *EgressProxy) gate(rawurl, method string) (pol *EffectivePolicy, tunnel bool, err error) {
	// A saturated log means we can no longer record what happens, so nothing
	// further is allowed to happen. Never fail silent.
	if p.audit.Saturated() {
		return nil, false, errors.New("audit log saturated; egress refused")
	}
	pol = p.currentPolicy()
	if pol == nil {
		p.refuse(rawurl, method, "no-policy", "no session policy installed")
		return nil, false, errors.New("no session policy installed")
	}
	allowed, tunnel, rule := pol.Decide(rawurl)
	if !allowed {
		p.refuse(rawurl, method, rule, "denied by policy")
		return nil, false, fmt.Errorf("denied by policy (%s)", rule)
	}
	return pol, tunnel, nil
}

// gateHost applies the fail-closed checks at CONNECT time, where only the host
// is known. Admission is host-granular; path scoping is enforced later, per
// request, by gate. Denials are recorded against the host, the finest URL we can
// attribute them to here.
func (p *EgressProxy) gateHost(host string) (tunnel bool, err error) {
	if p.audit.Saturated() {
		return false, errors.New("audit log saturated; egress refused")
	}
	pol := p.currentPolicy()
	if pol == nil {
		p.refuse("https://"+host+"/", http.MethodConnect, "no-policy", "no session policy installed")
		return false, errors.New("no session policy installed")
	}
	allowed, tunnel, rule := pol.AdmitHost(host)
	if !allowed {
		p.refuse("https://"+host+"/", http.MethodConnect, rule, "denied by policy")
		return false, fmt.Errorf("denied by policy (%s)", rule)
	}
	return tunnel, nil
}

// ---------- CONNECT ----------

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, "443")
	// At CONNECT time only the host is known, so admission is host-granular.
	// Interception re-checks each request against the full URL; tunnel-only
	// hosts get host granularity and nothing more, which the audit entry states
	// explicitly.
	tunnel, err := p.gateHost(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	mode := "mitm"
	if tunnel {
		mode = "tunnel"
	}
	id := randHex(16)
	reservation, err := p.audit.Admit(EntryNetConnectIntent, NewSalt(), struct {
		ID   string `json:"id"`
		Host string `json:"host"`
		Port string `json:"port"`
		Mode string `json:"mode"`
	}{id, host, port, mode})
	if err != nil {
		http.Error(w, "cannot audit connection", http.StatusInsufficientStorage)
		return
	}
	result := &connectResult{id: id, mode: mode, outcome: "closed", startedAt: time.Now()}
	defer p.completeConnect(reservation, result)

	hj, ok := w.(http.Hijacker)
	if !ok {
		result.outcome = "hijack-unavailable"
		http.Error(w, "cannot hijack connection", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		result.outcome = "hijack-failed"
		result.err = err.Error()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), originDialTimeout)
	if err != nil {
		result.outcome = "dial-failed"
		result.err = err.Error()
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		p.refuse("https://"+host+"/", http.MethodConnect, "upstream", "dial failed: "+err.Error())
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		result.outcome = "client-write-failed"
		result.err = err.Error()
		return
	}

	if tunnel {
		p.tunnel(client, upstream, result)
		return
	}
	p.intercept(client, upstream, host, port, result)
}

type connectResult struct {
	id, mode, outcome, err string
	bytesUp, bytesDown     int64
	startedAt              time.Time
}

func (p *EgressProxy) completeConnect(reservation *AuditReservation, result *connectResult) {
	typ := EntryNetConnect
	if result.mode == "tunnel" {
		typ = EntryNetTunnel
	}
	if err := reservation.Complete(typ, NewSalt(), struct {
		ID         string `json:"id"`
		BytesUp    int64  `json:"bytes_up"`
		BytesDown  int64  `json:"bytes_down"`
		Outcome    string `json:"outcome"`
		Error      string `json:"error,omitempty"`
		Mode       string `json:"mode"`
		DurationMS int64  `json:"duration_ms"`
	}{result.id, result.bytesUp, result.bytesDown, result.outcome, result.err, result.mode, time.Since(result.startedAt).Milliseconds()}); err != nil {
		log.Printf("api-server: audit append failed for connection completion: %v", err)
	}
}

// tunnel copies bytes opaquely for hosts the policy marks tunnel-only.
//
// The record is necessarily thin: the CONNECT target, the ClientHello SNI, and
// byte counts. There is no method, URL, or origin certificate hash — TLS 1.3
// encrypts the Certificate message, so a passthrough proxy cannot observe it.
func (p *EgressProxy) tunnel(client, upstream net.Conn, result *connectResult) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result.bytesUp, _ = io.Copy(upstream, client)
		if c, ok := upstream.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		result.bytesDown, _ = io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()
	wg.Wait()
}

// intercept terminates TLS under a minted leaf and forwards each request,
// verifying the origin normally on the upstream leg.
func (p *EgressProxy) intercept(client, upstream net.Conn, host, port string, result *connectResult) {
	leaf, err := p.ca.LeafFor(host)
	if err != nil {
		result.outcome = "leaf-failed"
		result.err = err.Error()
		log.Printf("api-server: minting leaf for %s: %v", host, err)
		return
	}

	clientTLS := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		result.outcome = "client-tls-failed"
		result.err = err.Error()
		// Commonly a cert-pinning client. Record it: a pinned client failing
		// is a policy-relevant event, not noise.
		p.refuse("https://"+host+"/", http.MethodConnect, "mitm", "client rejected interception: "+err.Error())
		return
	}
	defer clientTLS.Close()

	originTLS := tls.Client(upstream, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	hsCtx, cancel := context.WithTimeout(context.Background(), originTLSTimeout)
	defer cancel()
	if err := originTLS.HandshakeContext(hsCtx); err != nil {
		result.outcome = "origin-tls-failed"
		result.err = err.Error()
		p.refuse("https://"+host+"/", http.MethodConnect, "upstream", "origin TLS failed: "+err.Error())
		return
	}
	defer originTLS.Close()

	originFP := ""
	if st := originTLS.ConnectionState(); len(st.PeerCertificates) > 0 {
		sum := sha256.Sum256(st.PeerCertificates[0].Raw)
		originFP = hex.EncodeToString(sum[:])
	}

	p.pump(clientTLS, originTLS, "https", host, port, originFP)
}

// pump reads requests off the intercepted connection and forwards them,
// recording each. Keep-alive is honoured: one CONNECT may carry many requests.
func (p *EgressProxy) pump(client, origin net.Conn, scheme, host, port, originFP string) {
	clientReader := bufio.NewReader(client)
	originReader := bufio.NewReader(origin)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return // EOF or malformed; the tunnel is done
		}

		rawurl := scheme + "://" + host
		if port != "443" && port != "80" {
			rawurl += ":" + port
		}
		rawurl += req.URL.RequestURI()

		pol, _, gErr := p.gate(rawurl, req.Method)
		if gErr != nil {
			writeSimpleResponse(client, http.StatusForbidden, gErr.Error())
			return
		}

		if err := p.forward(client, origin, originReader, req, rawurl, originFP, pol); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

// forward proxies one intercepted request and appends its audit entry.
func (p *EgressProxy) forward(
	client net.Conn, origin net.Conn, originReader *bufio.Reader,
	req *http.Request, rawurl, originFP string, pol *EffectivePolicy,
) error {
	start := time.Now()
	salt := NewSalt()

	reqHash := salt.Hasher()
	if req.Body != nil {
		req.Body = io.NopCloser(io.TeeReader(req.Body, reqHash))
	}

	// Strip hop-by-hop headers before relaying.
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	names, values := recordHeaders(req.Header, salt)
	id := randHex(16)
	reservation, err := p.audit.Admit(EntryNetRequestIntent, salt, struct {
		ID           string            `json:"id"`
		Method       string            `json:"method"`
		URL          string            `json:"url"`
		Host         string            `json:"host"`
		ReqHeaders   []string          `json:"req_headers"`
		ReqHdrValues map[string]string `json:"req_header_values"`
		Decision     string            `json:"decision"`
		Mode         string            `json:"mode"`
	}{id, req.Method, rawurl, req.Host, names, values, "allow", "mitm"})
	if err != nil {
		writeSimpleResponse(client, http.StatusInsufficientStorage, "cannot audit request")
		return err
	}

	if err := req.Write(origin); err != nil {
		p.completeRequestError(reservation, id, err, time.Since(start), "mitm")
		p.refuse(rawurl, req.Method, "upstream", "write failed: "+err.Error())
		writeSimpleResponse(client, http.StatusBadGateway, "upstream write failed")
		return err
	}

	resp, err := http.ReadResponse(originReader, req)
	if err != nil {
		p.completeRequestError(reservation, id, err, time.Since(start), "mitm")
		p.refuse(rawurl, req.Method, "upstream", "read failed: "+err.Error())
		writeSimpleResponse(client, http.StatusBadGateway, "upstream read failed")
		return err
	}
	defer resp.Body.Close()

	maxResp := pol.Effective.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = defaultMaxRespBytes
	}

	respHash := salt.Hasher()
	truncated := false
	body := io.Reader(resp.Body)
	if resp.ContentLength < 0 || resp.ContentLength > maxResp {
		body = io.LimitReader(resp.Body, maxResp)
	}
	resp.Body = io.NopCloser(io.TeeReader(body, respHash))

	writeErr := resp.Write(client)
	if respHash.Count() >= maxResp {
		truncated = true
	}

	if err := reservation.Complete(EntryNetRequest, salt, struct {
		ID           string            `json:"id"`
		Method       string            `json:"method"`
		URL          string            `json:"url"`
		Host         string            `json:"host"`
		ReqHeaders   []string          `json:"req_headers"`
		ReqHdrValues map[string]string `json:"req_header_values"`
		ReqBodySHA   string            `json:"req_body_sha256"`
		ReqBytes     int64             `json:"req_bytes"`
		Status       int               `json:"status"`
		RespBodySHA  string            `json:"resp_body_sha256"`
		RespBytes    int64             `json:"resp_bytes"`
		Truncated    bool              `json:"truncated"`
		OriginCert   string            `json:"origin_cert_sha256"`
		DurationMS   int64             `json:"duration_ms"`
		Decision     string            `json:"decision"`
		Mode         string            `json:"mode"`
	}{
		ID:           id,
		Method:       req.Method,
		URL:          rawurl,
		Host:         req.Host,
		ReqHeaders:   names,
		ReqHdrValues: values,
		ReqBodySHA:   reqHash.Sum(),
		ReqBytes:     reqHash.Count(),
		Status:       resp.StatusCode,
		RespBodySHA:  respHash.Sum(),
		RespBytes:    respHash.Count(),
		Truncated:    truncated,
		OriginCert:   originFP,
		DurationMS:   time.Since(start).Milliseconds(),
		Decision:     "allow",
		Mode:         "mitm",
	}); err != nil {
		log.Printf("api-server: audit append failed for %s: %v", rawurl, err)
	}

	return writeErr
}

// ---------- plain HTTP ----------

// handlePlain serves absolute-form http:// proxy requests. No interception is
// needed — the request line, headers and body are already in the clear.
func (p *EgressProxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	rawurl := r.URL.String()
	pol, _, err := p.gate(rawurl, r.Method)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	start := time.Now()
	salt := NewSalt()
	reqHash := salt.Hasher()

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, rawurl,
		io.NopCloser(io.TeeReader(r.Body, reqHash)))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	names, values := recordHeaders(r.Header, salt)
	id := randHex(16)
	reservation, err := p.audit.Admit(EntryNetRequestIntent, salt, struct {
		ID           string            `json:"id"`
		Method       string            `json:"method"`
		URL          string            `json:"url"`
		Host         string            `json:"host"`
		ReqHeaders   []string          `json:"req_headers"`
		ReqHdrValues map[string]string `json:"req_header_values"`
		Decision     string            `json:"decision"`
		Mode         string            `json:"mode"`
	}{id, r.Method, rawurl, r.Host, names, values, "allow", "plaintext"})
	if err != nil {
		http.Error(w, "cannot audit request", http.StatusInsufficientStorage)
		return
	}

	resp, err := plainTransport.RoundTrip(outReq)
	if err != nil {
		p.completeRequestError(reservation, id, err, time.Since(start), "plaintext")
		p.refuse(rawurl, r.Method, "upstream", err.Error())
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	maxResp := pol.Effective.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = defaultMaxRespBytes
	}
	respHash := salt.Hasher()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.TeeReader(io.LimitReader(resp.Body, maxResp), respHash))

	if err := reservation.Complete(EntryNetRequest, salt, struct {
		ID           string            `json:"id"`
		Method       string            `json:"method"`
		URL          string            `json:"url"`
		Host         string            `json:"host"`
		ReqHeaders   []string          `json:"req_headers"`
		ReqHdrValues map[string]string `json:"req_header_values"`
		ReqBodySHA   string            `json:"req_body_sha256"`
		ReqBytes     int64             `json:"req_bytes"`
		Status       int               `json:"status"`
		RespBodySHA  string            `json:"resp_body_sha256"`
		RespBytes    int64             `json:"resp_bytes"`
		Truncated    bool              `json:"truncated"`
		OriginCert   string            `json:"origin_cert_sha256"`
		DurationMS   int64             `json:"duration_ms"`
		Decision     string            `json:"decision"`
		Mode         string            `json:"mode"`
	}{
		ID:           id,
		Method:       r.Method,
		URL:          rawurl,
		Host:         r.Host,
		ReqHeaders:   names,
		ReqHdrValues: values,
		ReqBodySHA:   reqHash.Sum(),
		ReqBytes:     reqHash.Count(),
		Status:       resp.StatusCode,
		RespBodySHA:  respHash.Sum(),
		RespBytes:    respHash.Count(),
		Truncated:    respHash.Count() >= maxResp,
		OriginCert:   "",
		DurationMS:   time.Since(start).Milliseconds(),
		Decision:     "allow",
		Mode:         "plaintext",
	}); err != nil {
		log.Printf("api-server: audit append failed for %s: %v", rawurl, err)
	}
}

func (p *EgressProxy) completeRequestError(reservation *AuditReservation, id string, requestErr error, dur time.Duration, mode string) {
	if err := reservation.Complete(EntryNetRequest, NewSalt(), struct {
		ID         string `json:"id"`
		Error      string `json:"error"`
		DurationMS int64  `json:"duration_ms"`
		Mode       string `json:"mode"`
	}{id, requestErr.Error(), dur.Milliseconds(), mode}); err != nil {
		log.Printf("api-server: audit append failed for request completion: %v", err)
	}
}

var plainTransport http.RoundTripper = &http.Transport{
	DialContext:           (&net.Dialer{Timeout: originDialTimeout}).DialContext,
	ResponseHeaderTimeout: 60 * time.Second,
}

// ---------- helpers ----------

// recordHeaders returns every header name, plus values for the allowlisted
// ones and salted hashes for the credential-bearing ones. Values outside both
// sets are omitted entirely.
func recordHeaders(h http.Header, salt Salt) ([]string, map[string]string) {
	names := make([]string, 0, len(h))
	values := make(map[string]string, 4)
	for k, v := range h {
		lower := strings.ToLower(k)
		names = append(names, lower)
		switch {
		case headerValueAllowlist[lower]:
			values[lower] = strings.Join(v, ", ")
		case hashedHeaders[lower]:
			values[lower] = "sha256:" + salt.Hash([]byte(strings.Join(v, ", ")))
		}
	}
	return names, values
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func splitHostPort(hostport, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(hostport), defPort
}

func writeSimpleResponse(w io.Writer, status int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
}

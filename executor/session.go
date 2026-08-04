// Session init: the executor learns where its egress proxy is.
//
// It cannot work this out for itself. cvmimage gives user-declared Docker
// networks dynamic IPAM (only shim-net is pinned), so the api-server's
// sandbox-side address is unknown at image-build time — and with the proxy
// doing all name resolution there is no resolver here to look it up with. So
// api-server pushes the address and its interception CA over the execsock unix
// socket, preserving the direction of trust: api-server drives the executor,
// never the reverse.
//
// These variables are ergonomics, not enforcement. The sandbox network is
// declared `egress: closed` in tinfoil-config.yml, so nftables drops anything
// that skips the proxy. Setting them decides whether bypassing the proxy fails
// *usefully* rather than whether it is possible.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

// caPath lives on the /tmp tmpfs: the container rootfs is read-only, and this
// is the only writable location the bash uid can also read.
const caPath = "/tmp/tinfoil-egress-ca.pem"

type sessionInitRequest struct {
	// ProxyCandidates are the api-server's addresses as CIDRs. It cannot pick
	// for us: it sits on three bridges and cvmimage attaches the egress-capable
	// one first, so its "first" address is most likely one we must not use. We
	// have exactly one interface, so we match on subnet.
	ProxyCandidates []string `json:"proxy_candidates"`
	ProxyPort       string   `json:"proxy_port"`
	CAPEM           string   `json:"ca_pem"`
	NoProxy         string   `json:"no_proxy"`
}

// selectProxy returns the candidate that shares a subnet with one of our own
// interfaces.
func selectProxy(candidates []string, port string) (string, error) {
	local, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	for _, c := range candidates {
		ip, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		for _, a := range local {
			mine, ok := a.(*net.IPNet)
			if !ok || mine.IP.To4() == nil || mine.IP.IsLoopback() {
				continue
			}
			if ipnet.Contains(mine.IP) {
				return "http://" + net.JoinHostPort(ip.String(), port), nil
			}
		}
	}
	return "", fmt.Errorf("no candidate in %v shares a subnet with this container", candidates)
}

var (
	sessionMu  sync.RWMutex
	proxyEnv   []string // fully-formed KEY=VALUE pairs for cmd.Env
	sessionSet bool
)

func handleSessionInit(w http.ResponseWriter, r *http.Request) {
	var req sessionInitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.ProxyCandidates) == 0 {
		respondError(w, http.StatusBadRequest, "proxy_candidates is required")
		return
	}
	if req.ProxyPort == "" {
		respondError(w, http.StatusBadRequest, "proxy_port is required")
		return
	}

	proxy, err := selectProxy(req.ProxyCandidates, req.ProxyPort)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	env := []string{
		"HTTP_PROXY=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"http_proxy=" + proxy,
		"https_proxy=" + proxy,
		"NO_PROXY=" + req.NoProxy,
		"no_proxy=" + req.NoProxy,
		// Node's built-in fetch ignores the proxy variables unless told to.
		"NODE_USE_ENV_PROXY=1",
	}

	if req.CAPEM != "" {
		// 0644: bash runs as uid 1001 while this process is 1000, so the
		// trust anchor has to be world-readable. It is a public certificate.
		if err := os.WriteFile(caPath, []byte(req.CAPEM), 0644); err != nil {
			respondError(w, http.StatusInternalServerError, "writing CA: "+err.Error())
			return
		}
		env = append(env,
			"SSL_CERT_FILE="+caPath,
			"REQUESTS_CA_BUNDLE="+caPath,
			"CURL_CA_BUNDLE="+caPath,
			"NODE_EXTRA_CA_CERTS="+caPath,
			"GIT_SSL_CAINFO="+caPath,
		)
	}

	sessionMu.Lock()
	proxyEnv = env
	sessionSet = true
	sessionMu.Unlock()

	log.Printf("executor: session init applied, proxy=%s", proxy)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// commandEnv builds the environment for a bash invocation: the inherited
// process environment plus the proxy settings.
func commandEnv() []string {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	env := os.Environ()
	if !sessionSet {
		return env
	}
	return append(env, proxyEnv...)
}

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGate_TokenClaimAndMatch(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	// First call claims the token.
	if _, _, ok := g.check("/restore", "tok-1"); !ok {
		t.Fatal("first call should be allowed")
	}
	if g.token != "tok-1" {
		t.Errorf("expected token claimed as %q, got %q", "tok-1", g.token)
	}

	// Subsequent call with the same token passes.
	if _, _, ok := g.check("/exec", "tok-1"); !ok {
		t.Fatal("matching token should be allowed")
	}
}

func TestGate_TokenMismatchReturns403(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	g.check("/restore", "tok-1") // claim

	status, _, ok := g.check("/exec", "tok-2")
	if ok {
		t.Fatal("mismatched token should be rejected")
	}
	if status != http.StatusForbidden {
		t.Errorf("expected 403, got %d", status)
	}
}

func TestGate_LifecycleWarmToActive(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	// Repeated /restore stays in warm (idempotent retry).
	g.check("/restore", "tok")
	g.check("/restore", "tok")
	if g.state != lifecycleWarm {
		t.Errorf("expected warm after /restore calls, got %s", g.state)
	}

	// First non-/restore call flips to active.
	g.check("/exec", "tok")
	if g.state != lifecycleActive {
		t.Errorf("expected active after /exec, got %s", g.state)
	}

	// /restore is now closed.
	status, _, ok := g.check("/restore", "tok")
	if ok {
		t.Fatal("/restore should be rejected once active")
	}
	if status != http.StatusGone {
		t.Errorf("expected 410, got %d", status)
	}
}

func TestGate_LifecycleKilledRejectsEverything(t *testing.T) {
	g := &gate{state: lifecycleWarm}
	g.check("/exec", "tok") // claim + go active
	g.markKilled()

	for _, path := range []string{"/exec", "/read", "/write", "/snapshot", "/restore"} {
		status, _, ok := g.check(path, "tok")
		if ok {
			t.Errorf("%s should be rejected once killed", path)
		}
		if status != http.StatusGone {
			t.Errorf("%s: expected 410, got %d", path, status)
		}
	}
}

// withFakeExecutor stands up an httptest server, points executorClient at
// it, and resets the package-level gate. Returned cleanup restores both.
func withFakeExecutor(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	addr := srv.Listener.Addr().String()

	oldClient := executorClient
	executorClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("tcp", addr)
			},
		},
	}

	oldGate := g
	g = &gate{state: lifecycleWarm}

	oldAudit := auditRecorder
	auditRecorder = NewAuditLog()

	return func() {
		srv.Close()
		executorClient = oldClient
		g = oldGate
		auditRecorder = oldAudit
	}
}

// activate moves the gate out of warm and claims the token, which /snapshot
// requires: a warm container has nothing worth snapshotting.
func activate(t *testing.T, token string) {
	t.Helper()
	if _, _, ok := g.check("/exec", token); !ok {
		t.Fatal("failed to activate gate")
	}
}

// Proxy must pass the executor's status code and body bytes through.
func TestProxy_ForwardsStatusAndBody(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, `{"forwarded":true}`)
	})()

	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(`{}`))
	req.Header.Set(authTokenHeader, "tok")
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusTeapot)
	}
	if got := w.Body.String(); got != `{"forwarded":true}` {
		t.Errorf("body: got %q, want forwarded body", got)
	}
}

func TestProxy_ExecAuditSurvivesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, `{"stdout":"done","stderr":"","exit_code":0}`)
	})()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(`{"command":"touch /workspace/proof"}`)).WithContext(ctx)
	req.Header.Set(authTokenHeader, "tok")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		proxyHandler(w, req)
		close(done)
	}()

	<-started
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not finish independently of caller cancellation")
	}

	lines := auditRecorder.Range(0, 0)
	if len(lines) != 2 {
		t.Fatalf("audit entries = %d, want intent and completion", len(lines))
	}
	for i, want := range []string{EntryExecIntent, EntryExec} {
		var entry Entry
		if err := json.Unmarshal(lines[i], &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type != want {
			t.Errorf("entry %d type = %s, want %s", i, entry.Type, want)
		}
	}
}

// A clean /snapshot 200 with the completion trailer must kill the gate.
func TestProxy_KillsAfterSnapshotWithTrailer(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", snapshotTrailer)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"tar":"AAAA"}`)
		w.Header().Set(snapshotTrailer, "ok")
	})()

	activate(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	req.Header.Set(authTokenHeader, "tok")
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if g.state != lifecycleKilled {
		t.Errorf("state: got %s, want killed", g.state)
	}
}

// 200 with no completion trailer simulates an executor that wrote 200,
// then errored mid-tar and returned without setting the trailer. The
// gate must stay open so the orchestrator can retry.
func TestProxy_DoesNotKillWithoutTrailer(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"tar":"truncated`) // no trailer, no closing }
	})()

	activate(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	req.Header.Set(authTokenHeader, "tok")
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if g.state == lifecycleKilled {
		t.Error("gate should not be killed without snapshot completion trailer")
	}
}

// /health returns 200 when executor responds 200.
func TestHealth_BothHealthy(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
}

// /health returns 503 when executor returns non-200.
func TestHealth_ExecutorDown(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	})()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	healthHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", w.Code)
	}
}

// /snapshot must require the auth token like every other path. It used to
// bypass it, which let anyone able to reach this port exfiltrate the workspace
// and permanently kill the session. The orchestrator already holds the token
// when it snapshots, so there is no reason to exempt it.
func TestProxy_SnapshotRequiresAuthToken(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"tar":"AAAA"}`)
	})()

	req := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	// Intentionally no authTokenHeader set.
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (snapshot must not bypass auth)", w.Code)
	}
	if g.state == lifecycleKilled {
		t.Error("an unauthenticated snapshot must not kill the session")
	}
}

// User-driven paths still require the auth token. /exec without one
// must 401.
func TestProxy_ExecRequiresAuthToken(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})()

	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(`{}`))
	// No authTokenHeader.
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", w.Code)
	}
}

// A non-200 /snapshot must not kill the gate — orchestrator can retry.
func TestProxy_DoesNotKillOnSnapshotError(t *testing.T) {
	defer withFakeExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})()

	activate(t, "tok")

	req := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	req.Header.Set(authTokenHeader, "tok")
	w := httptest.NewRecorder()
	proxyHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", w.Code)
	}
	if g.state == lifecycleKilled {
		t.Error("gate should not be killed when executor returned 500")
	}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// replay recomputes the chain the way an external verifier does: hash the
// exact bytes of each line and check each entry's prev against the previous
// hash. Returns the head it arrives at.
func replay(t *testing.T, lines [][]byte) string {
	t.Helper()
	prev := ""
	for i, raw := range lines {
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if e.Prev != prev {
			t.Fatalf("entry %d: prev = %q, want %q", i, e.Prev, prev)
		}
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
	}
	return prev
}

func TestAudit_ChainReplayMatchesHead(t *testing.T) {
	l := NewAuditLog()
	for i := 0; i < 25; i++ {
		if _, err := l.Append(EntryExec, NewSalt(), map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	head, seq := l.Head()
	if seq != 25 {
		t.Fatalf("seq = %d, want 25", seq)
	}
	if got := replay(t, l.Range(0, 0)); got != head {
		t.Errorf("replayed head = %s, want %s", got, head)
	}
}

// Tampering with any entry must break the chain at that point — this is the
// whole property the log exists to provide.
func TestAudit_TamperingIsDetected(t *testing.T) {
	l := NewAuditLog()
	for i := 0; i < 10; i++ {
		l.Append(EntryExec, NewSalt(), map[string]any{"cmd": "echo safe"})
	}
	head, _ := l.Head()

	lines := l.Range(0, 0)
	// Rewrite entry 4's body as an attacker would, hiding what really ran.
	lines[4] = []byte(strings.Replace(string(lines[4]), "echo safe", "echo evil", 1))

	prev := ""
	broke := -1
	for i, raw := range lines {
		var e Entry
		json.Unmarshal(raw, &e)
		if e.Prev != prev {
			broke = i
			break
		}
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
	}

	if broke != 5 {
		t.Errorf("chain broke at entry %d, want 5 (the link after the tampered one)", broke)
	}
	if prev == head {
		t.Error("tampered chain reproduced the original head")
	}
}

// Truncation must be detectable too: a shortened log cannot reach the head.
func TestAudit_TruncationIsDetected(t *testing.T) {
	l := NewAuditLog()
	for i := 0; i < 10; i++ {
		l.Append(EntryNetRequest, NewSalt(), map[string]any{"i": i})
	}
	head, _ := l.Head()

	if got := replay(t, l.Range(0, 7)); got == head {
		t.Error("truncated log reproduced the full head")
	}
}

func TestAudit_SaturationSealsAndRefuses(t *testing.T) {
	l := NewAuditLog()
	l.maxEntries = 5

	for i := 0; i < 5; i++ {
		if _, err := l.Append(EntryExec, NewSalt(), map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d should succeed: %v", i, err)
		}
	}
	if !l.Saturated() {
		t.Fatal("log should be saturated at the cap")
	}
	if _, err := l.Append(EntryExec, NewSalt(), map[string]any{"i": 99}); err == nil {
		t.Error("append after saturation should fail, so egress fails closed")
	}

	lines := l.Range(0, 0)
	var last Entry
	json.Unmarshal(lines[len(lines)-1], &last)
	if last.Type != EntryLogSaturated {
		t.Errorf("last entry type = %s, want %s", last.Type, EntryLogSaturated)
	}
	// The seal must itself be a valid link, not an out-of-band note.
	if got := replay(t, lines); got == "" {
		t.Error("sealed chain does not replay")
	}
}

func TestAudit_SaltedHashIsDeterministicAndSalted(t *testing.T) {
	s := NewSalt()
	data := []byte("hello")

	if s.Hash(data) != s.Hash(data) {
		t.Error("same salt and data must give the same hash")
	}
	if NewSalt().Hash(data) == s.Hash(data) {
		t.Error("different salts must give different hashes")
	}

	// The streaming form must agree with the buffered one.
	hc := s.Hasher()
	hc.Write(data)
	if hc.Sum() != s.Hash(data) {
		t.Errorf("streaming hash %s != buffered %s", hc.Sum(), s.Hash(data))
	}
	if hc.Count() != int64(len(data)) {
		t.Errorf("count = %d, want %d", hc.Count(), len(data))
	}
}

// ---- provenance ----

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckpoint_SignatureVerifies(t *testing.T) {
	s := testSigner(t)
	sc, err := s.Sign("seg-1", 42, strings.Repeat("ab", 32), strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(sc.Checkpoint)
	digest := sha512.Sum384(body)
	sig, _ := base64.StdEncoding.DecodeString(sc.Sig)

	if !ecdsa.VerifyASN1(&s.key.PublicKey, digest[:], sig) {
		t.Error("checkpoint signature did not verify under its own key")
	}
	if sc.Checkpoint.TLSKeyFP != s.KeyFP() {
		t.Error("checkpoint does not carry the signing key's fingerprint")
	}
	if sc.Binding != nil {
		t.Error("binding must be null in v1, where pubkey is the TLS key itself")
	}
}

// The cross-CVM forgery, in miniature. An attacker takes a victim's log and
// checkpoint and pairs them with a quote from their OWN CVM. That quote names
// a different tls_key_fp, so the signature must not verify under it.
func TestCheckpoint_ForeignKeyIsRejected(t *testing.T) {
	victim := testSigner(t)
	attacker := testSigner(t)

	victimCP, err := victim.Sign("seg-victim", 7, strings.Repeat("11", 32), strings.Repeat("22", 32))
	if err != nil {
		t.Fatal(err)
	}

	if victim.KeyFP() == attacker.KeyFP() {
		t.Fatal("distinct keys must have distinct fingerprints")
	}

	body, _ := json.Marshal(victimCP.Checkpoint)
	digest := sha512.Sum384(body)
	sig, _ := base64.StdEncoding.DecodeString(victimCP.Sig)

	// Step 4 of verification: the quote's tls_key_fp is the attacker's, so
	// this is the key a verifier would check the signature against.
	if ecdsa.VerifyASN1(&attacker.key.PublicKey, digest[:], sig) {
		t.Fatal("victim's checkpoint verified under the attacker's key")
	}
}

func TestAttestationNonce_BindsAllThreeInputs(t *testing.T) {
	head := strings.Repeat("aa", 32)
	policy := strings.Repeat("bb", 32)
	chal := make([]byte, 32)

	base, err := AttestationNonce(head, policy, chal)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 64 {
		t.Fatalf("nonce is %d hex chars, want 64 — the shim requires exactly 32 bytes", len(base))
	}

	otherHead, _ := AttestationNonce(strings.Repeat("ac", 32), policy, chal)
	otherPolicy, _ := AttestationNonce(head, strings.Repeat("bc", 32), chal)
	otherChal, _ := AttestationNonce(head, policy, append(chal[:31], 1))

	for name, got := range map[string]string{
		"head": otherHead, "policy": otherPolicy, "challenge": otherChal,
	} {
		if got == base {
			t.Errorf("changing the %s did not change the nonce", name)
		}
	}
}

// ---- listener isolation ----

// The sandbox-facing listener serves proxy protocol only. If it ever answered
// an origin-form request, the executor could read the transcript that is
// supposed to be a record of its own behaviour.
func TestEgressProxy_RefusesNonProxyRequests(t *testing.T) {
	p := NewEgressProxy(NewAuditLog(), mustCA(t))

	for _, path := range []string{"/audit/log", "/audit/head", "/audit/session", "/exec", "/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 — the proxy port must not serve the control mux", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "audit") && w.Code == http.StatusOK {
			t.Errorf("%s: proxy listener leaked audit data", path)
		}
	}
}

// With no policy installed, nothing may leave — and the refusal is recorded.
func TestEgressProxy_FailsClosedWithoutPolicy(t *testing.T) {
	audit := NewAuditLog()
	p := NewEgressProxy(audit, mustCA(t))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 with no policy installed", w.Code)
	}
	if _, seq := audit.Head(); seq != 1 {
		t.Fatalf("expected the denial to be recorded, got %d entries", seq)
	}
	var e Entry
	json.Unmarshal(audit.Range(0, 0)[0], &e)
	if e.Type != EntryNetDeny {
		t.Errorf("entry type = %s, want %s", e.Type, EntryNetDeny)
	}
}

// A saturated log means we can no longer record what happens, so nothing
// further may happen.
func TestEgressProxy_RefusesWhenAuditSaturated(t *testing.T) {
	audit := NewAuditLog()
	audit.maxEntries = 1
	audit.Append(EntryExec, NewSalt(), map[string]any{})
	if !audit.Saturated() {
		t.Fatal("precondition: log should be saturated")
	}

	p := NewEgressProxy(audit, mustCA(t))
	eff, _ := Compose([]string{"example.com"}, &Policy{Allow: []string{"example.com"}})
	p.SetPolicy(eff)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 once the log can no longer record", w.Code)
	}
}

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

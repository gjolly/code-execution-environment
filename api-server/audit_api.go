// The /audit/* control surface. Served ONLY on the shim-net listener: the
// executor must not be able to read the transcript or install a policy that
// governs it.
package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
)

type auditAPI struct {
	audit  *AuditLog
	signer *Signer
	proxy  *EgressProxy
	ca     *CA

	// policy is the composed session policy; nil until /audit/session lands.
	policy *EffectivePolicy
}

// headResponse is what a verifier needs to drive the attestation binding. It
// carries the inputs to the nonce so the client can recompute it independently
// rather than trusting the value we return.
type headResponse struct {
	SegmentID string            `json:"segment_id"`
	Seq       int               `json:"seq"`
	AuditHead string            `json:"audit_head"`
	Policy    map[string]string `json:"policy"`
	Challenge string            `json:"challenge,omitempty"`
	Nonce     string            `json:"nonce,omitempty"`
	StartedAt string            `json:"started_at"`
	Signed    *SignedCheckpoint `json:"signed_checkpoint"`
	Saturated bool              `json:"saturated"`
}

func (a *auditAPI) handleHead(w http.ResponseWriter, r *http.Request) {
	head, seq := a.audit.Head()

	policyHash := ""
	policyInfo := map[string]string{}
	if a.policy != nil {
		policyHash = a.policy.EffSHA
		policyInfo["requested_sha256"] = a.policy.ReqSHA
		policyInfo["effective_sha256"] = a.policy.EffSHA
		policyInfo["ceiling_sha256"] = a.policy.CeilingSHA
	}

	resp := headResponse{
		SegmentID: a.audit.SegmentID(),
		Seq:       seq,
		AuditHead: head,
		Policy:    policyInfo,
		StartedAt: a.audit.StartedAt().Format("2006-01-02T15:04:05.999999999Z07:00"),
		Saturated: a.audit.Saturated(),
	}

	// The challenge is the client's; an enclave-chosen value would prove
	// nothing about freshness to a remote verifier.
	if chal := r.URL.Query().Get("challenge"); chal != "" {
		raw, err := hex.DecodeString(chal)
		if err != nil || len(raw) != 32 {
			writeJSONError(w, http.StatusBadRequest, "challenge must be 32 bytes (64 hex chars)")
			return
		}
		nonce, err := AttestationNonce(head, policyHash, raw)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp.Challenge = chal
		resp.Nonce = nonce
	}

	signed, err := a.signer.Sign(a.audit.SegmentID(), seq, head, policyHash)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "signing checkpoint: "+err.Error())
		return
	}
	resp.Signed = signed

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleLog streams the exact bytes the chain hashes, one entry per line, so
// a verifier recomputes H(i) = sha256(line_i) without needing to agree with us
// on a JSON canonicalization scheme.
func (a *auditAPI) handleLog(w http.ResponseWriter, r *http.Request) {
	from := intParam(r, "from", 0)
	to := intParam(r, "to", 0)

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	for _, raw := range a.audit.Range(from, to) {
		if _, err := w.Write(append(raw, '\n')); err != nil {
			return
		}
	}
}

// handleSession installs the per-session policy. It must be called before any
// user traffic; the composed result is recorded as the first chain entry so
// the transcript states the rules that were in force.
func (a *auditAPI) handleSession(w http.ResponseWriter, r *http.Request) {
	var requested Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&requested); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid policy json: "+err.Error())
		return
	}

	eff, err := Compose(LoadCeiling(), &requested)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	salt := NewSalt()
	if _, err := a.audit.Append(EntrySessionStart, salt, struct {
		SegmentID    string           `json:"segment_id"`
		Policy       *EffectivePolicy `json:"policy"`
		MITMCASHA256 string           `json:"mitm_ca_sha256"`
		TLSKeyFP     string           `json:"tls_key_fp"`
		Retention    string           `json:"retention"`
	}{
		SegmentID:    a.audit.SegmentID(),
		Policy:       eff,
		MITMCASHA256: a.ca.Fingerprint(),
		TLSKeyFP:     a.signer.KeyFP(),
		Retention:    "hash-and-size",
	}); err != nil {
		writeJSONError(w, http.StatusInsufficientStorage, err.Error())
		return
	}

	// Rules the ceiling refused are recorded individually so a reader sees
	// exactly what the orchestrator asked for and was not granted.
	for _, rule := range eff.Rejected {
		rejSalt := NewSalt()
		_, _ = a.audit.Append(EntryPolicyReject, rejSalt, struct {
			Rule   string `json:"rule"`
			Reason string `json:"reason"`
		}{rule, "outside attested egress ceiling"})
	}

	a.policy = eff
	a.proxy.SetPolicy(eff)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"effective_policy_sha256": eff.EffSHA,
		"rejected":                eff.Rejected,
		"mitm_ca_sha256":          a.ca.Fingerprint(),
	})
}

// handleResume continues a prior segment's chain in this container. Each hop
// is a different CVM with its own attestation, so a session's transcript is a
// sequence of per-CVM segments linked by these entries.
func (a *auditAPI) handleResume(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrevSegmentID  string          `json:"prev_segment_id"`
		PrevHead       string          `json:"prev_head"`
		PrevCheckpoint json.RawMessage `json:"prev_checkpoint"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid resume json: "+err.Error())
		return
	}
	if err := a.audit.AdoptSegment(req.PrevSegmentID, req.PrevHead, req.PrevCheckpoint); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"segment_id": a.audit.SegmentID()})
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

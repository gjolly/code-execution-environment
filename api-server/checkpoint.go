// Checkpoints bind the audit chain to the CVM's hardware root of trust.
//
// The problem this solves: the shim's attestation nonce is chosen by the
// client (cvmimage cmd/shim/api.go), so a quote over a nonce derived from a
// log head is NOT an assertion by the enclave — anyone running their own CVM
// on the same released image can obtain one over someone else's log. What the
// quote binds unforgeably is tls_key_fp, a REPORT_DATA input the client cannot
// choose and which is unique per CVM boot (cvmimage cmd/boot/identity.go
// generates a fresh P-384 key each boot and reuses it across cert renewals).
//
// So provenance requires the *enclave* to sign the checkpoint with the TLS
// key. We get at it by bind-mounting the private ramdisk's TLS directory into
// this container read-only. A verifier then checks:
//
//	quote.ReportData.TLSKeyFP == SHA256(DER SPKI of checkpoint.pubkey)
//
// and that the signature verifies under that key. An attacker's CVM has a
// different fingerprint and cannot produce a signature under ours.
//
// This deliberately puts the enclave identity key in the container that also
// terminates MITM TLS — a time-boxed tradeoff taken to ship the binding with
// no cvmimage release. The exit path is a dedicated audit key derived and
// signed by boot: serving `binding` from day one (null for now) means that
// upgrade touches cvmimage only, not this wire format.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	tlsKeyPath = "/run/tinfoil/tls/key.pem"

	// checkpointAlg is recorded in the served document so a verifier never
	// has to infer it from the key.
	checkpointAlg = "ECDSA-P384-SHA384"

	// Domain separator for the attestation nonce. Distinct from any other
	// use of the audit head so a nonce can never be mistaken for a different
	// kind of commitment.
	nonceDomainSep = "tinfoil-sandbox-audit/v1"
)

// Checkpoint is the signed statement. Field order is the serialization order
// and is load-bearing: the signature covers these exact bytes.
type Checkpoint struct {
	SegmentID  string `json:"segment_id"`
	Seq        int    `json:"seq"`
	AuditHead  string `json:"audit_head"`
	PolicyHash string `json:"effective_policy_sha256"`
	TLSKeyFP   string `json:"tls_key_fp"`
	TS         string `json:"ts"`
}

// SignedCheckpoint is what /audit/head serves. Binding is nil in v1, where
// pubkey *is* the CVM's TLS key. When boot grows a derived audit key it
// carries that key's TLS-key signature and verification gains one step.
type SignedCheckpoint struct {
	Checkpoint Checkpoint      `json:"checkpoint"`
	Alg        string          `json:"alg"`
	Sig        string          `json:"sig"`    // base64, ASN.1 DER ECDSA
	PubKey     string          `json:"pubkey"` // PEM, SubjectPublicKeyInfo
	Binding    json.RawMessage `json:"binding"`
}

// Signer holds the mounted TLS key and the fingerprint a verifier matches
// against the attestation report.
type Signer struct {
	key      *ecdsa.PrivateKey
	pubPEM   string
	keyFPHex string
}

// LoadSigner reads the bind-mounted TLS key, retrying until boot has written
// it. cvmimage's cmd/boot/cert.go writes key.pem partway through boot, so a
// container that starts first will briefly see an empty directory. We mount
// the directory rather than the file precisely so Docker cannot materialize a
// stray directory at the mount target in that window.
func LoadSigner(timeout time.Duration) (*Signer, error) {
	deadline := time.Now().Add(timeout)
	for {
		s, err := loadSignerOnce()
		if err == nil {
			return s, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("waiting for %s: %w", keyPath(), err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// keyPath is tlsKeyPath in the CVM. TLS_KEY_PATH overrides it for local dev,
// where the private ramdisk does not exist.
func keyPath() string {
	if p := os.Getenv("TLS_KEY_PATH"); p != "" {
		return p
	}
	return tlsKeyPath
}

func loadSignerOnce() (*Signer, error) {
	pemBytes, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath())
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
	case "PRIVATE KEY":
		parsed, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parsing PKCS#8 private key: %w", perr)
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("TLS key is %T, want *ecdsa.PrivateKey", parsed)
		}
		key = ecKey
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}

	return signerFromKey(key)
}

// signerFromKey derives the fingerprint a verifier matches against the
// attestation report. It must match cvmimage internal/tls.KeyFPBytes exactly:
// SHA-256 over the DER SubjectPublicKeyInfo. That value is what lands in
// REPORT_DATA, so any divergence here silently breaks provenance.
func signerFromKey(key *ecdsa.PrivateKey) (*Signer, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	fp := sha256.Sum256(der)

	return &Signer{
		key:      key,
		pubPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		keyFPHex: hex.EncodeToString(fp[:]),
	}, nil
}

func (s *Signer) KeyFP() string { return s.keyFPHex }

// Sign produces the signed checkpoint for the given chain state.
func (s *Signer) Sign(segmentID string, seq int, auditHead, policyHash string) (*SignedCheckpoint, error) {
	cp := Checkpoint{
		SegmentID:  segmentID,
		Seq:        seq,
		AuditHead:  auditHead,
		PolicyHash: policyHash,
		TLSKeyFP:   s.keyFPHex,
		TS:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("marshaling checkpoint: %w", err)
	}
	digest := sha512.Sum384(body)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing checkpoint: %w", err)
	}

	return &SignedCheckpoint{
		Checkpoint: cp,
		Alg:        checkpointAlg,
		Sig:        base64.StdEncoding.EncodeToString(sig),
		PubKey:     s.pubPEM,
		Binding:    nil,
	}, nil
}

// AttestationNonce derives the 32-byte nonce the client passes to the shim's
// /.well-known/tinfoil-attestation. SHA-256 output is exactly the 32 bytes the
// shim requires, which is what makes this binding possible with no platform
// change. The challenge is supplied by the client: an enclave-chosen value
// would prove nothing about freshness to a remote verifier.
func AttestationNonce(auditHead, policyHash string, challenge []byte) (string, error) {
	headBytes, err := hex.DecodeString(auditHead)
	if err != nil {
		return "", fmt.Errorf("audit head is not hex: %w", err)
	}
	policyBytes, err := hex.DecodeString(policyHash)
	if err != nil {
		return "", fmt.Errorf("policy hash is not hex: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(nonceDomainSep))
	h.Write(headBytes)
	h.Write(policyBytes)
	h.Write(challenge)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// logSignerReady records the fingerprint at startup so it can be correlated
// with the attestation report from the operator's side.
func (s *Signer) logReady() {
	log.Printf("api-server: audit signer ready, tls_key_fp=%s", s.keyFPHex)
}

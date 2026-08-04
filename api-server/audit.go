// Audit chain: an append-only, tamper-evident record of everything the
// sandbox did — every command executed and every request that left the CVM.
//
// The chain's integrity rests on hashing the *exact bytes* we serialize, not
// a re-marshal of the parsed form. /audit/log streams those same bytes back,
// one entry per line, so a verifier recomputes H(i) = sha256(line_i) without
// having to agree with us on a JSON canonicalization scheme.
//
// Payload bytes (stdout, request/response bodies) are never stored — only a
// salted SHA-256 and a length. The caller already holds the real bytes, so the
// hash lets them prove an entry matches what they got, without turning the
// audit log into a second copy of the data. The per-entry salt stops an
// adversary from dictionary-attacking short values.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sync"
	"time"
)

// Entry types.
const (
	EntrySessionStart = "session.start"
	EntrySessionEnd   = "session.end"
	EntrySessionResum = "session.resume"
	EntryExec         = "exec"
	EntryFileRead     = "file.read"
	EntryFileWrite    = "file.write"
	EntryUpload       = "upload"
	EntrySnapshot     = "snapshot"
	EntryNetRequest   = "net.request"
	EntryNetDeny      = "net.deny"
	EntryNetTunnel    = "net.tunnel"
	EntryPolicyReject = "policy.reject"
	EntryLogSaturated = "log.saturated"
)

// Saturation caps. The executor is untrusted and could try to bury one real
// request under a flood of synthetic ones; past these limits the log stops
// accepting entries and egress is refused (fail closed, never fail silent).
const (
	defaultMaxEntries = 50_000
	defaultMaxBytes   = 64 << 20
)

// Entry is one link in the chain. Field order here is the serialization order
// and must not be reordered — it changes every hash in every existing log.
type Entry struct {
	Seq  uint64          `json:"seq"`
	TS   string          `json:"ts"`
	Type string          `json:"type"`
	Salt string          `json:"salt"`
	Prev string          `json:"prev"`
	Body json.RawMessage `json:"body"`
}

type record struct {
	raw  []byte // exact bytes emitted by /audit/log and hashed into the chain
	hash string
}

// AuditLog is the in-memory chain. There is no disk: the container is
// read_only, and the log must never round-trip through the untrusted executor.
type AuditLog struct {
	mu         sync.Mutex
	records    []record
	head       string
	bytes      int
	saturated  bool
	segmentID  string
	startedAt  time.Time
	maxEntries int
	maxBytes   int
}

func NewAuditLog() *AuditLog {
	return &AuditLog{
		segmentID:  randHex(16),
		startedAt:  time.Now().UTC(),
		maxEntries: defaultMaxEntries,
		maxBytes:   defaultMaxBytes,
	}
}

// Salt is a per-entry random value mixed into every payload hash in that
// entry's body. Obtain it before building the body, then hand it back to
// Append so the entry records the salt the hashes were computed with.
type Salt []byte

func NewSalt() Salt {
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		panic("audit: entropy unavailable: " + err.Error())
	}
	return s
}

// Hash returns hex(sha256(salt || data)) — the only form in which payload
// bytes ever enter the log.
func (s Salt) Hash(data []byte) string {
	h := sha256.New()
	h.Write(s)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Hasher returns a streaming equivalent of Hash, for payloads that are proxied
// through rather than buffered. Pre-seeded with the salt, so the digest matches
// Hash over the same bytes.
func (s Salt) Hasher() *HashCounter {
	h := sha256.New()
	h.Write(s)
	return &HashCounter{h: h}
}

// HashCounter is an io.Writer that digests and counts without retaining.
type HashCounter struct {
	h hash.Hash
	n int64
}

func (hc *HashCounter) Write(p []byte) (int, error) {
	hc.h.Write(p)
	hc.n += int64(len(p))
	return len(p), nil
}

func (hc *HashCounter) Sum() string  { return hex.EncodeToString(hc.h.Sum(nil)) }
func (hc *HashCounter) Count() int64 { return hc.n }

// Append adds one entry and returns the new head. It reports an error only
// when the log is saturated; callers treating egress as gated on the audit
// record must refuse the underlying operation in that case.
func (l *AuditLog) Append(typ string, salt Salt, body any) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(typ, salt, body)
}

func (l *AuditLog) appendLocked(typ string, salt Salt, body any) (string, error) {
	if l.saturated {
		return l.head, fmt.Errorf("audit log saturated")
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return l.head, fmt.Errorf("marshaling %s body: %w", typ, err)
	}

	e := Entry{
		Seq:  uint64(len(l.records)),
		TS:   time.Now().UTC().Format(time.RFC3339Nano),
		Type: typ,
		Salt: hex.EncodeToString(salt),
		Prev: l.head,
		Body: bodyJSON,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return l.head, fmt.Errorf("marshaling %s entry: %w", typ, err)
	}

	sum := sha256.Sum256(raw)
	l.records = append(l.records, record{raw: raw, hash: hex.EncodeToString(sum[:])})
	l.head = hex.EncodeToString(sum[:])
	l.bytes += len(raw)

	// Seal the chain when it hits a cap, leaving the saturation itself as the
	// last verifiable link rather than silently dropping records.
	if !l.saturated && (len(l.records) >= l.maxEntries || l.bytes >= l.maxBytes) {
		l.sealLocked()
	}
	return l.head, nil
}

// sealLocked appends the terminal log.saturated entry. Caller holds l.mu and
// must not have set l.saturated yet.
func (l *AuditLog) sealLocked() {
	body, _ := json.Marshal(struct {
		AfterSeq uint64 `json:"after_seq"`
		Entries  int    `json:"entries"`
		Bytes    int    `json:"bytes"`
		Reason   string `json:"reason"`
	}{
		AfterSeq: uint64(len(l.records) - 1),
		Entries:  len(l.records),
		Bytes:    l.bytes,
		Reason:   "entry or byte cap reached; egress refused from here on",
	})

	e := Entry{
		Seq:  uint64(len(l.records)),
		TS:   time.Now().UTC().Format(time.RFC3339Nano),
		Type: EntryLogSaturated,
		Salt: hex.EncodeToString(NewSalt()),
		Prev: l.head,
		Body: body,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		// Nothing useful left to do; mark saturated so egress still fails closed.
		l.saturated = true
		return
	}
	sum := sha256.Sum256(raw)
	l.records = append(l.records, record{raw: raw, hash: hex.EncodeToString(sum[:])})
	l.head = hex.EncodeToString(sum[:])
	l.bytes += len(raw)
	l.saturated = true
}

// Saturated reports whether the log has stopped accepting entries. Egress
// must be refused while this is true.
func (l *AuditLog) Saturated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.saturated
}

// Head returns the current chain head and the number of entries behind it.
func (l *AuditLog) Head() (head string, seq int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head, len(l.records)
}

func (l *AuditLog) SegmentID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.segmentID
}

func (l *AuditLog) StartedAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.startedAt
}

// Range returns the exact serialized bytes for entries in [from, to), which
// are what the chain hashes. to <= 0 means "through the end".
func (l *AuditLog) Range(from, to int) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()

	if from < 0 {
		from = 0
	}
	if to <= 0 || to > len(l.records) {
		to = len(l.records)
	}
	if from >= to {
		return nil
	}
	out := make([][]byte, 0, to-from)
	for _, r := range l.records[from:to] {
		out = append(out, r.raw)
	}
	return out
}

// AdoptSegment continues a prior segment's chain in this container. Each
// container hop is a different CVM with its own attestation, so a session's
// transcript is a sequence of per-CVM segments linked by session.resume.
func (l *AuditLog) AdoptSegment(prevSegmentID, prevHead string, prevCheckpoint json.RawMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.records) != 0 {
		return fmt.Errorf("cannot resume: chain already has %d entries", len(l.records))
	}
	_, err := l.appendLocked(EntrySessionResum, NewSalt(), struct {
		PrevSegmentID  string          `json:"prev_segment_id"`
		PrevHead       string          `json:"prev_head"`
		PrevCheckpoint json.RawMessage `json:"prev_checkpoint,omitempty"`
		SegmentID      string          `json:"segment_id"`
	}{prevSegmentID, prevHead, prevCheckpoint, l.segmentID})
	return err
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("audit: entropy unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

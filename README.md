Simple code execution environment containers.

Executor <-> api server

## Available in the executor image

**Runtimes**

- Python 3.12 (with pip)
- Node.js 22 (with npm)
- gcc / g++, make

**System CLI tools**

- ffmpeg
- pandoc
- tesseract (OCR)
- jq

**Python packages** (direct, pinned in [`executor/deps/requirements.in`](executor/deps/requirements.in); full transitive lock in [`requirements.txt`](executor/deps/requirements.txt))

- Pillow
- matplotlib
- numpy
- openpyxl
- pandas
- pdfplumber
- pypdf
- pypdfium2
- python-docx
- python-pptx
- reportlab
- sympy

**Node packages** (direct, pinned in [`executor/deps/package.json`](executor/deps/package.json); full transitive lock in [`package-lock.json`](executor/deps/package-lock.json))

- docx
- markdownlint
- marked
- pdf-lib
- pdfjs-dist
- pptxgenjs
- remark
- sharp
- ts-node
- tsx
- typescript

## Verifiable transcript

The executor has no route of its own. It sits on `sandbox-net`, declared
`egress: closed` in `tinfoil-config.yml`, so nftables installs no forward rule
for that bridge and the kernel drops anything it sends toward the internet. Its
one reachable peer is the api-server, which serves an intercepting HTTP proxy on
`:3128`. Every command in and every request out is therefore recorded, and that
completeness is covered by the launch measurement — this file's SHA-256 is in
the kernel cmdline.

The `HTTP_PROXY` variables handed to bash are ergonomics, not enforcement: they
decide whether bypassing the proxy fails *usefully* rather than whether it is
possible.

### What is recorded

An append-only hash chain. Commands and URLs are stored in the clear — they are
the action being audited. Payloads are stored only as a salted SHA-256 and a
length: the caller already holds the bytes, so the hash lets them prove an entry
matches what they received, without the transcript becoming a second copy of the
data. Request header *names* are always recorded; values only for a safe
allowlist, with `authorization` and `cookie` hashed instead.

### Endpoints

```
POST /audit/session  {"allow":[...], "deny":[...], "tunnel_only":[...]}
                     → {"effective_policy_sha256":"...", "rejected":[...]}
                     Install the session policy. Must precede user traffic.

GET  /audit/head?challenge=<64 hex>
                     → {seq, audit_head, policy, nonce, signed_checkpoint}

GET  /audit/log?from=&to=
                     → NDJSON; the exact bytes the chain hashes

POST /audit/resume   {"prev_segment_id","prev_head","prev_checkpoint"}
                     Continue a prior segment's chain after a container hop.
```

### Verifying a transcript

The attestation nonce is chosen by the client, so a quote over it is *not* an
assertion by the enclave — anyone running their own CVM on the same released
image can obtain one over someone else's log head. What the quote binds
unforgeably is `tls_key_fp`. So the api-server signs each checkpoint with the
CVM's TLS key, and step 4 below is what actually establishes provenance.

```
1. quote signature chains to AMD/Intel roots
2. launch measurement == the released tinfoil-deployment.json  (pins the
   api-server image digest AND the networks: stanza)
3. ReportData.Nonce == SHA256("tinfoil-sandbox-audit/v1" || audit_head
                              || effective_policy_sha256 || challenge)
4. ReportData.TLSKeyFP == SHA256(DER SPKI of checkpoint.pubkey)   ← provenance
5. checkpoint signature verifies under that key
6. checkpoint.audit_head matches, and replaying /audit/log reproduces it
```

Yielding: *the log with this head, under this policy, was produced by that exact
measured api-server binary, inside the specific CVM instance identified by
`tls_key_fp`, whose attested config forbade the executor any egress except
through it.* Because the checkpoint is self-contained and signed,
`{log, checkpoint, quote}` verifies offline.

### Known gaps

- **DNS.** Docker's embedded resolver forwards from the *host* netns, bypassing
  the `forward` chain (`output` policy is `accept`), so a `closed` network still
  has a working, unlogged DNS channel. With the proxy resolving on the
  executor's behalf nothing legitimate needs it; closing it properly needs a
  `dns:` key on the container stanza in cvmimage.
- **The TLS key is mounted into the api-server.** A compromise there yields
  enclave impersonation and forged attestation documents, not just forged logs.
  This is a deliberate, time-boxed tradeoff to ship the binding with no cvmimage
  release; the exit path is a dedicated audit key derived and signed by boot,
  which the `{checkpoint, sig, pubkey, binding}` wire format already anticipates.
- **The ceiling is coarse.** `cmd/egress` resolves the allow list to IPv4 and
  accepts by address, so anything sharing a CDN address with an allowed host is
  reachable at L3. The L7 policy is the layer that distinguishes paths.

### Config invariants

`go run . ../../tinfoil-config.yml` from `hack/configcheck` asserts the
properties the transcript depends on, and gates the release. cvmimage validates
this file too, but its checks are about internal consistency: it accepts an
executor attached directly to `egress-net` without complaint, which would make
the transcript a record of only the traffic that chose to be recorded.

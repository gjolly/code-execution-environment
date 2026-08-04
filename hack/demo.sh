#!/usr/bin/env bash
#
# Exercise the full sandbox flow against a deployed CVM, for demo and manual
# testing. Installs a session policy, runs a handful of commands, pulls the
# transcript and the signed checkpoint, and fetches a hardware attestation
# bound to that transcript.
#
# It replays the hash chain, recomputes the attestation nonce, and verifies the
# checkpoint signature under the certificate served on the TLS connection. It
# does NOT verify the quote itself (signature chain to AMD/Intel roots, launch
# measurement) — that comes later.
#
#   usage: hack/demo.sh https://<sandbox-domain> [--keep]
#
# Everything is written to a run directory so you can inspect or replay it.

set -euo pipefail

URL="${1:-}"
if [[ -z "$URL" || "$URL" == -* ]]; then
	echo "usage: $0 https://<sandbox-domain> [--keep]" >&2
	exit 2
fi
URL="${URL%/}"
shift
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

for tool in curl jq sha256sum; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

# 32 random bytes as hex, without depending on openssl.
randhex32() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

# Hex string -> raw bytes on stdout, without depending on xxd.
unhex() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")"; }

OUT=$(mktemp -d -t sandbox-demo-XXXXXX)
cleanup() {
	if [[ $KEEP -eq 1 ]]; then
		echo
		echo "artifacts kept in $OUT"
	else
		rm -rf "$OUT"
	fi
}
trap cleanup EXIT

# The container auth token is trust-on-first-use: whoever presents one first
# claims the container for its lifetime. Every call below must reuse it.
AUTH_TOKEN=$(randhex32)

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
dim() { printf '\033[2m%s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

# call METHOD PATH [BODY] -> response body on stdout, non-2xx is fatal
call() {
	local method="$1" path="$2" body="${3:-}"
	local -a args=(
		--silent --show-error
		--write-out '\n%{http_code}'
		-X "$method"
		-H "X-Code-Execution-Container-Auth-Token: $AUTH_TOKEN"
		-H 'Content-Type: application/json'
	)
	[[ -n "$body" ]] && args+=(--data "$body")

	local raw code
	raw=$(curl "${args[@]}" "$URL$path") || fail "curl $method $path"
	code=$(tail -n1 <<<"$raw")
	body=$(sed '$d' <<<"$raw")

	if [[ ! "$code" =~ ^2 ]]; then
		echo "$body" >&2
		fail "$method $path returned HTTP $code"
	fi
	printf '%s' "$body"
}

# exec_cmd CMD -> prints the command, its exit code and stdout
exec_cmd() {
	local cmd="$1" resp
	resp=$(call POST /exec "$(jq -nc --arg c "$cmd" '{command:$c}')")

	printf '\033[36m$ %s\033[0m\n' "$cmd"
	jq -r '.stdout' <<<"$resp" | sed 's/^/  /'
	local rc stderr
	rc=$(jq -r '.exit_code' <<<"$resp")
	stderr=$(jq -r '.stderr' <<<"$resp")
	[[ -n "$stderr" ]] && printf '\033[33m%s\033[0m\n' "$(sed 's/^/  stderr: /' <<<"$stderr")"
	[[ "$rc" != "0" ]] && printf '  \033[33mexit %s\033[0m\n' "$rc"
	return 0
}

echo "sandbox: $URL"
echo "run dir: $OUT"

# ---------------------------------------------------------------------------
bold "1. Health"
call GET /health >/dev/null && echo "api-server and executor both reachable"

# ---------------------------------------------------------------------------
bold "2. Install session policy"
# The api-server intersects this with the attested ceiling from
# tinfoil-config.yml. Anything outside it comes back in .rejected rather than
# being silently granted.
POLICY=$(cat <<'JSON'
{
  "allow": [
    "https://pypi.org/simple/**",
    "https://files.pythonhosted.org/**",
    "https://evil.example.com/**"
  ],
  "deny": ["**/secret/**"],
  "tunnel_only": [],
  "max_response_bytes": 67108864
}
JSON
)
SESSION=$(call POST /audit/session "$POLICY")
echo "$SESSION" | jq . | tee "$OUT/session.json" | sed 's/^/  /'
REJECTED=$(jq -r '.rejected // [] | length' <<<"$SESSION")
if [[ "$REJECTED" != "0" ]]; then
	dim "  ^ $REJECTED rule(s) refused: outside the attested ceiling, so they were never granted"
fi

# ---------------------------------------------------------------------------
bold "3. Run commands in the sandbox"
exec_cmd 'ls -la'
exec_cmd 'uname -r'
exec_cmd 'lsblk'
exec_cmd 'cat /etc/os-release'

exec_cmd 'apt-get update'
exec_cmd 'apt-get install -y curl'

# ---------------------------------------------------------------------------
bold "4. Egress through the recording proxy"
dim "the executor has no route of its own; these go through the api-server proxy"
exec_cmd 'curl -sS -o /dev/null -w "%{http_code}\n" --max-time 20 https://pypi.org/simple/ || true'
dim "denied by policy — should fail, and appear in the transcript as net.deny"
exec_cmd 'curl -sS -o /dev/null -w "%{http_code}\n" --max-time 20 https://evil.example.com/ || true'

# ---------------------------------------------------------------------------
bold "5. Attested head"
# The challenge is ours: an enclave-chosen value would prove nothing about
# freshness. The api-server returns the nonce it derived; we recompute it below
# so we are not taking its word for the binding.
CHALLENGE=$(randhex32)
HEAD=$(call GET "/audit/head?challenge=$CHALLENGE")
echo "$HEAD" | jq . >"$OUT/head.json"

AUDIT_HEAD=$(jq -r '.audit_head' <<<"$HEAD")
POLICY_SHA=$(jq -r '.policy.effective_sha256 // ""' <<<"$HEAD")
NONCE=$(jq -r '.nonce' <<<"$HEAD")
SEQ=$(jq -r '.seq' <<<"$HEAD")
KEYFP=$(jq -r '.signed_checkpoint.checkpoint.tls_key_fp' <<<"$HEAD")

printf '  seq          %s\n' "$SEQ"
printf '  audit_head   %s\n' "$AUDIT_HEAD"
printf '  policy sha   %s\n' "$POLICY_SHA"
printf '  tls_key_fp   %s\n' "$KEYFP"
printf '  nonce        %s\n' "$NONCE"

# Recompute the nonce independently:
#   SHA256("tinfoil-sandbox-audit/v1" || audit_head || effective_policy || challenge)
# with the three hex values as raw bytes.
LOCAL_NONCE=$(
	{
		printf 'tinfoil-sandbox-audit/v1'
		unhex "$AUDIT_HEAD"
		unhex "$POLICY_SHA"
		unhex "$CHALLENGE"
	} | sha256sum | cut -d' ' -f1
)
if [[ "$LOCAL_NONCE" == "$NONCE" ]]; then
	printf '  \033[32mnonce recomputed locally and matches\033[0m\n'
else
	printf '  \033[31mnonce MISMATCH — local %s\033[0m\n' "$LOCAL_NONCE"
fi

jq -r '.signed_checkpoint.pubkey' <<<"$HEAD" >"$OUT/checkpoint-pubkey.pem"
jq '.signed_checkpoint' <<<"$HEAD" >"$OUT/checkpoint.json"

# ---------------------------------------------------------------------------
bold "6. Transcript"
curl --silent --show-error \
	-H "X-Code-Execution-Container-Auth-Token: $AUTH_TOKEN" \
	"$URL/audit/log" >"$OUT/audit.ndjson" || fail "fetching /audit/log"

ENTRIES=$(wc -l <"$OUT/audit.ndjson" | tr -d ' ')
echo "$ENTRIES entries"
echo
# One line per entry: seq, type, and whichever field carries the action.
jq -r '
  [ .seq,
    .type,
    ( .body.command
      // ( .body.method? // empty | tostring ) + " " + ( .body.url? // "" )
      // .body.path
      // .body.host
      // ""
    )
  ] | @tsv
' "$OUT/audit.ndjson" | awk -F'\t' '{ printf "  %-4s %-14s %s\n", $1, $2, substr($3,1,80) }'

echo
dim "full entries:"
jq -c . "$OUT/audit.ndjson" | sed 's/^/  /'

# Replay the chain so the printed head is not just something we were told.
bold "7. Chain replay"
PREV=""
BROKEN=0
LINE=0
while IFS= read -r entry; do
	claimed=$(jq -r '.prev' <<<"$entry")
	if [[ "$claimed" != "$PREV" ]]; then
		printf '  \033[31mbroken link at entry %s: prev=%s, expected %s\033[0m\n' "$LINE" "$claimed" "$PREV"
		BROKEN=1
		break
	fi
	PREV=$(printf '%s' "$entry" | sha256sum | cut -d' ' -f1)
	LINE=$((LINE + 1))
done <"$OUT/audit.ndjson"

if [[ $BROKEN -eq 0 ]]; then
	printf '  replayed %s entries -> %s\n' "$LINE" "$PREV"
	if [[ "$PREV" == "$AUDIT_HEAD" ]]; then
		printf '  \033[32mreplayed head matches /audit/head\033[0m\n'
	else
		# Expected if commands ran between the two fetches: the log is
		# append-only, so a later head is a valid extension.
		printf '  \033[33mreplayed head differs from the earlier /audit/head (log grew since)\033[0m\n'
	fi
fi

# ---------------------------------------------------------------------------
bold "8. Hardware attestation bound to that head"
dim "GET /.well-known/tinfoil-attestation?nonce=<nonce over head+policy+challenge>"
curl --silent --show-error \
	"$URL/.well-known/tinfoil-attestation?nonce=$NONCE" >"$OUT/attestation.json" ||
	fail "fetching attestation"

if ! jq -e . "$OUT/attestation.json" >/dev/null 2>&1; then
	echo "  attestation endpoint did not return JSON:" >&2
	head -c 400 "$OUT/attestation.json" >&2
	exit 1
fi

jq '{format, report_data, cpu: {platform: .cpu.platform, report_bytes: (.cpu.report | length)}}' \
	"$OUT/attestation.json" | sed 's/^/  /'

ECHOED=$(jq -r '.report_data.nonce // ""' "$OUT/attestation.json")
if [[ "$ECHOED" == "$NONCE" ]]; then
	printf '  \033[32mquote echoes our nonce\033[0m\n'
else
	printf '  \033[31mquote nonce %s != requested %s\033[0m\n' "$ECHOED" "$NONCE"
fi

QUOTE_FP=$(jq -r '.report_data.tls_key_fp // ""' "$OUT/attestation.json")
printf '  quote tls_key_fp      %s\n' "$QUOTE_FP"
printf '  checkpoint tls_key_fp %s\n' "$KEYFP"
if [[ -n "$QUOTE_FP" && "$QUOTE_FP" == "$KEYFP" ]]; then
	printf '  \033[32mthe key that signed the checkpoint is the key in REPORT_DATA\033[0m\n'
else
	printf '  \033[31mfingerprint mismatch — the transcript is NOT attributable to this CVM\033[0m\n'
fi

# ---------------------------------------------------------------------------
bold "9. Checkpoint signature under the serving TLS certificate"
if ! command -v openssl >/dev/null; then
	dim "openssl not installed — skipping signature verification"
else
	HOSTPORT="${URL#*://}"
	HOSTPORT="${HOSTPORT%%/*}"
	SNI="${HOSTPORT%%:*}"
	[[ "$HOSTPORT" == *:* ]] || HOSTPORT="$HOSTPORT:443"

	# The leaf certificate as presented on this connection. Everything below is
	# checked against that key, not against the pubkey the JSON handed us —
	# otherwise the checkpoint would only be self-consistent.
	openssl s_client -connect "$HOSTPORT" -servername "$SNI" </dev/null 2>/dev/null |
		openssl x509 -outform pem >"$OUT/server-cert.pem" 2>/dev/null || true
	[[ -s "$OUT/server-cert.pem" ]] || fail "could not fetch the TLS certificate from $HOSTPORT"
	openssl x509 -in "$OUT/server-cert.pem" -pubkey -noout >"$OUT/server-pubkey.pem"
	dim "  $(openssl x509 -in "$OUT/server-cert.pem" -noout -subject | sed 's/^subject=*//')"

	# SHA-256 over the DER SubjectPublicKeyInfo — the same derivation boot uses
	# for the value it puts in REPORT_DATA.
	spki_fp() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
	CERT_FP=$(spki_fp "$OUT/server-pubkey.pem")
	CP_FP=$(spki_fp "$OUT/checkpoint-pubkey.pem")

	printf '  cert key fp           %s\n' "$CERT_FP"
	printf '  checkpoint pubkey fp  %s\n' "$CP_FP"
	if [[ -n "$CERT_FP" && "$CERT_FP" == "$CP_FP" && "$CERT_FP" == "$KEYFP" ]]; then
		printf '  \033[32mthe checkpoint pubkey is the key of the cert terminating this connection\033[0m\n'
	else
		fail "checkpoint pubkey is not the serving certificate's key"
	fi

	# Reconstruct the exact bytes the enclave signed: compact JSON, struct field
	# order (api-server/checkpoint.go Checkpoint), no trailing newline. All
	# values are hex, base64 or RFC3339, so Go's HTML escaping never fires and
	# jq reproduces them byte for byte.
	jq -jc '.checkpoint | {segment_id, seq, audit_head, effective_policy_sha256, tls_key_fp, ts}' \
		"$OUT/checkpoint.json" >"$OUT/checkpoint-body.json"
	jq -r '.sig' "$OUT/checkpoint.json" | base64 -d >"$OUT/checkpoint.sig"

	ALG=$(jq -r '.alg' "$OUT/checkpoint.json")
	case "$ALG" in
	ECDSA-P384-SHA384) DGST=-sha384 ;;
	ECDSA-P256-SHA256) DGST=-sha256 ;;
	*) fail "unsupported checkpoint alg $ALG" ;;
	esac

	printf '  alg                   %s\n' "$ALG"
	if openssl dgst "$DGST" -verify "$OUT/server-pubkey.pem" \
		-signature "$OUT/checkpoint.sig" "$OUT/checkpoint-body.json" >/dev/null 2>&1; then
		printf '  \033[32msignature verifies — this CVM asserts head %s at seq %s\033[0m\n' \
			"${AUDIT_HEAD:0:16}…" "$SEQ"
	else
		printf '  \033[31mSIGNATURE INVALID — the checkpoint is not signed by this CVM\033[0m\n'
		exit 1
	fi
fi

# ---------------------------------------------------------------------------
bold "Collected"
cat <<EOF
  $OUT/audit.ndjson           the transcript (hash-chained)
  $OUT/head.json              head + signed checkpoint
  $OUT/checkpoint.json        checkpoint, signature, pubkey
  $OUT/checkpoint-pubkey.pem  the CVM's TLS public key
  $OUT/attestation.json       hardware quote over our nonce
  $OUT/session.json           the effective policy
  $OUT/server-cert.pem        the leaf cert served on this connection
  $OUT/checkpoint-body.json   the exact bytes covered by the signature

Still to verify (deliberately not done here):
  - quote signature chains to AMD/Intel roots
  - launch measurement matches the published release for this repo
EOF
[[ $KEEP -eq 0 ]] && dim "(run with --keep to retain these)"
exit 0

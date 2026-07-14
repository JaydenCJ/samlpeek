#!/usr/bin/env bash
# End-to-end smoke test for samlpeek: builds the binary, then drives every
# subcommand against the committed example payloads plus a POST blob
# fabricated on the fly, asserting on real CLI output and exit codes.
# No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/samlpeek"
NOW="2026-07-12T09:01:00Z"   # matches the pinned timestamps in examples/

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/samlpeek) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" version | grep -qx "samlpeek 0.1.0" || fail "version mismatch"

echo "3. decode a POST blob fabricated with base64(1)"
printf '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0" IssueInstant="2026-07-12T09:00:00Z" InResponseTo="_lo1"><saml:Issuer>https://idp.example.test/saml</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>' \
  | base64 > "$WORKDIR/logout.b64"
"$BIN" decode "$WORKDIR/logout.b64" | grep -q "<samlp:LogoutResponse" \
  || fail "decode did not unwrap base64"

echo "4. explain the healthy POST response"
OUT="$("$BIN" explain --now "$NOW" "$ROOT/examples/response-post.b64")"
echo "$OUT" | grep -q "Success — the request succeeded" || fail "status line missing"
echo "$OUT" | grep -q "alice@example.test  \[emailAddress\]" || fail "subject missing"
echo "$OUT" | grep -q "window 10m" || fail "conditions window missing"
echo "$OUT" | grep -q "cert CN=idp.example.test expires 2035-01-01" || fail "certificate summary missing"

echo "5. explain a full redirect URL (percent + base64 + DEFLATE)"
OUT="$("$BIN" explain "$(cat "$ROOT/examples/redirect-request.txt")")"
echo "$OUT" | grep -q "SAML AuthnRequest (http-redirect)" || fail "redirect binding not detected"
echo "$OUT" | grep -q "inflate (raw DEFLATE)" || fail "decode chain missing inflation"
echo "$OUT" | grep -q "relay-state: /dashboard" || fail "RelayState missing"

echo "6. lint passes on the healthy response with the right audience"
"$BIN" lint --now "$NOW" --audience https://sp.example.test \
  "$ROOT/examples/response-post.b64" | grep -q "— PASS" || fail "healthy lint should PASS"

echo "7. lint fails on the broken response with exit code 1"
set +e
OUT="$("$BIN" lint --now "$NOW" "$ROOT/examples/bad-response.b64")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "bad response should exit 1, got $CODE"
echo "$OUT" | grep -q "assertion-expired" || fail "assertion-expired not reported"
echo "$OUT" | grep -q "nameid-comment" || fail "nameid-comment not reported"
echo "$OUT" | grep -q "certificate-expired" || fail "certificate-expired not reported"

echo "8. lint --format json is machine-readable"
set +e
JSON="$("$BIN" lint --now "$NOW" --format json "$ROOT/examples/bad-response.b64")"
set -e
echo "$JSON" | grep -q '"tool": "samlpeek"' || fail "json envelope missing"
echo "$JSON" | grep -q '"verdict": "fail"' || fail "json verdict wrong"
echo "$JSON" | grep -q '"schema_version": 1' || fail "schema_version missing"

echo "9. audience mismatch is caught"
set +e
"$BIN" lint --now "$NOW" --audience https://wrong.example.test \
  "$ROOT/examples/response-post.b64" > "$WORKDIR/aud.txt"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "audience mismatch should exit 1"
grep -q "audience-mismatch" "$WORKDIR/aud.txt" || fail "audience-mismatch not reported"

echo "10. certs lists the metadata signing certificate"
OUT="$("$BIN" certs --now "$NOW" "$ROOT/examples/idp-metadata.xml")"
echo "$OUT" | grep -q "CN=idp.example.test" || fail "certificate subject missing"
echo "$OUT" | grep -q "RSA-2048" || fail "key type missing"
echo "$OUT" | grep -q "sha256" || fail "fingerprint missing"

echo "11. decode --pretty re-indents without rewriting prefixes"
"$BIN" decode --pretty "$ROOT/examples/response-post.b64" \
  | grep -q "^  <saml:Issuer>https://idp.example.test/saml</saml:Issuer>" \
  || fail "pretty output wrong"

echo "12. usage errors exit 2"
set +e
"$BIN" explain --format yaml "$ROOT/examples/response-post.b64" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
"$BIN" frobnicate >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown command should exit 2"
set -e

echo "SMOKE OK"

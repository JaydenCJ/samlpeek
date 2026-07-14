# Contributing to samlpeek

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — samlpeek is standard library only.

```bash
git clone https://github.com/JaydenCJ/samlpeek && cd samlpeek
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives every subcommand against
the committed example payloads (POST base64, redirect URL, broken
response, metadata), asserting on real output and exit codes; it must
finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network, no wall clock).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (decode, saml, lint, certs, render never touch the filesystem —
   only the cli package does).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No network calls, ever. SAML payloads contain credentials-equivalent
  material; the whole point of samlpeek is that they never leave the machine.
- Lint rules are data plus one function: a new rule needs a stable
  kebab-case ID, a test that makes it fire and one that keeps it silent,
  and a row in `docs/lint-rules.md`.
- Determinism first: every time-dependent check must honor `--now` and
  `--skew`, and test fixtures pin all timestamps.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `samlpeek version`, the full command you ran, and —
this is the important part — the payload *shape*: run
`samlpeek explain --format json` on it and redact the values you cannot
share (NameID, attribute values, certificates). The decode steps and
document structure are usually enough to reproduce a decoding or lint bug.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Transport auto-decoder (`decode`): raw XML, base64 in all four alphabets
  (padded/unpadded, standard/url-safe, whitespace-wrapped), raw-DEFLATE and
  zlib inflation with a 16 MB bomb cap, full HTTP-Redirect URLs, and bare
  query/form strings — with the applied step chain recorded and shown, plus
  `RelayState`/`SigAlg`/`Signature` capture and a `--pretty` lexical
  re-indenter that never rewrites namespace prefixes or content.
- Parser for the six SAML 2.0 document kinds (Response, bare Assertion,
  AuthnRequest, LogoutRequest, LogoutResponse, EntityDescriptor /
  EntitiesDescriptor) with a comment-aware NameID unmarshaller and
  flattened XML-DSig facts (algorithms, reference URI, certificates).
- `explain` subcommand: plain-language summaries — registered status codes
  and sub-codes translated to actionable sentences, conditions windows with
  durations, bearer confirmations, attributes, metadata endpoints and keys.
- `lint` subcommand with 57 rules and stable kebab-case IDs: expired /
  not-yet-valid conditions with `--skew`, audience / recipient / destination
  expectations, signature coverage, SHA-1 deprecation, certificate expiry,
  DTD presence, and the NameID comment-truncation attack shape; exit code 1
  on errors, `--strict` for warnings, `--now` for deterministic evaluation.
- `certs` subcommand: subject, validity, days-left, key type/size, and
  SHA-256 fingerprint for every certificate embedded in a document.
- Stable JSON output (`--format json`, `schema_version: 1`) for explain,
  lint, and certs.
- Runnable examples (healthy POST response, six-ways-broken response, full
  redirect URL, IdP metadata) with pinned timestamps and real test
  certificates, plus a complete rule reference in `docs/lint-rules.md`.
- 90 deterministic offline tests (unit + in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/samlpeek/releases/tag/v0.1.0

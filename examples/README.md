# samlpeek examples

Four offline payloads covering the shapes samlpeek decodes. Every timestamp
is pinned to 2026-07-12, so pass `--now 2026-07-12T09:01:00Z` to get the
exact outputs shown in the main README on any machine, on any date.

## response-post.b64

A healthy HTTP-POST `SAMLResponse`: base64-wrapped XML with a Success
status, one rsa-sha256-signed assertion for `alice@example.test`, a live
conditions window, an audience restriction, and three attributes.

```bash
samlpeek explain --now 2026-07-12T09:01:00Z examples/response-post.b64
samlpeek lint --now 2026-07-12T09:01:00Z --audience https://sp.example.test examples/response-post.b64
samlpeek certs --now 2026-07-12T09:01:00Z examples/response-post.b64
```

## bad-response.b64

The same login gone wrong in six distinct ways: expired conditions and
bearer window, SHA-1 signature and digest, an expired signing certificate,
an XML comment inside the NameID (the truncation-attack shape), no
audience restriction, and a bearer confirmation without a Recipient.

```bash
samlpeek lint --now 2026-07-12T09:01:00Z examples/bad-response.b64; echo "exit: $?"
```

## redirect-request.txt

A complete HTTP-Redirect URL as copied from a browser address bar: the
`SAMLRequest` parameter is percent-encoded, base64-encoded, raw-DEFLATE
compressed XML, alongside `RelayState`, `SigAlg`, and `Signature`.

```bash
samlpeek explain "$(cat examples/redirect-request.txt)"
samlpeek decode --pretty examples/redirect-request.txt
```

## idp-metadata.xml

IdP metadata with a signing certificate (CN=idp.example.test, valid
2025-01-01 → 2035-01-01), two SSO bindings, and a logout endpoint.

```bash
samlpeek explain --now 2026-07-12T09:01:00Z examples/idp-metadata.xml
samlpeek lint --now 2026-07-12T09:01:00Z examples/idp-metadata.xml
```

The certificates are real self-signed RSA-2048 test certificates generated
once for this repository; the signature *values* are placeholders, which is
fine because samlpeek inspects and lints signatures but never verifies them.

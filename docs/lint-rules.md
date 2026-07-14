# samlpeek lint rules

Every rule has a stable kebab-case ID (safe to grep and to suppress in
wrapper scripts) and a fixed severity. `lint` exits `1` when any **error**
fires (add `--strict` to fail on warnings too). Time-based rules evaluate
against `--now` (default: current time) with `--skew` tolerance (default
90s) applied in the direction that forgives clock drift.

Severities: **error** — this login will (or should) fail; **warn** — works
today but is fragile or unsafe; *info* — worth knowing, never a failure.

## Rules for any document

| Rule | Severity | Meaning |
|---|---|---|
| `doctype-present` | error | Document carries a `<!DOCTYPE>`; SAML forbids DTDs (XXE / entity-expansion vector) |
| `bad-timestamp` | error | An xs:dateTime attribute does not parse |
| `naive-timestamp` | warn | Timestamp has no timezone; SAML requires UTC `Z` |
| `version-mismatch` | error | `Version` attribute is not `2.0` |

## Signature and certificate rules (responses, assertions, requests, metadata)

| Rule | Severity | Meaning |
|---|---|---|
| `weak-signature-algorithm` | warn | rsa-sha1 signature; deprecated everywhere |
| `weak-digest-algorithm` | warn | sha1 digest; deprecated everywhere |
| `signature-no-reference` | warn | Signature Reference URI is empty; unclear what is signed |
| `unparseable-certificate` | error | Embedded X509Certificate is not valid base64/DER |
| `certificate-expired` | error | Certificate NotAfter is in the past |
| `certificate-not-yet-valid` | error | Certificate NotBefore is in the future |
| `certificate-expiring-soon` | warn | Certificate expires within 30 days (metadata renewal window) |
| `weak-certificate-key` | warn | RSA key below 2048 bits |

## Response and assertion rules

| Rule | Severity | Meaning |
|---|---|---|
| `status-missing` | error | No StatusCode at all |
| `status-not-success` | error | Status is not Success; message explains the registered code and sub-code |
| `destination-mismatch` | error | `Destination` differs from `--destination` |
| `no-assertion` | error | Success response with no assertion to consume |
| `encrypted-assertion` | info | EncryptedAssertion present; needs the SP private key to inspect |
| `multiple-assertions` | warn | More than one assertion; many SPs only read the first |
| `nothing-signed` | error | Neither the Response nor any Assertion is signed |
| `response-not-signed` | info | Response unsigned but the assertion is signed (commonly accepted) |
| `missing-issuer` | error | No Issuer element |
| `assertion-expired` | error | Conditions NotOnOrAfter is past (beyond skew) |
| `assertion-not-yet-valid` | error | Conditions NotBefore is in the future (beyond skew) |
| `inverted-validity-window` | error | NotBefore is not before NotOnOrAfter |
| `long-validity-window` | warn | Window exceeds 24 h; widens the replay surface |
| `no-conditions` | warn | No Conditions element at all |
| `no-audience-restriction` | warn | No AudienceRestriction; replayable to any trusting SP |
| `audience-mismatch` | error | Audiences do not include `--audience` |
| `missing-subject` / `missing-nameid` / `empty-nameid` | warn | Subject or NameID absent/empty |
| `encrypted-nameid` | info | EncryptedID; cannot inspect offline |
| `nameid-comment` | error | XML comment inside NameID — the comment-truncation attack shape |
| `no-bearer-confirmation` | info | No bearer method; Web Browser SSO requires it |
| `bearer-no-data` / `bearer-no-recipient` / `bearer-no-expiry` | warn | Bearer confirmation missing required fields |
| `recipient-mismatch` | error | Bearer Recipient differs from `--recipient` |
| `bearer-expired` | error | Bearer NotOnOrAfter is past (beyond skew) |
| `session-expired` | warn | SessionNotOnOrAfter is past |

## Metadata rules

| Rule | Severity | Meaning |
|---|---|---|
| `missing-entity-id` | error | EntityDescriptor without entityID |
| `metadata-expired` | error | `validUntil` is past; peers must stop using the document |
| `no-sso-role` | warn | Neither IdP nor SP role declared |
| `no-sso-endpoint` / `no-acs-endpoint` | error | Role missing its essential endpoint |
| `duplicate-acs-index` | error | Two AssertionConsumerService entries share an index |
| `unsigned-assertions-accepted` | warn | SP sets `WantAssertionsSigned="false"` |
| `no-signing-key` | warn | Role advertises no signing certificate |
| `insecure-endpoint` | warn | Plain `http://` endpoint (loopback exempt) |
| `endpoint-no-location` | warn | Endpoint with an empty Location |
| `no-nameid-format` | info | IdP advertises no NameIDFormat |

## AuthnRequest and logout rules

| Rule | Severity | Meaning |
|---|---|---|
| `missing-id` | error | AuthnRequest without ID; response correlation breaks |
| `forceauthn-and-ispassive` | error | Both flags true — contradictory by definition |
| `no-acs-url` | info | No ACS URL; the IdP falls back to registered metadata |
| `logout-request-expired` | error | LogoutRequest NotOnOrAfter is past |
| `no-session-index` | info | LogoutRequest ends every session for the principal |
| `unsolicited-logout-response` | warn | LogoutResponse without InResponseTo |

## What lint deliberately does not do

samlpeek never verifies XML-DSig signatures — that requires exclusive
canonicalization and belongs to your SAML stack, not a debugging tool.
It reports *presence*, *algorithms*, and *certificate health* instead, and
tells you honestly when content is encrypted beyond offline reach.

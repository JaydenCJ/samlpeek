// Tests for the lint rules. Pattern: start from the healthy fixture
// (fixture.Good()), break exactly one thing, and assert that exactly the
// expected rule fires — plus negative assertions proving the healthy
// response stays clean. All times are pinned; nothing reads the wall clock.
package lint

import (
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/fixture"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// now matches fixture.Now (2026-07-12T09:01:00Z).
var now = time.Date(2026, 7, 12, 9, 1, 0, 0, time.UTC)

// opts is the baseline evaluation context used unless a test overrides it.
var opts = Options{
	Now:       now,
	Skew:      90 * time.Second,
	Audience:  "https://sp.example.test",
	Recipient: "https://sp.example.test/saml/acs",
}

// check parses XML and lints it.
func check(t *testing.T, xml string, o Options) []Finding {
	t.Helper()
	doc, err := saml.Parse([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	return Check(doc, o)
}

// rules extracts the fired rule IDs.
func rules(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.Rule] = f
	}
	return out
}

// assertRule requires that a rule fired at the given severity.
func assertRule(t *testing.T, fs []Finding, rule string, sev Severity) Finding {
	t.Helper()
	f, ok := rules(fs)[rule]
	if !ok {
		t.Fatalf("rule %q did not fire; got %v", rule, ruleNames(fs))
	}
	if f.Severity != sev {
		t.Fatalf("rule %q severity = %v, want %v", rule, f.Severity, sev)
	}
	return f
}

// assertNoRule requires that a rule did not fire.
func assertNoRule(t *testing.T, fs []Finding, rule string) {
	t.Helper()
	if _, ok := rules(fs)[rule]; ok {
		t.Fatalf("rule %q fired unexpectedly", rule)
	}
}

func ruleNames(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestHealthyResponseHasNoErrors(t *testing.T) {
	fs := check(t, fixture.Response(fixture.Good()), opts)
	errors, _, _ := Count(fs)
	if errors != 0 {
		t.Fatalf("healthy response produced errors: %v", ruleNames(fs))
	}
	// The only expected finding is the informational response-not-signed.
	assertRule(t, fs, "response-not-signed", Info)
}

func TestStatusNotSuccessExplainsSubcode(t *testing.T) {
	o := fixture.Good()
	o.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	o.StatusSub = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	o.StatusMessage = "MFA denied"
	f := assertRule(t, check(t, fixture.Response(o), opts), "status-not-success", Error)
	for _, want := range []string{"Responder", "AuthnFailed", "failed to authenticate", "MFA denied"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message missing %q: %s", want, f.Message)
		}
	}
}

func TestConditionsExpiryRespectsSkew(t *testing.T) {
	// 31 minutes past NotOnOrAfter: dead, on both conditions and bearer.
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T08:30:00Z"
	o.BearerExpiry = "2026-07-12T08:30:00Z"
	fs := check(t, fixture.Response(o), opts)
	assertRule(t, fs, "assertion-expired", Error)
	assertRule(t, fs, "bearer-expired", Error)

	// 60 s past is inside the 90 s skew allowance: silent.
	o = fixture.Good()
	o.NotOnOrAfter = "2026-07-12T09:00:00Z"
	o.BearerExpiry = "2026-07-12T09:00:00Z"
	fs = check(t, fixture.Response(o), opts)
	assertNoRule(t, fs, "assertion-expired")
	assertNoRule(t, fs, "bearer-expired")

	// NotBefore 9 minutes ahead: not yet valid, beyond any skew.
	o = fixture.Good()
	o.NotBefore = "2026-07-12T09:10:00Z"
	o.NotOnOrAfter = "2026-07-12T09:20:00Z"
	assertRule(t, check(t, fixture.Response(o), opts), "assertion-not-yet-valid", Error)
}

func TestValidityWindowShapeRules(t *testing.T) {
	o := fixture.Good()
	o.NotBefore = "2026-07-12T09:05:00Z"
	o.NotOnOrAfter = "2026-07-12T08:55:00Z"
	assertRule(t, check(t, fixture.Response(o), opts), "inverted-validity-window", Error)

	o = fixture.Good()
	o.NotBefore = "2026-07-12T08:55:00Z"
	o.NotOnOrAfter = "2026-07-20T08:55:00Z" // 8 days
	assertRule(t, check(t, fixture.Response(o), opts), "long-validity-window", Warn)
}

func TestConditionsAndAudiencePresenceRules(t *testing.T) {
	o := fixture.Good()
	o.OmitAudience = true
	assertRule(t, check(t, fixture.Response(o), opts), "no-audience-restriction", Warn)

	o = fixture.Good()
	o.OmitConditions = true
	assertRule(t, check(t, fixture.Response(o), opts), "no-conditions", Warn)

	// Matching audience, and audience without an expectation flag: silent.
	assertNoRule(t, check(t, fixture.Response(fixture.Good()), opts), "audience-mismatch")
	noFlag := opts
	noFlag.Audience = ""
	assertNoRule(t, check(t, fixture.Response(fixture.Good()), noFlag), "audience-mismatch")
}

func TestExpectationFlagMismatches(t *testing.T) {
	o := opts
	o.Audience = "https://other-sp.example.test"
	f := assertRule(t, check(t, fixture.Response(fixture.Good()), o), "audience-mismatch", Error)
	if !strings.Contains(f.Message, "https://sp.example.test") || !strings.Contains(f.Message, "other-sp") {
		t.Errorf("message should quote both sides: %s", f.Message)
	}

	o = opts
	o.Recipient = "https://sp.example.test/different/acs"
	assertRule(t, check(t, fixture.Response(fixture.Good()), o), "recipient-mismatch", Error)

	o = opts
	o.Destination = "https://sp.example.test/expected/acs"
	assertRule(t, check(t, fixture.Response(fixture.Good()), o), "destination-mismatch", Error)
}

func TestBearerDataCompletenessRules(t *testing.T) {
	o := fixture.Good()
	o.OmitRecipient = true
	fs := check(t, fixture.Response(o), opts)
	assertRule(t, fs, "bearer-no-recipient", Warn)
	assertNoRule(t, fs, "recipient-mismatch") // absent ≠ mismatched

	o = fixture.Good()
	o.BearerExpiry = "-"
	assertRule(t, check(t, fixture.Response(o), opts), "bearer-no-expiry", Warn)
}

func TestSignatureCoverageRules(t *testing.T) {
	// Nothing signed at all: error.
	o := fixture.Good()
	o.AssertionSigned = false
	fs := check(t, fixture.Response(o), opts)
	assertRule(t, fs, "nothing-signed", Error)
	assertNoRule(t, fs, "response-not-signed")

	// Signed response with unsigned assertion is an accepted layout.
	o = fixture.Good()
	o.AssertionSigned = false
	o.ResponseSigned = true
	fs = check(t, fixture.Response(o), opts)
	assertNoRule(t, fs, "nothing-signed")
	assertNoRule(t, fs, "response-not-signed")
}

func TestWeakAlgorithmRules(t *testing.T) {
	o := fixture.Good()
	o.SigAlg = fixture.SigRSASHA1
	o.DigestAlg = fixture.DigSHA1
	fs := check(t, fixture.Response(o), opts)
	assertRule(t, fs, "weak-signature-algorithm", Warn)
	assertRule(t, fs, "weak-digest-algorithm", Warn)

	// SHA-256 pair is the modern baseline: silent.
	fs = check(t, fixture.Response(fixture.Good()), opts)
	assertNoRule(t, fs, "weak-signature-algorithm")
	assertNoRule(t, fs, "weak-digest-algorithm")
}

func TestExpiredSigningCertificate(t *testing.T) {
	o := fixture.Good()
	o.Cert = fixture.CertExpired
	f := assertRule(t, check(t, fixture.Response(o), opts), "certificate-expired", Error)
	if !strings.Contains(f.Message, "old-idp.example.test") {
		t.Errorf("message should name the cert: %s", f.Message)
	}
}

func TestNameIDRules(t *testing.T) {
	o := fixture.Good()
	o.NameIDXML = `<saml:NameID>alice@example.test<!-- -->.attacker.test</saml:NameID>`
	f := assertRule(t, check(t, fixture.Response(o), opts), "nameid-comment", Error)
	if !strings.Contains(f.Message, "alice@example.test.attacker.test") {
		t.Errorf("message should quote the full NameID: %s", f.Message)
	}

	o = fixture.Good()
	o.OmitNameID = true
	assertRule(t, check(t, fixture.Response(o), opts), "missing-nameid", Warn)
}

func TestAssertionPresenceRules(t *testing.T) {
	// Success with no assertion: the SP has nothing to consume.
	o := fixture.Good()
	o.OmitAssertion = true
	assertRule(t, check(t, fixture.Response(o), opts), "no-assertion", Error)

	// A failed login legitimately has no assertion; only the status
	// error should fire.
	o.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	fs := check(t, fixture.Response(o), opts)
	assertRule(t, fs, "status-not-success", Error)
	assertNoRule(t, fs, "no-assertion")

	// Encrypted assertion: honest info, not a false error.
	o = fixture.Good()
	o.OmitAssertion = true
	o.EncryptedAssertion = true
	fs = check(t, fixture.Response(o), opts)
	assertRule(t, fs, "encrypted-assertion", Info)
	assertNoRule(t, fs, "no-assertion")
}

func TestMultipleAssertionsWarn(t *testing.T) {
	o := fixture.Good()
	o.ExtraAssertion = true
	assertRule(t, check(t, fixture.Response(o), opts), "multiple-assertions", Warn)
}

func TestDoctypeIsError(t *testing.T) {
	xml := "<!DOCTYPE x>" + fixture.Response(fixture.Good())
	assertRule(t, check(t, xml, opts), "doctype-present", Error)
}

func TestTimestampQualityRules(t *testing.T) {
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T09:05:00" // no timezone designator
	assertRule(t, check(t, fixture.Response(o), opts), "naive-timestamp", Warn)

	o = fixture.Good()
	o.NotOnOrAfter = "soonish"
	assertRule(t, check(t, fixture.Response(o), opts), "bad-timestamp", Error)
}

func TestFindingsSortedErrorsFirst(t *testing.T) {
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T08:30:00Z" // error
	o.SigAlg = fixture.SigRSASHA1           // warn
	fs := check(t, fixture.Response(o), opts)
	last := Error
	for _, f := range fs {
		if f.Severity > last {
			t.Fatalf("findings not sorted by severity: %v", ruleNames(fs))
		}
		last = f.Severity
	}
}

// --- metadata rules ---

func TestHealthyIdPMetadataIsClean(t *testing.T) {
	fs := check(t, fixture.Metadata(fixture.MetadataOpts{}), opts)
	if len(fs) != 0 {
		t.Fatalf("healthy metadata produced findings: %v", ruleNames(fs))
	}
}

func TestMetadataExpiryRules(t *testing.T) {
	o := fixture.MetadataOpts{ValidUntil: "2026-07-01T00:00:00Z"}
	assertRule(t, check(t, fixture.Metadata(o), opts), "metadata-expired", Error)

	o = fixture.MetadataOpts{Cert: fixture.CertExpired}
	assertRule(t, check(t, fixture.Metadata(o), opts), "certificate-expired", Error)

	// Evaluate 20 days before the valid cert's 2035-01-01 expiry.
	soon := opts
	soon.Now = time.Date(2034, 12, 12, 0, 0, 0, 0, time.UTC)
	f := assertRule(t, check(t, fixture.Metadata(fixture.MetadataOpts{}), soon), "certificate-expiring-soon", Warn)
	if !strings.Contains(f.Message, "20 days") {
		t.Errorf("message should count days: %s", f.Message)
	}
}

func TestMetadataEndpointAndKeyRules(t *testing.T) {
	o := fixture.MetadataOpts{SSOURL: "http://idp.example.test/sso"}
	assertRule(t, check(t, fixture.Metadata(o), opts), "insecure-endpoint", Warn)

	// Loopback HTTP is normal in local development: exempt.
	o = fixture.MetadataOpts{SSOURL: "http://127.0.0.1:8080/sso"}
	assertNoRule(t, check(t, fixture.Metadata(o), opts), "insecure-endpoint")

	o = fixture.MetadataOpts{OmitSSO: true}
	assertRule(t, check(t, fixture.Metadata(o), opts), "no-sso-endpoint", Error)

	o = fixture.MetadataOpts{KeyUse: "encryption"}
	assertRule(t, check(t, fixture.Metadata(o), opts), "no-signing-key", Warn)
}

func TestSPMetadataRules(t *testing.T) {
	o := fixture.MetadataOpts{SP: true, WantAssertionsSigned: "false"}
	assertRule(t, check(t, fixture.Metadata(o), opts), "unsigned-assertions-accepted", Warn)

	o = fixture.MetadataOpts{SP: true, DuplicateACSIndex: true}
	assertRule(t, check(t, fixture.Metadata(o), opts), "duplicate-acs-index", Error)
}

// --- request / logout rules ---

func TestAuthnRequestRules(t *testing.T) {
	fs := check(t, fixture.AuthnRequest(fixture.AuthnRequestOpts{}), opts)
	errors, warnings, _ := Count(fs)
	if errors+warnings != 0 {
		t.Fatalf("healthy request produced findings: %v", ruleNames(fs))
	}

	o := fixture.AuthnRequestOpts{ForceAuthn: "true", IsPassive: "true"}
	assertRule(t, check(t, fixture.AuthnRequest(o), opts), "forceauthn-and-ispassive", Error)

	o = fixture.AuthnRequestOpts{OmitIssuer: true}
	assertRule(t, check(t, fixture.AuthnRequest(o), opts), "missing-issuer", Error)

	o = fixture.AuthnRequestOpts{ACSURL: "-"}
	assertRule(t, check(t, fixture.AuthnRequest(o), opts), "no-acs-url", Info)
}

func TestLogoutRules(t *testing.T) {
	assertRule(t, check(t, fixture.LogoutRequest(true), opts), "nameid-comment", Error)
	assertNoRule(t, check(t, fixture.LogoutRequest(false), opts), "nameid-comment")

	fs := check(t, fixture.LogoutResponse("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"), opts)
	f := assertRule(t, fs, "status-not-success", Error)
	if !strings.Contains(f.Message, "PartialLogout") {
		t.Errorf("message = %s", f.Message)
	}
}

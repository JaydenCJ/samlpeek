// Tests for the text and JSON renderers: the explain view must surface
// every field an integrator greps for, and the JSON envelope must be
// stable, valid, and carry the documented schema_version.
package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/certs"
	"github.com/JaydenCJ/samlpeek/internal/decode"
	"github.com/JaydenCJ/samlpeek/internal/fixture"
	"github.com/JaydenCJ/samlpeek/internal/lint"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

var now = time.Date(2026, 7, 12, 9, 1, 0, 0, time.UTC)

// parse builds the (doc, dec) pair the renderers consume.
func parse(t *testing.T, xml string) (*saml.Document, *decode.Result) {
	t.Helper()
	dec, err := decode.Auto([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := saml.Parse(dec.XML)
	if err != nil {
		t.Fatal(err)
	}
	return doc, dec
}

func TestExplainResponseShowsTheEssentials(t *testing.T) {
	doc, dec := parse(t, fixture.Response(fixture.Good()))
	var buf bytes.Buffer
	Explain(&buf, doc, dec, now)
	out := buf.String()
	for _, want := range []string{
		"SAML Response",
		"https://idp.example.test/saml",                             // issuer
		"Success — the request succeeded",                           // explained status
		"alice@example.test  [emailAddress]",                        // subject + format
		"2026-07-12T08:55:00Z → 2026-07-12T09:05:00Z  (window 10m)", // conditions
		"https://sp.example.test",                                   // audience
		"rsa-sha256 / sha256",                                       // signature algorithms
		"cert CN=idp.example.test expires 2035-01-01",
		"PasswordProtectedTransport", // authn context
		"Attributes (3)",
		"groups       admins, engineers",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainShowsDecodeChain(t *testing.T) {
	doc, dec := parse(t, fixture.Response(fixture.Good()))
	dec.Steps = []string{"extract SAMLResponse from query", "percent-decode", "base64 (standard)", "already XML"}
	dec.Binding = "http-post"
	dec.RelayState = "/dashboard"
	var buf bytes.Buffer
	Explain(&buf, doc, dec, now)
	out := buf.String()
	if !strings.Contains(out, "decode: extract SAMLResponse from query → percent-decode → base64 (standard) → already XML") {
		t.Errorf("decode chain not shown:\n%s", out)
	}
	if !strings.Contains(out, "relay-state: /dashboard") {
		t.Errorf("relay state not shown:\n%s", out)
	}
}

func TestExplainMarksExpiredCertificate(t *testing.T) {
	o := fixture.Good()
	o.Cert = fixture.CertExpired
	doc, dec := parse(t, fixture.Response(o))
	var buf bytes.Buffer
	Explain(&buf, doc, dec, now)
	if !strings.Contains(buf.String(), "[expired]") {
		t.Errorf("expired cert not marked:\n%s", buf.String())
	}
}

func TestExplainMetadataListsEndpointsAndKeys(t *testing.T) {
	doc, dec := parse(t, fixture.Metadata(fixture.MetadataOpts{}))
	var buf bytes.Buffer
	Explain(&buf, doc, dec, now)
	out := buf.String()
	for _, want := range []string{
		"EntityDescriptor",
		"IdP role",
		"SSO   HTTP-Redirect  https://idp.example.test/sso",
		"NameIDFormat  emailAddress",
		"CN=idp.example.test, RSA-2048, expires 2035-01-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata explain missing %q:\n%s", want, out)
		}
	}
}

func TestLintTextShowsVerdictAndCounts(t *testing.T) {
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T08:30:00Z"
	doc, _ := parse(t, fixture.Response(o))
	lopts := lint.Options{Now: now, Skew: 90 * time.Second}
	findings := lint.Check(doc, lopts)
	var buf bytes.Buffer
	Lint(&buf, doc, findings, lopts)
	out := buf.String()
	if !strings.Contains(out, "ERROR  assertion-expired") {
		t.Errorf("finding line missing:\n%s", out)
	}
	if !strings.Contains(out, "— FAIL") {
		t.Errorf("verdict missing:\n%s", out)
	}
	if !strings.Contains(out, "evaluated at 2026-07-12T09:01:00Z (skew 1m30s)") {
		t.Errorf("evaluation context missing:\n%s", out)
	}
}

func TestLintTextPassVerdict(t *testing.T) {
	doc, _ := parse(t, fixture.Metadata(fixture.MetadataOpts{}))
	lopts := lint.Options{Now: now, Skew: 90 * time.Second}
	var buf bytes.Buffer
	Lint(&buf, doc, lint.Check(doc, lopts), lopts)
	if !strings.Contains(buf.String(), "0 errors, 0 warnings, 0 info — PASS") {
		t.Errorf("clean pass line missing:\n%s", buf.String())
	}
}

// The summary line must agree in number: "1 error", never "1 errors" or
// the lazy "1 error(s)".
func TestCountNounPluralizesCorrectly(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{{0, "0 errors"}, {1, "1 error"}, {2, "2 errors"}}
	for _, c := range cases {
		if got := countNoun(c.n, "error"); got != c.want {
			t.Errorf("countNoun(%d, \"error\") = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestExplainJSONEnvelope(t *testing.T) {
	doc, dec := parse(t, fixture.Response(fixture.Good()))
	var buf bytes.Buffer
	if err := ExplainJSON(&buf, doc, dec); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if env["tool"] != "samlpeek" || env["schema_version"] != float64(1) {
		t.Errorf("envelope header wrong: %v", env)
	}
	resp := env["response"].(map[string]any)
	if resp["status"] != "Success" {
		t.Errorf("status = %v", resp["status"])
	}
	assertions := resp["assertions"].([]any)
	first := assertions[0].(map[string]any)
	if first["name_id"] != "alice@example.test" {
		t.Errorf("name_id = %v", first["name_id"])
	}
	if first["signed"] != true {
		t.Errorf("signed = %v", first["signed"])
	}
	auds := first["audiences"].([]any)
	if len(auds) != 1 || auds[0] != "https://sp.example.test" {
		t.Errorf("audiences = %v", auds)
	}
}

func TestLintJSONSummaryAndFindings(t *testing.T) {
	o := fixture.Good()
	o.SigAlg = fixture.SigRSASHA1
	doc, dec := parse(t, fixture.Response(o))
	lopts := lint.Options{Now: now, Skew: 90 * time.Second}
	findings := lint.Check(doc, lopts)
	var buf bytes.Buffer
	if err := LintJSON(&buf, doc, dec, findings, lopts); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Findings []struct {
			Severity, Rule string
		} `json:"findings"`
		Summary struct {
			Errors, Warnings int
			Verdict          string `json:"verdict"`
		} `json:"summary"`
		SkewSeconds int `json:"skew_seconds"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Summary.Verdict != "pass" { // weak alg is a warning, not an error
		t.Errorf("verdict = %q", env.Summary.Verdict)
	}
	if env.SkewSeconds != 90 {
		t.Errorf("skew_seconds = %d", env.SkewSeconds)
	}
	found := false
	for _, f := range env.Findings {
		if f.Rule == "weak-signature-algorithm" && f.Severity == "warn" {
			found = true
		}
	}
	if !found {
		t.Errorf("weak-signature-algorithm missing from findings: %+v", env.Findings)
	}
}

func TestCertsTextListsFingerprint(t *testing.T) {
	doc, _ := parse(t, fixture.Response(fixture.Good()))
	var buf bytes.Buffer
	Certs(&buf, certs.Collect(doc), now)
	out := buf.String()
	for _, want := range []string{
		"CN=idp.example.test",
		"(Assertion signature)",
		"2025-01-01 → 2035-01-01",
		"RSA-2048",
		"self-signed",
		"sha256    ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("certs output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "days left") {
		t.Errorf("days-left missing:\n%s", out)
	}

	// A document with no certificates says so instead of printing nothing.
	doc2, _ := parse(t, fixture.LogoutRequest(false))
	buf.Reset()
	Certs(&buf, certs.Collect(doc2), now)
	if !strings.Contains(buf.String(), "no certificates found") {
		t.Errorf("empty case not handled:\n%s", buf.String())
	}
}

func TestCertsJSONStatusField(t *testing.T) {
	o := fixture.Good()
	o.Cert = fixture.CertExpired
	doc, _ := parse(t, fixture.Response(o))
	var buf bytes.Buffer
	if err := CertsJSON(&buf, doc, certs.Collect(doc), now); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Certificates []struct {
			Subject, Status string
			SelfSigned      bool `json:"self_signed"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Certificates) != 1 || env.Certificates[0].Status != "expired" {
		t.Fatalf("certificates = %+v", env.Certificates)
	}
}

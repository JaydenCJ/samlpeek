// Tests for SAML document parsing: root-kind dispatch, field extraction,
// the comment-aware NameID unmarshaller, and signature flattening. All
// fixtures are deterministic XML built by internal/fixture.
package saml

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/samlpeek/internal/fixture"
)

// parseResponse is a helper asserting the fixture parses as a Response.
func parseResponse(t *testing.T, xml string) *Response {
	t.Helper()
	doc, err := Parse([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != KindResponse || doc.Response == nil {
		t.Fatalf("kind = %v, want Response", doc.Kind)
	}
	return doc.Response
}

func TestParseResponseHeaderFields(t *testing.T) {
	r := parseResponse(t, fixture.Response(fixture.Good()))
	if r.ID != "_resp-7f3d9a12" {
		t.Errorf("ID = %q", r.ID)
	}
	if r.Version != "2.0" {
		t.Errorf("Version = %q", r.Version)
	}
	if r.Issuer != "https://idp.example.test/saml" {
		t.Errorf("Issuer = %q", r.Issuer)
	}
	if r.Destination != "https://sp.example.test/saml/acs" {
		t.Errorf("Destination = %q", r.Destination)
	}
	if r.InResponseTo != "_authnreq-42" {
		t.Errorf("InResponseTo = %q", r.InResponseTo)
	}
	if r.Status.Code.Value != StatusSuccess {
		t.Errorf("status = %q", r.Status.Code.Value)
	}
}

func TestParseStatusSubcodeAndMessage(t *testing.T) {
	opts := fixture.Good()
	opts.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	opts.StatusSub = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	opts.StatusMessage = "user cancelled at MFA prompt"
	r := parseResponse(t, fixture.Response(opts))
	if r.Status.Code.Sub == nil || r.Status.Code.Sub.Value != "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" {
		t.Fatalf("subcode not parsed: %+v", r.Status.Code)
	}
	if r.Status.Message != "user cancelled at MFA prompt" {
		t.Errorf("message = %q", r.Status.Message)
	}
}

func TestParseSubjectConditionsAndBearer(t *testing.T) {
	r := parseResponse(t, fixture.Response(fixture.Good()))
	if len(r.Assertions) != 1 {
		t.Fatalf("assertions = %d, want 1", len(r.Assertions))
	}
	a := r.Assertions[0]
	if a.Subject == nil || a.Subject.NameID == nil {
		t.Fatal("subject/NameID missing")
	}
	if a.Subject.NameID.Value != "alice@example.test" {
		t.Errorf("NameID = %q", a.Subject.NameID.Value)
	}
	if got := NameIDFormatName(a.Subject.NameID.Format); got != "emailAddress" {
		t.Errorf("format = %q", got)
	}

	if a.Conditions == nil {
		t.Fatal("conditions missing")
	}
	if a.Conditions.NotBefore != fixture.NotBefore || a.Conditions.NotOnOrAfter != fixture.NotOnOrAfter {
		t.Errorf("window = %q → %q", a.Conditions.NotBefore, a.Conditions.NotOnOrAfter)
	}
	if aud := a.Conditions.Audiences(); len(aud) != 1 || aud[0] != "https://sp.example.test" {
		t.Errorf("audiences = %v", aud)
	}

	confs := a.Subject.Confirmations
	if len(confs) != 1 {
		t.Fatalf("confirmations = %d", len(confs))
	}
	c := confs[0]
	if c.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		t.Errorf("method = %q", c.Method)
	}
	if c.Data == nil || c.Data.Recipient != "https://sp.example.test/saml/acs" {
		t.Fatalf("recipient not parsed: %+v", c.Data)
	}
	if c.Data.InResponseTo != "_authnreq-42" {
		t.Errorf("InResponseTo = %q", c.Data.InResponseTo)
	}
}

func TestParseAttributesWithMultipleValues(t *testing.T) {
	r := parseResponse(t, fixture.Response(fixture.Good()))
	attrs := r.Assertions[0].Attributes()
	if len(attrs) != 3 {
		t.Fatalf("attributes = %d, want 3", len(attrs))
	}
	byName := map[string][]string{}
	for _, a := range attrs {
		byName[a.Name] = a.Values
	}
	if got := byName["groups"]; len(got) != 2 || got[0] != "admins" || got[1] != "engineers" {
		t.Errorf("groups = %v", got)
	}
	if got := byName["email"]; len(got) != 1 || got[0] != "alice@example.test" {
		t.Errorf("email = %v", got)
	}
}

func TestParseSignaturesFlattenedAndDistinct(t *testing.T) {
	opts := fixture.Good()
	opts.ResponseSigned = true
	r := parseResponse(t, fixture.Response(opts))

	sig := r.Assertions[0].Signature
	if sig == nil {
		t.Fatal("assertion signature missing")
	}
	if AlgorithmName(sig.SignatureAlg) != "rsa-sha256" {
		t.Errorf("sig alg = %q", sig.SignatureAlg)
	}
	if AlgorithmName(sig.DigestAlg) != "sha256" {
		t.Errorf("digest alg = %q", sig.DigestAlg)
	}
	if sig.ReferenceURI != "#_assert-91af" {
		t.Errorf("assertion reference = %q", sig.ReferenceURI)
	}
	if len(sig.Certificates) != 1 || !strings.HasPrefix(sig.Certificates[0], "MIID") {
		t.Errorf("certificates not captured")
	}

	// The response's own signature must not be confused with the
	// assertion's — mixing them up is how SPs mis-verify.
	if r.Signature == nil {
		t.Fatal("response signature missing")
	}
	if r.Signature.ReferenceURI != "#_resp-7f3d9a12" {
		t.Errorf("response reference = %q", r.Signature.ReferenceURI)
	}
}

func TestNameIDCommentDetection(t *testing.T) {
	// Trailing comment: detected, value intact.
	opts := fixture.Good()
	opts.NameIDXML = `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test<!-- --></saml:NameID>`
	n := parseResponse(t, fixture.Response(opts)).Assertions[0].Subject.NameID
	if !n.HasComment {
		t.Fatal("comment inside NameID was not detected")
	}
	if n.Value != "alice@example.test" {
		t.Errorf("value = %q", n.Value)
	}

	// Comment splitting the value (the truncation-attack shape): the
	// reported value must be the full concatenation, not the prefix a
	// vulnerable stack would see.
	opts = fixture.Good()
	opts.NameIDXML = `<saml:NameID>alice@example.test<!-- -->.attacker.test</saml:NameID>`
	n = parseResponse(t, fixture.Response(opts)).Assertions[0].Subject.NameID
	if !n.HasComment {
		t.Fatal("splitting comment not detected")
	}
	if n.Value != "alice@example.test.attacker.test" {
		t.Errorf("value = %q, want the full concatenation", n.Value)
	}

	// No comment: no false positive.
	n = parseResponse(t, fixture.Response(fixture.Good())).Assertions[0].Subject.NameID
	if n.HasComment {
		t.Fatal("false positive comment detection")
	}
}

func TestAssertionMultiplicityParsing(t *testing.T) {
	opts := fixture.Good()
	opts.EncryptedAssertion = true
	opts.OmitAssertion = true
	r := parseResponse(t, fixture.Response(opts))
	if len(r.EncryptedAssertions) != 1 {
		t.Fatalf("encrypted assertions = %d, want 1", len(r.EncryptedAssertions))
	}
	if len(r.Assertions) != 0 {
		t.Fatalf("plain assertions = %d, want 0", len(r.Assertions))
	}

	opts = fixture.Good()
	opts.ExtraAssertion = true
	r = parseResponse(t, fixture.Response(opts))
	if len(r.Assertions) != 2 {
		t.Fatalf("assertions = %d, want 2", len(r.Assertions))
	}
	if r.Assertions[1].ID != "_assert-2nd00" {
		t.Errorf("second assertion ID = %q", r.Assertions[1].ID)
	}
}

func TestParseAuthnRequest(t *testing.T) {
	doc, err := Parse([]byte(fixture.AuthnRequest(fixture.AuthnRequestOpts{})))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != KindAuthnRequest {
		t.Fatalf("kind = %v", doc.Kind)
	}
	r := doc.AuthnRequest
	if r.Issuer != "https://sp.example.test" {
		t.Errorf("issuer = %q", r.Issuer)
	}
	if r.ACSURL != "https://sp.example.test/saml/acs" {
		t.Errorf("acs = %q", r.ACSURL)
	}
	if r.NameIDPolicy == nil || NameIDFormatName(r.NameIDPolicy.Format) != "emailAddress" {
		t.Errorf("NameIDPolicy not parsed")
	}
}

func TestParseLogoutRequestAndResponse(t *testing.T) {
	doc, err := Parse([]byte(fixture.LogoutRequest(false)))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != KindLogoutRequest || doc.LogoutRequest.NameID == nil {
		t.Fatalf("logout request not parsed: %+v", doc)
	}
	if doc.LogoutRequest.NameID.Value != "alice@example.test" {
		t.Errorf("NameID = %q", doc.LogoutRequest.NameID.Value)
	}

	doc2, err := Parse([]byte(fixture.LogoutResponse(StatusSuccess)))
	if err != nil {
		t.Fatal(err)
	}
	if doc2.Kind != KindLogoutResponse || doc2.LogoutResponse.Status.Code.Value != StatusSuccess {
		t.Fatalf("logout response not parsed")
	}
}

func TestParseMetadataRoles(t *testing.T) {
	// IdP role.
	doc, err := Parse([]byte(fixture.Metadata(fixture.MetadataOpts{})))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != KindEntityDescriptor || doc.Entity == nil {
		t.Fatalf("kind = %v", doc.Kind)
	}
	idp := doc.Entity.IDPSSO
	if idp == nil {
		t.Fatal("IDPSSODescriptor missing")
	}
	if len(idp.SSOServices) != 2 {
		t.Fatalf("sso endpoints = %d, want 2", len(idp.SSOServices))
	}
	if BindingName(idp.SSOServices[0].Binding) != "HTTP-Redirect" {
		t.Errorf("binding = %q", idp.SSOServices[0].Binding)
	}
	if len(idp.KeyDescriptors) != 1 || len(idp.KeyDescriptors[0].Certificates) != 1 {
		t.Fatalf("key descriptors not parsed")
	}

	// SP role.
	doc2, err := Parse([]byte(fixture.Metadata(fixture.MetadataOpts{SP: true, WantAssertionsSigned: "true"})))
	if err != nil {
		t.Fatal(err)
	}
	sp := doc2.Entity.SPSSO
	if sp == nil {
		t.Fatal("SPSSODescriptor missing")
	}
	if sp.WantAssertionsSigned != "true" {
		t.Errorf("WantAssertionsSigned = %q", sp.WantAssertionsSigned)
	}
	if len(sp.ACS) != 1 || sp.ACS[0].Index != "0" || !strings.EqualFold(sp.ACS[0].IsDefault, "true") {
		t.Errorf("ACS not parsed: %+v", sp.ACS)
	}
}

func TestParseBareAssertion(t *testing.T) {
	// Extract just the assertion element from the full response fixture.
	full := fixture.Response(fixture.Good())
	start := strings.Index(full, "<saml:Assertion")
	end := strings.Index(full, "</saml:Assertion>") + len("</saml:Assertion>")
	bare := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` + full[start+len("<saml:Assertion"):end]
	doc, err := Parse([]byte(bare))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Kind != KindAssertion || doc.Assertion == nil {
		t.Fatalf("kind = %v", doc.Kind)
	}
	if doc.Assertion.Subject.NameID.Value != "alice@example.test" {
		t.Errorf("NameID = %q", doc.Assertion.Subject.NameID.Value)
	}
}

func TestNonSAMLInputRejected(t *testing.T) {
	_, err := Parse([]byte(`<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`))
	if err == nil {
		t.Fatal("HTML must be rejected")
	}
	if !strings.Contains(err.Error(), "unrecognized root element") {
		t.Fatalf("error not descriptive: %v", err)
	}

	_, err = Parse([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`))
	if err == nil {
		t.Fatal("truncated XML must be rejected")
	}
}

func TestDoctypeDetection(t *testing.T) {
	xml := `<!DOCTYPE Response><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"><samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status></samlp:Response>`
	doc, err := Parse([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.HasDOCTYPE {
		t.Fatal("DOCTYPE not detected")
	}
	if doc2, _ := Parse([]byte(fixture.Response(fixture.Good()))); doc2 == nil || doc2.HasDOCTYPE {
		t.Fatal("false positive DOCTYPE")
	}
}

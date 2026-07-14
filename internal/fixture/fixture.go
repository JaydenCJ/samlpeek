// Package fixture builds deterministic SAML XML documents for tests. Every
// timestamp is pinned to 2026-07-12 so tests evaluate with an explicit
// "now" and never depend on the wall clock. The two embedded certificates
// are real self-signed RSA-2048 DER blobs with fixed validity windows
// (valid: 2025-01-01 → 2035-01-01; expired: 2020-01-01 → 2021-01-01),
// generated once and committed — nothing here touches crypto/rand.
package fixture

import (
	"fmt"
	"strings"
)

// Pinned instants shared by fixtures and tests.
const (
	Now          = "2026-07-12T09:01:00Z" // reference evaluation time
	IssueInstant = "2026-07-12T09:00:00Z"
	NotBefore    = "2026-07-12T08:55:00Z"
	NotOnOrAfter = "2026-07-12T09:05:00Z"
)

// Signature algorithm URI pairs.
const (
	SigRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SigRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	DigSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// CertValid is a real self-signed RSA-2048 certificate for
// CN=idp.example.test, valid 2025-01-01 → 2035-01-01.
const CertValid = "MIIDCDCCAfCgAwIBAgICD6EwDQYJKoZIhvcNAQELBQAwNjEZMBcGA1UEChMQRXhhbXBsZSBUZXN0IElkUDEZMBcGA1UEAxMQaWRwLmV4YW1wbGUudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMDYxGTAXBgNVBAoTEEV4YW1wbGUgVGVzdCBJZFAxGTAXBgNVBAMTEGlkcC5leGFtcGxlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAcVNHhtO7zX3WSe38yWG60qRxX/qBTGc+HadUQwLWm/CqK/jvEx6/2ZrDuG32ZTA+8dNgrno6VegfKHmgAeO7x8hTCCXM06UDDMibjdPAPSI0U664IYNEI3EcDzRCsyOlUBfWTeaVqFqp3KZRse6FN0gzLsfN1o1ExoQo1yw8jzyPKzJZeUz+rxcickStdSnjwwnZLEOb+e+fANKi1mPXbRtZw9/I2MJ6l90HKaNCdGQKzPBiGidogI6nOa1XSI50Zoc1Gr6uiblrXe/k/64VMWaKgu1HCrdQJRquQz4/2XTf8rLQJgHor0qxZRqt1e3AlCoMTUEiMMp4kyB/aiSnAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCEJHj2DcTX7/wWLKrqSCVazrS5XAi+8qWdWG8u+bkmIiFZMmU3o5ObUXOVumj5rhcDM3+Gx6/IpPyhXLE+9CvsK2GD6JsorNcEjp+W4GSOJIFRraCZ68GKWAPkh+tNoLOJBt47XOA0c4D2E51fuSNqk6zMzuFewa6mrmDlafL2HC/nic/Dmh7u06kX242vI8dqOcTIuMTsVoswlsdT5bXC1xDUCrFZknBJpKBq5ksVRB5YRcz6MI+bdIKWNPkaPdAUa3gX1rRKTdWC2+4cUmrEbK10X9kFdtS36rH6niKRrK8qk8h157QBHB3UVARcb9eOhhV8nKJe3KBLHj+I1tCk"

// CertExpired is a real self-signed RSA-2048 certificate for
// CN=old-idp.example.test, valid 2020-01-01 → 2021-01-01 (long dead).
const CertExpired = "MIIDEDCCAfigAwIBAgICD6IwDQYJKoZIhvcNAQELBQAwOjEZMBcGA1UEChMQRXhhbXBsZSBUZXN0IElkUDEdMBsGA1UEAxMUb2xkLWlkcC5leGFtcGxlLnRlc3QwHhcNMjAwMTAxMDAwMDAwWhcNMjEwMTAxMDAwMDAwWjA6MRkwFwYDVQQKExBFeGFtcGxlIFRlc3QgSWRQMR0wGwYDVQQDExRvbGQtaWRwLmV4YW1wbGUudGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANNYr8lsaNyrxD8E3ZfjNbEy4ppEeCO5Xw2/kwNAOJxybEAA32ELmkrmUIqoiIs2g+PWo82+UDYS+43BJ2Z8OEHSNr+O0Q84j5ito58ESNQpKLHrTZl7pz19xma7BRYBUAXyCs2epC25LCILwspbe+MkpKMTG0kSHtIc9LD8fd94yr26ZeQAUrfRF/Qp7Tmko8O44E+O52d08aN0sGCNt7K/e2vIdS27ddoaF+ZQCcw4iQ9S7+DDbNnMeLGz2k1/21Q6ztdUTFMTrrG/HSicIEM1f+tACN6BHJ9RoqFe3VQaY2YqArfbZg7hv8X64tV95UIMw945IwCSd0jbOw68nskCAwEAAaMgMB4wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAG2F5m0BEpk0ZzUeBHSCsyjsWzu/Php07xKG5vqGWBATAv7ebxk7H39igNyTK2o4z9mkIeIrQTIrA0q/P2Qyp0oUpP7fc/PlcYt07osD+InAIvEtSUbGIpgBXnhocfAazPsNzmOz5h0z6O9gxirXQZHNmhLKOR5Wgt1HHztqKDf7ZUD340gow9DgIR36jKlrwEtR3hTuoj8VgDh885h02DyCCj2dCux6HO99J7boGwxUhmO/zRXGOktLjps61DIMvABavSablQHzf351+8q7J3xGZ4IbtzEAiUcFfcYDSglSS6AOYxEnnLPiw06b7wllaOJ1i9qh6ZulXPKR4GTQJJE="

// ResponseOpts tweaks the golden response; the zero value plus Defaults()
// yields a healthy, signed-assertion login response.
type ResponseOpts struct {
	StatusCode     string // default Success
	StatusSub      string
	StatusMessage  string
	Destination    string
	ResponseSigned bool // add a signature on the Response element

	OmitAssertion      bool
	EncryptedAssertion bool
	ExtraAssertion     bool // append a second minimal assertion

	AssertionSigned bool   // default true via Defaults()
	SigAlg          string // default rsa-sha256
	DigestAlg       string // default sha256
	Cert            string // default CertValid; "" after Defaults() keeps default

	NameIDXML      string // raw NameID element override; "" = default alice
	OmitNameID     bool
	NotBefore      string // default NotBefore
	NotOnOrAfter   string // default NotOnOrAfter
	OmitConditions bool
	OmitAudience   bool
	Audience       string // default https://sp.example.test
	Recipient      string // default https://sp.example.test/saml/acs
	OmitRecipient  bool
	BearerExpiry   string // default NotOnOrAfter; "-" = omit
}

// Good returns the options for a healthy login response: Success status,
// signed assertion (rsa-sha256), live conditions window, matching audience
// and recipient. Tests start here and break exactly one thing.
func Good() ResponseOpts {
	return ResponseOpts{AssertionSigned: true}
}

// defaults fills the zero values with the healthy baseline.
func (o *ResponseOpts) defaults() {
	if o.StatusCode == "" {
		o.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	if o.Destination == "" {
		o.Destination = "https://sp.example.test/saml/acs"
	}
	if o.SigAlg == "" {
		o.SigAlg = SigRSASHA256
	}
	if o.DigestAlg == "" {
		o.DigestAlg = DigSHA256
	}
	if o.Cert == "" {
		o.Cert = CertValid
	}
	if o.NotBefore == "" {
		o.NotBefore = NotBefore
	}
	if o.NotOnOrAfter == "" {
		o.NotOnOrAfter = NotOnOrAfter
	}
	if o.Audience == "" {
		o.Audience = "https://sp.example.test"
	}
	if o.Recipient == "" {
		o.Recipient = "https://sp.example.test/saml/acs"
	}
	if o.BearerExpiry == "" {
		o.BearerExpiry = NotOnOrAfter
	}
	if o.NameIDXML == "" {
		o.NameIDXML = `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test</saml:NameID>`
	}
}

// signatureXML renders a ds:Signature block referencing refID.
func signatureXML(refID, sigAlg, digAlg, cert string) string {
	keyInfo := ""
	if cert != "" {
		keyInfo = fmt.Sprintf("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>", cert)
	}
	return fmt.Sprintf(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
		`<ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="%s"/>`+
		`<ds:Reference URI="#%s">`+
		`<ds:DigestMethod Algorithm="%s"/>`+
		`<ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>`+
		`</ds:Reference>`+
		`</ds:SignedInfo>`+
		`<ds:SignatureValue>ZmFrZS1zaWduYXR1cmUtZm9yLXRlc3Rz</ds:SignatureValue>`+
		`%s</ds:Signature>`, sigAlg, refID, digAlg, keyInfo)
}

// Response renders a samlp:Response according to the options.
func Response(o ResponseOpts) string {
	o.defaults()
	var b strings.Builder

	b.WriteString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`)
	b.WriteString(` ID="_resp-7f3d9a12" Version="2.0" IssueInstant="` + IssueInstant + `"`)
	b.WriteString(` Destination="` + o.Destination + `" InResponseTo="_authnreq-42">`)
	b.WriteString(`<saml:Issuer>https://idp.example.test/saml</saml:Issuer>`)
	if o.ResponseSigned {
		b.WriteString(signatureXML("_resp-7f3d9a12", o.SigAlg, o.DigestAlg, o.Cert))
	}

	b.WriteString(`<samlp:Status><samlp:StatusCode Value="` + o.StatusCode + `">`)
	if o.StatusSub != "" {
		b.WriteString(`<samlp:StatusCode Value="` + o.StatusSub + `"/>`)
	}
	b.WriteString(`</samlp:StatusCode>`)
	if o.StatusMessage != "" {
		b.WriteString(`<samlp:StatusMessage>` + o.StatusMessage + `</samlp:StatusMessage>`)
	}
	b.WriteString(`</samlp:Status>`)

	if o.EncryptedAssertion {
		b.WriteString(`<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>`)
	}
	if !o.OmitAssertion {
		b.WriteString(assertionXML(o, "_assert-91af"))
		if o.ExtraAssertion {
			b.WriteString(assertionXML(o, "_assert-2nd00"))
		}
	}
	b.WriteString(`</samlp:Response>`)
	return b.String()
}

// assertionXML renders one saml:Assertion per the options.
func assertionXML(o ResponseOpts, id string) string {
	var b strings.Builder
	b.WriteString(`<saml:Assertion ID="` + id + `" Version="2.0" IssueInstant="` + IssueInstant + `">`)
	b.WriteString(`<saml:Issuer>https://idp.example.test/saml</saml:Issuer>`)
	if o.AssertionSigned {
		b.WriteString(signatureXML(id, o.SigAlg, o.DigestAlg, o.Cert))
	}

	b.WriteString(`<saml:Subject>`)
	if !o.OmitNameID {
		b.WriteString(o.NameIDXML)
	}
	b.WriteString(`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`)
	b.WriteString(`<saml:SubjectConfirmationData`)
	if !o.OmitRecipient {
		b.WriteString(` Recipient="` + o.Recipient + `"`)
	}
	if o.BearerExpiry != "-" {
		b.WriteString(` NotOnOrAfter="` + o.BearerExpiry + `"`)
	}
	b.WriteString(` InResponseTo="_authnreq-42"/></saml:SubjectConfirmation></saml:Subject>`)

	if !o.OmitConditions {
		b.WriteString(`<saml:Conditions NotBefore="` + o.NotBefore + `" NotOnOrAfter="` + o.NotOnOrAfter + `">`)
		if !o.OmitAudience {
			b.WriteString(`<saml:AudienceRestriction><saml:Audience>` + o.Audience + `</saml:Audience></saml:AudienceRestriction>`)
		}
		b.WriteString(`</saml:Conditions>`)
	}

	b.WriteString(`<saml:AuthnStatement AuthnInstant="2026-07-12T08:59:58Z" SessionIndex="_sess-91af">`)
	b.WriteString(`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>`)
	b.WriteString(`</saml:AuthnStatement>`)

	b.WriteString(`<saml:AttributeStatement>`)
	b.WriteString(`<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>alice@example.test</saml:AttributeValue></saml:Attribute>`)
	b.WriteString(`<saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute>`)
	b.WriteString(`<saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>engineers</saml:AttributeValue></saml:Attribute>`)
	b.WriteString(`</saml:AttributeStatement>`)
	b.WriteString(`</saml:Assertion>`)
	return b.String()
}

// AuthnRequestOpts tweaks the AuthnRequest fixture.
type AuthnRequestOpts struct {
	OmitIssuer bool
	OmitID     bool
	ForceAuthn string
	IsPassive  string
	ACSURL     string // "-" = omit
}

// AuthnRequest renders a samlp:AuthnRequest.
func AuthnRequest(o AuthnRequestOpts) string {
	if o.ACSURL == "" {
		o.ACSURL = "https://sp.example.test/saml/acs"
	}
	var b strings.Builder
	b.WriteString(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`)
	if !o.OmitID {
		b.WriteString(` ID="_authnreq-42"`)
	}
	b.WriteString(` Version="2.0" IssueInstant="` + IssueInstant + `" Destination="https://idp.example.test/sso"`)
	if o.ACSURL != "-" {
		b.WriteString(` AssertionConsumerServiceURL="` + o.ACSURL + `"`)
	}
	b.WriteString(` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`)
	if o.ForceAuthn != "" {
		b.WriteString(` ForceAuthn="` + o.ForceAuthn + `"`)
	}
	if o.IsPassive != "" {
		b.WriteString(` IsPassive="` + o.IsPassive + `"`)
	}
	b.WriteString(`>`)
	if !o.OmitIssuer {
		b.WriteString(`<saml:Issuer>https://sp.example.test</saml:Issuer>`)
	}
	b.WriteString(`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>`)
	b.WriteString(`</samlp:AuthnRequest>`)
	return b.String()
}

// MetadataOpts tweaks the EntityDescriptor fixture.
type MetadataOpts struct {
	EntityID             string // default https://idp.example.test/saml
	ValidUntil           string
	Cert                 string // default CertValid
	KeyUse               string // default "signing"
	SSOURL               string // default https; set http:// to trigger the lint
	OmitSSO              bool
	SP                   bool // render an SP role instead of IdP
	WantAssertionsSigned string
	DuplicateACSIndex    bool
}

// Metadata renders an md:EntityDescriptor.
func Metadata(o MetadataOpts) string {
	if o.EntityID == "" {
		o.EntityID = "https://idp.example.test/saml"
	}
	if o.Cert == "" {
		o.Cert = CertValid
	}
	if o.KeyUse == "" {
		o.KeyUse = "signing"
	}
	if o.SSOURL == "" {
		o.SSOURL = "https://idp.example.test/sso"
	}
	var b strings.Builder
	b.WriteString(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + o.EntityID + `"`)
	if o.ValidUntil != "" {
		b.WriteString(` validUntil="` + o.ValidUntil + `"`)
	}
	b.WriteString(`>`)

	key := `<md:KeyDescriptor use="` + o.KeyUse + `"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + o.Cert + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`

	if o.SP {
		b.WriteString(`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"`)
		if o.WantAssertionsSigned != "" {
			b.WriteString(` WantAssertionsSigned="` + o.WantAssertionsSigned + `"`)
		}
		b.WriteString(`>`)
		b.WriteString(key)
		b.WriteString(`<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>`)
		b.WriteString(`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/saml/acs" index="0" isDefault="true"/>`)
		if o.DuplicateACSIndex {
			b.WriteString(`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/saml/acs2" index="0"/>`)
		}
		b.WriteString(`</md:SPSSODescriptor>`)
	} else {
		b.WriteString(`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
		b.WriteString(key)
		b.WriteString(`<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>`)
		if !o.OmitSSO {
			b.WriteString(`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + o.SSOURL + `"/>`)
			b.WriteString(`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + o.SSOURL + `"/>`)
		}
		b.WriteString(`</md:IDPSSODescriptor>`)
	}
	b.WriteString(`</md:EntityDescriptor>`)
	return b.String()
}

// LogoutRequest renders a samlp:LogoutRequest; comment=true injects an XML
// comment into the NameID.
func LogoutRequest(comment bool) string {
	name := `alice@example.test`
	if comment {
		name = `alice@example.test<!-- -->.attacker.test`
	}
	return `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="_logout-1" Version="2.0" IssueInstant="` + IssueInstant + `" Destination="https://idp.example.test/slo" NotOnOrAfter="` + NotOnOrAfter + `">` +
		`<saml:Issuer>https://sp.example.test</saml:Issuer>` +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + name + `</saml:NameID>` +
		`<samlp:SessionIndex>_sess-91af</samlp:SessionIndex>` +
		`</samlp:LogoutRequest>`
}

// LogoutResponse renders a samlp:LogoutResponse.
func LogoutResponse(status string) string {
	return `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="_logoutresp-1" Version="2.0" IssueInstant="` + IssueInstant + `" InResponseTo="_logout-1">` +
		`<saml:Issuer>https://idp.example.test/saml</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="` + status + `"/></samlp:Status>` +
		`</samlp:LogoutResponse>`
}

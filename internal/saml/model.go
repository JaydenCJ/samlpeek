// Package saml parses SAML 2.0 protocol messages, assertions, and metadata
// into a small, lint-friendly model. It reads only what the linter and the
// explain view need; it does not attempt XML canonicalization or signature
// verification (see the README for why that is out of scope for a decoder).
package saml

// Kind identifies the root document type.
type Kind string

const (
	KindResponse           Kind = "Response"
	KindAuthnRequest       Kind = "AuthnRequest"
	KindLogoutRequest      Kind = "LogoutRequest"
	KindLogoutResponse     Kind = "LogoutResponse"
	KindAssertion          Kind = "Assertion"
	KindEntityDescriptor   Kind = "EntityDescriptor"
	KindEntitiesDescriptor Kind = "EntitiesDescriptor"
)

// Document is the parsed root; exactly one of the pointer fields matching
// Kind is non-nil (EntitiesDescriptor fills Entities with every child).
type Document struct {
	Kind           Kind
	HasDOCTYPE     bool // a DTD was present in the raw bytes — always suspicious in SAML
	Response       *Response
	AuthnRequest   *AuthnRequest
	LogoutRequest  *LogoutRequest
	LogoutResponse *LogoutResponse
	Assertion      *Assertion // bare <Assertion> root
	Entity         *EntityDescriptor
	Entities       []EntityDescriptor
}

// Response is a samlp:Response.
type Response struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Destination  string `xml:"Destination,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Issuer     string      `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status     Status      `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Signature  *Signature  `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Assertions []Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	// EncryptedAssertions counts assertions samlpeek cannot open without
	// the SP private key; the linter reports them instead of hiding them.
	EncryptedAssertions []struct{} `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
}

// Status is the samlp:Status tree, flattened to two levels of StatusCode.
type Status struct {
	Code    StatusCode `xml:"StatusCode"`
	Message string     `xml:"StatusMessage"`
}

// StatusCode holds the top-level code and one nested sub-code level, which
// is where the useful diagnosis (AuthnFailed, InvalidNameIDPolicy, …) lives.
type StatusCode struct {
	Value string      `xml:"Value,attr"`
	Sub   *StatusCode `xml:"StatusCode"`
}

// Assertion is a saml:Assertion.
type Assertion struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`

	Issuer              string               `xml:"Issuer"`
	Signature           *Signature           `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Subject             *Subject             `xml:"Subject"`
	Conditions          *Conditions          `xml:"Conditions"`
	AuthnStatements     []AuthnStatement     `xml:"AuthnStatement"`
	AttributeStatements []AttributeStatement `xml:"AttributeStatement"`
}

// Attributes flattens every AttributeStatement into one list.
func (a *Assertion) Attributes() []Attribute {
	var out []Attribute
	for _, st := range a.AttributeStatements {
		out = append(out, st.Attributes...)
	}
	return out
}

// Subject is a saml:Subject.
type Subject struct {
	NameID        *NameID               `xml:"NameID"`
	EncryptedID   *struct{}             `xml:"EncryptedID"`
	Confirmations []SubjectConfirmation `xml:"SubjectConfirmation"`
}

// NameID keeps the text value plus a flag recording whether an XML comment
// appeared inside the element. Comments inside NameID are the vector for
// the classic canonicalization-truncation attack (a signed
// "user@example.test<!---->.attacker.test" verifying as "user@example.test"
// on some stacks), so the linter treats them as an error. Decoding needs a
// custom unmarshaller because encoding/xml silently drops comments.
type NameID struct {
	Value      string
	Format     string
	HasComment bool
}

// SubjectConfirmation is a saml:SubjectConfirmation with its Data inlined.
type SubjectConfirmation struct {
	Method string                   `xml:"Method,attr"`
	Data   *SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

// SubjectConfirmationData carries the bearer-check fields.
type SubjectConfirmationData struct {
	Recipient    string `xml:"Recipient,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	NotBefore    string `xml:"NotBefore,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
	Address      string `xml:"Address,attr"`
}

// Conditions is a saml:Conditions element.
type Conditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`

	AudienceRestrictions []AudienceRestriction `xml:"AudienceRestriction"`
	OneTimeUse           *struct{}             `xml:"OneTimeUse"`
	ProxyRestriction     *struct{}             `xml:"ProxyRestriction"`
}

// Audiences flattens all restrictions into a single audience list.
func (c *Conditions) Audiences() []string {
	var out []string
	for _, r := range c.AudienceRestrictions {
		out = append(out, r.Audiences...)
	}
	return out
}

// AudienceRestriction lists allowed relying parties.
type AudienceRestriction struct {
	Audiences []string `xml:"Audience"`
}

// AuthnStatement is a saml:AuthnStatement.
type AuthnStatement struct {
	AuthnInstant        string `xml:"AuthnInstant,attr"`
	SessionIndex        string `xml:"SessionIndex,attr"`
	SessionNotOnOrAfter string `xml:"SessionNotOnOrAfter,attr"`
	ContextClassRef     string `xml:"AuthnContext>AuthnContextClassRef"`
}

// AttributeStatement is a saml:AttributeStatement.
type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute is a saml:Attribute with all its values.
type Attribute struct {
	Name         string   `xml:"Name,attr"`
	FriendlyName string   `xml:"FriendlyName,attr"`
	NameFormat   string   `xml:"NameFormat,attr"`
	Values       []string `xml:"AttributeValue"`
}

// Signature captures the XML-DSig facts samlpeek reports on: which element
// it covers, the algorithms, and the embedded certificates. Verification is
// deliberately not attempted. Unmarshalling is custom (see parse.go) so the
// exported shape stays flat and lint-friendly.
type Signature struct {
	CanonicalizationAlg string
	SignatureAlg        string
	DigestAlg           string
	ReferenceURI        string
	Certificates        []string // base64 DER, whitespace preserved as-is
}

// AuthnRequest is a samlp:AuthnRequest.
type AuthnRequest struct {
	ID              string `xml:"ID,attr"`
	Version         string `xml:"Version,attr"`
	IssueInstant    string `xml:"IssueInstant,attr"`
	Destination     string `xml:"Destination,attr"`
	ACSURL          string `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding string `xml:"ProtocolBinding,attr"`
	ForceAuthn      string `xml:"ForceAuthn,attr"`
	IsPassive       string `xml:"IsPassive,attr"`

	Issuer       string     `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	NameIDPolicy *struct {
		Format      string `xml:"Format,attr"`
		AllowCreate string `xml:"AllowCreate,attr"`
	} `xml:"NameIDPolicy"`
	RequestedAuthnContext *struct {
		Comparison string   `xml:"Comparison,attr"`
		ClassRefs  []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	} `xml:"RequestedAuthnContext"`
}

// LogoutRequest is a samlp:LogoutRequest.
type LogoutRequest struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Destination  string `xml:"Destination,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`

	Issuer       string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       *NameID  `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex []string `xml:"SessionIndex"`
}

// LogoutResponse is a samlp:LogoutResponse.
type LogoutResponse struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Destination  string `xml:"Destination,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Issuer string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status Status `xml:"Status"`
}

// EntityDescriptor is an md:EntityDescriptor (IdP and/or SP metadata).
type EntityDescriptor struct {
	EntityID      string `xml:"entityID,attr"`
	ValidUntil    string `xml:"validUntil,attr"`
	CacheDuration string `xml:"cacheDuration,attr"`

	IDPSSO *IDPSSODescriptor `xml:"IDPSSODescriptor"`
	SPSSO  *SPSSODescriptor  `xml:"SPSSODescriptor"`
}

// IDPSSODescriptor describes an identity provider role.
type IDPSSODescriptor struct {
	WantAuthnRequestsSigned string `xml:"WantAuthnRequestsSigned,attr"`

	KeyDescriptors []KeyDescriptor `xml:"KeyDescriptor"`
	NameIDFormats  []string        `xml:"NameIDFormat"`
	SSOServices    []Endpoint      `xml:"SingleSignOnService"`
	SLOServices    []Endpoint      `xml:"SingleLogoutService"`
}

// SPSSODescriptor describes a service provider role.
type SPSSODescriptor struct {
	AuthnRequestsSigned  string `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned string `xml:"WantAssertionsSigned,attr"`

	KeyDescriptors []KeyDescriptor   `xml:"KeyDescriptor"`
	NameIDFormats  []string          `xml:"NameIDFormat"`
	ACS            []IndexedEndpoint `xml:"AssertionConsumerService"`
	SLOServices    []Endpoint        `xml:"SingleLogoutService"`
}

// KeyDescriptor is an md:KeyDescriptor; Use is "signing", "encryption",
// or empty (meaning both).
type KeyDescriptor struct {
	Use          string   `xml:"use,attr"`
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

// Endpoint is a Binding+Location pair.
type Endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// IndexedEndpoint is an endpoint with an index and default marker (ACS).
type IndexedEndpoint struct {
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
	Index     string `xml:"index,attr"`
	IsDefault string `xml:"isDefault,attr"`
}

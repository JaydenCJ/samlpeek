package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// XML namespaces samlpeek understands at the root.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// Parse decodes a SAML XML document into the model. It detects the root
// element (namespace + local name) and dispatches to the matching type, so
// callers never have to announce what they pasted.
func Parse(raw []byte) (*Document, error) {
	root, err := rootElement(raw)
	if err != nil {
		return nil, err
	}

	doc := &Document{HasDOCTYPE: hasDOCTYPE(raw)}
	switch {
	case root.Name.Space == nsProtocol && root.Name.Local == "Response":
		doc.Kind = KindResponse
		doc.Response = &Response{}
		err = xml.Unmarshal(raw, doc.Response)
	case root.Name.Space == nsProtocol && root.Name.Local == "AuthnRequest":
		doc.Kind = KindAuthnRequest
		doc.AuthnRequest = &AuthnRequest{}
		err = xml.Unmarshal(raw, doc.AuthnRequest)
	case root.Name.Space == nsProtocol && root.Name.Local == "LogoutRequest":
		doc.Kind = KindLogoutRequest
		doc.LogoutRequest = &LogoutRequest{}
		err = xml.Unmarshal(raw, doc.LogoutRequest)
	case root.Name.Space == nsProtocol && root.Name.Local == "LogoutResponse":
		doc.Kind = KindLogoutResponse
		doc.LogoutResponse = &LogoutResponse{}
		err = xml.Unmarshal(raw, doc.LogoutResponse)
	case root.Name.Space == nsAssertion && root.Name.Local == "Assertion":
		doc.Kind = KindAssertion
		doc.Assertion = &Assertion{}
		err = xml.Unmarshal(raw, doc.Assertion)
	case root.Name.Space == nsMetadata && root.Name.Local == "EntityDescriptor":
		doc.Kind = KindEntityDescriptor
		doc.Entity = &EntityDescriptor{}
		err = xml.Unmarshal(raw, doc.Entity)
	case root.Name.Space == nsMetadata && root.Name.Local == "EntitiesDescriptor":
		doc.Kind = KindEntitiesDescriptor
		var group struct {
			Entities []EntityDescriptor `xml:"EntityDescriptor"`
		}
		err = xml.Unmarshal(raw, &group)
		doc.Entities = group.Entities
	default:
		return nil, fmt.Errorf("unrecognized root element <%s> in namespace %q — not a SAML 2.0 message or metadata document",
			root.Name.Local, root.Name.Space)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed %s: %v", doc.Kind, err)
	}
	return doc, nil
}

// rootElement scans for the first StartElement without unmarshalling.
func rootElement(raw []byte) (xml.StartElement, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, fmt.Errorf("not well-formed XML: %v", err)
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start, nil
		}
	}
}

// hasDOCTYPE reports whether the raw bytes contain a DTD declaration.
// SAML processors must reject DTDs (XXE / entity-expansion vector), so the
// linter flags any document that carries one.
func hasDOCTYPE(raw []byte) bool {
	return bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE"))
}

// UnmarshalXML decodes a NameID while watching the token stream for XML
// comments. encoding/xml drops comments silently, which is exactly the
// behavior the truncation attack exploits — so we look for them ourselves.
func (n *NameID) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, a := range start.Attr {
		if a.Name.Local == "Format" {
			n.Format = a.Value
		}
	}
	var text strings.Builder
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 {
				text.Write(t)
			}
		case xml.Comment:
			n.HasComment = true
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				n.Value = strings.TrimSpace(text.String())
				return nil
			}
			depth--
		}
	}
}

// signatureXML mirrors the literal ds:Signature layout for decoding.
type signatureXML struct {
	SignedInfo struct {
		CanonicalizationMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"CanonicalizationMethod"`
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			URI          string `xml:"URI,attr"`
			DigestMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"DigestMethod"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
	KeyInfo struct {
		Certificates []string `xml:"X509Data>X509Certificate"`
	} `xml:"KeyInfo"`
}

// UnmarshalXML flattens the deep XML-DSig structure into Signature.
func (s *Signature) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var raw signatureXML
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	s.CanonicalizationAlg = raw.SignedInfo.CanonicalizationMethod.Algorithm
	s.SignatureAlg = raw.SignedInfo.SignatureMethod.Algorithm
	s.DigestAlg = raw.SignedInfo.Reference.DigestMethod.Algorithm
	s.ReferenceURI = raw.SignedInfo.Reference.URI
	s.Certificates = raw.KeyInfo.Certificates
	return nil
}

// AlgorithmName maps the common XML-DSig algorithm URIs to short names;
// unknown URIs pass through unchanged so nothing is ever hidden.
func AlgorithmName(uri string) string {
	if short, ok := algorithmNames[uri]; ok {
		return short
	}
	return uri
}

var algorithmNames = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          "rsa-sha1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   "rsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   "rsa-sha384",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   "rsa-sha512",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ecdsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ecdsa-sha384",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ecdsa-sha512",
	"http://www.w3.org/2000/09/xmldsig#sha1":              "sha1",
	"http://www.w3.org/2001/04/xmlenc#sha256":             "sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384":       "sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512":             "sha512",
	"http://www.w3.org/2001/10/xml-exc-c14n#":             "exclusive-c14n",
	"http://www.w3.org/2001/10/xml-exc-c14n#WithComments": "exclusive-c14n-with-comments",
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":     "inclusive-c14n",
	"http://www.w3.org/2006/12/xml-c14n11":                "c14n-1.1",
}

// NameIDFormatName shortens the well-known urn:…:nameid-format URIs.
func NameIDFormatName(uri string) string {
	const prefix11 = "urn:oasis:names:tc:SAML:1.1:nameid-format:"
	const prefix20 = "urn:oasis:names:tc:SAML:2.0:nameid-format:"
	if strings.HasPrefix(uri, prefix11) {
		return strings.TrimPrefix(uri, prefix11)
	}
	if strings.HasPrefix(uri, prefix20) {
		return strings.TrimPrefix(uri, prefix20)
	}
	if uri == "" {
		return "unspecified (no Format attribute)"
	}
	return uri
}

// BindingName shortens the urn:…:bindings URIs used in metadata endpoints.
func BindingName(uri string) string {
	const prefix = "urn:oasis:names:tc:SAML:2.0:bindings:"
	if strings.HasPrefix(uri, prefix) {
		return strings.TrimPrefix(uri, prefix)
	}
	return uri
}

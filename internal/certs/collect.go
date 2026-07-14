package certs

import (
	"fmt"

	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// Located is a certificate blob plus where in the document it was found.
type Located struct {
	Where string // e.g. "Assertion signature", "IdP signing KeyDescriptor"
	B64   string
}

// Collect walks a parsed document and returns every embedded certificate
// in document order, labelled by location.
func Collect(doc *saml.Document) []Located {
	var out []Located
	addSig := func(sig *saml.Signature, where string) {
		if sig == nil {
			return
		}
		for _, c := range sig.Certificates {
			out = append(out, Located{where, c})
		}
	}
	addEntity := func(e *saml.EntityDescriptor) {
		roles := []struct {
			name string
			kds  []saml.KeyDescriptor
		}{}
		if e.IDPSSO != nil {
			roles = append(roles, struct {
				name string
				kds  []saml.KeyDescriptor
			}{"IdP", e.IDPSSO.KeyDescriptors})
		}
		if e.SPSSO != nil {
			roles = append(roles, struct {
				name string
				kds  []saml.KeyDescriptor
			}{"SP", e.SPSSO.KeyDescriptors})
		}
		for _, role := range roles {
			for _, kd := range role.kds {
				use := kd.Use
				if use == "" {
					use = "signing+encryption"
				}
				for _, c := range kd.Certificates {
					out = append(out, Located{fmt.Sprintf("%s %s KeyDescriptor", role.name, use), c})
				}
			}
		}
	}

	switch doc.Kind {
	case saml.KindResponse:
		addSig(doc.Response.Signature, "Response signature")
		for i := range doc.Response.Assertions {
			addSig(doc.Response.Assertions[i].Signature, "Assertion signature")
		}
	case saml.KindAssertion:
		addSig(doc.Assertion.Signature, "Assertion signature")
	case saml.KindAuthnRequest:
		addSig(doc.AuthnRequest.Signature, "AuthnRequest signature")
	case saml.KindEntityDescriptor:
		addEntity(doc.Entity)
	case saml.KindEntitiesDescriptor:
		for i := range doc.Entities {
			addEntity(&doc.Entities[i])
		}
	}
	return out
}

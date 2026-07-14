package saml

import "strings"

// StatusSuccess is the top-level success code.
const StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// statusMeanings translates the registered status codes into the plain
// sentence an integrator actually needs. Sources: SAML 2.0 Core §3.2.2.2.
var statusMeanings = map[string]string{
	"urn:oasis:names:tc:SAML:2.0:status:Success":                  "the request succeeded",
	"urn:oasis:names:tc:SAML:2.0:status:Requester":                "the IdP blames the request (SP side): check issuer, ACS URL, NameID policy, and signing requirements",
	"urn:oasis:names:tc:SAML:2.0:status:Responder":                "the IdP failed on its own side: check IdP logs, user assignment, and attribute mappings",
	"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch":          "the IdP could not handle the SAML version in the request",
	"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed":              "the user failed to authenticate at the IdP (wrong credentials, cancelled, or MFA denied)",
	"urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue":   "a requested attribute name or value was invalid",
	"urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy":      "the IdP cannot issue the NameID format the SP asked for — align NameIDPolicy with the IdP's supported formats",
	"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext":           "the IdP cannot satisfy the requested authentication context (e.g. MFA class it does not support)",
	"urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP":           "no identity provider was available to service the request",
	"urn:oasis:names:tc:SAML:2.0:status:NoPassive":                "the request demanded IsPassive but the user needed interaction — the user has no live IdP session",
	"urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP":           "none of the supported identity providers could be used",
	"urn:oasis:names:tc:SAML:2.0:status:PartialLogout":            "logout succeeded only for some session participants",
	"urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded":       "the proxy count was exceeded while relaying the request",
	"urn:oasis:names:tc:SAML:2.0:status:RequestDenied":            "the IdP refused the request outright — often an unassigned user or a disabled application",
	"urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported":       "the IdP does not support this kind of request",
	"urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated": "the request used a deprecated SAML version",
	"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh":    "the request's SAML version is newer than the IdP supports",
	"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow":     "the request's SAML version is older than the IdP supports",
	"urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized":    "the IdP did not recognize the requested resource",
	"urn:oasis:names:tc:SAML:2.0:status:TooManyResponses":         "the response would contain more elements than the IdP can return",
	"urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile":       "the attribute profile in the request is unknown to the IdP",
	"urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal":         "the IdP does not know the principal named in the request — the user likely does not exist there",
	"urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding":       "the IdP cannot respond over the requested protocol binding",
}

// StatusMeaning explains a status code URI; unknown codes get a fallback.
func StatusMeaning(uri string) string {
	if m, ok := statusMeanings[uri]; ok {
		return m
	}
	return "unregistered status code — consult the IdP's documentation"
}

// ShortStatus trims the long URN prefix for display ("Success",
// "Requester", "AuthnFailed", …).
func ShortStatus(uri string) string {
	const prefix = "urn:oasis:names:tc:SAML:2.0:status:"
	if strings.HasPrefix(uri, prefix) {
		return strings.TrimPrefix(uri, prefix)
	}
	if uri == "" {
		return "(missing)"
	}
	return uri
}

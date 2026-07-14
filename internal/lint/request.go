package lint

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// checkAuthnRequest lints a samlp:AuthnRequest.
func checkAuthnRequest(r *saml.AuthnRequest, opts Options) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	versionCheck(r.Version, "AuthnRequest", add)
	checkTime(r.IssueInstant, "AuthnRequest IssueInstant", add)
	if r.Issuer == "" {
		add(Finding{Error, "missing-issuer", "AuthnRequest has no Issuer; the IdP cannot tell which SP is asking"})
	}
	if r.ID == "" {
		add(Finding{Error, "missing-id", "AuthnRequest has no ID; the SP cannot correlate the response's InResponseTo"})
	}
	if opts.Destination != "" && r.Destination != opts.Destination {
		add(Finding{Error, "destination-mismatch",
			fmt.Sprintf("AuthnRequest Destination is %q but you expected %q", orMissing(r.Destination), opts.Destination)})
	}
	if strings.EqualFold(r.ForceAuthn, "true") && strings.EqualFold(r.IsPassive, "true") {
		add(Finding{Error, "forceauthn-and-ispassive",
			"AuthnRequest sets both ForceAuthn and IsPassive to true; the IdP must re-authenticate without interaction, which is impossible"})
	}
	if r.ACSURL == "" {
		add(Finding{Info, "no-acs-url", "AuthnRequest has no AssertionConsumerServiceURL; the IdP will fall back to the default ACS in the SP's registered metadata"})
	} else if strings.HasPrefix(r.ACSURL, "http://") && !strings.HasPrefix(r.ACSURL, "http://127.0.0.1") && !strings.HasPrefix(r.ACSURL, "http://localhost") {
		add(Finding{Warn, "insecure-endpoint", fmt.Sprintf("AssertionConsumerServiceURL %s uses plaintext http://", r.ACSURL)})
	}
	signatureAlgorithms(r.Signature, "AuthnRequest", add)
	signatureCerts(r.Signature, "AuthnRequest", opts, add)
	return f
}

// checkLogoutRequest lints a samlp:LogoutRequest.
func checkLogoutRequest(r *saml.LogoutRequest, opts Options) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	versionCheck(r.Version, "LogoutRequest", add)
	checkTime(r.IssueInstant, "LogoutRequest IssueInstant", add)
	if r.Issuer == "" {
		add(Finding{Error, "missing-issuer", "LogoutRequest has no Issuer"})
	}
	if r.NameID == nil {
		add(Finding{Error, "missing-nameid", "LogoutRequest has no NameID (or it is encrypted in a form samlpeek cannot read); the IdP cannot tell whose session to end"})
	} else if r.NameID.HasComment {
		add(Finding{Error, "nameid-comment",
			fmt.Sprintf("NameID %q contains an XML comment; reject this message (comment-truncation attack shape)", r.NameID.Value)})
	}
	if t, ok := checkTime(r.NotOnOrAfter, "LogoutRequest NotOnOrAfter", add); ok && !opts.Now.IsZero() && !opts.Now.Before(t.Add(opts.Skew)) {
		add(Finding{Error, "logout-request-expired",
			fmt.Sprintf("LogoutRequest NotOnOrAfter %s is past; the IdP will discard it", r.NotOnOrAfter)})
	}
	if len(r.SessionIndex) == 0 {
		add(Finding{Info, "no-session-index", "LogoutRequest names no SessionIndex; the IdP will terminate every session for this principal"})
	}
	return f
}

// checkLogoutResponse lints a samlp:LogoutResponse.
func checkLogoutResponse(r *saml.LogoutResponse) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	versionCheck(r.Version, "LogoutResponse", add)
	checkTime(r.IssueInstant, "LogoutResponse IssueInstant", add)
	code := r.Status.Code.Value
	if code == "" {
		add(Finding{Error, "status-missing", "LogoutResponse has no StatusCode"})
	} else if code != saml.StatusSuccess {
		add(Finding{Error, "status-not-success",
			fmt.Sprintf("LogoutResponse status is %s — %s", saml.ShortStatus(code), saml.StatusMeaning(code))})
	}
	if r.InResponseTo == "" {
		add(Finding{Warn, "unsolicited-logout-response", "LogoutResponse has no InResponseTo; it does not answer any request the SP sent"})
	}
	return f
}

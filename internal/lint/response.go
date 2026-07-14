package lint

import (
	"fmt"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// checkResponse lints a samlp:Response and every assertion inside it.
func checkResponse(r *saml.Response, opts Options) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	versionCheck(r.Version, "Response", add)
	checkTime(r.IssueInstant, "Response IssueInstant", add)

	// Status: anything but Success means the login already failed at the
	// IdP; explain the code instead of making the user search for it.
	code := r.Status.Code.Value
	if code == "" {
		add(Finding{Error, "status-missing", "Response has no StatusCode; this is not a valid SAML response"})
	} else if code != saml.StatusSuccess {
		msg := fmt.Sprintf("Status is %s — %s", saml.ShortStatus(code), saml.StatusMeaning(code))
		if r.Status.Code.Sub != nil {
			sub := r.Status.Code.Sub.Value
			msg = fmt.Sprintf("Status is %s / %s — %s", saml.ShortStatus(code), saml.ShortStatus(sub), saml.StatusMeaning(sub))
		}
		if r.Status.Message != "" {
			msg += fmt.Sprintf(" (IdP says: %q)", r.Status.Message)
		}
		add(Finding{Error, "status-not-success", msg})
	}

	if opts.Destination != "" && r.Destination != opts.Destination {
		add(Finding{Error, "destination-mismatch",
			fmt.Sprintf("Response Destination is %q but you expected %q; the SP will drop this response", orMissing(r.Destination), opts.Destination)})
	}

	// Assertion presence.
	encrypted := len(r.EncryptedAssertions)
	switch {
	case len(r.Assertions) == 0 && encrypted == 0 && code == saml.StatusSuccess:
		add(Finding{Error, "no-assertion", "Response reports Success but carries no Assertion — the SP has nothing to log the user in with"})
	case encrypted > 0:
		add(Finding{Info, "encrypted-assertion",
			fmt.Sprintf("%s present; samlpeek cannot inspect encrypted assertions without the SP private key", countNoun(encrypted, "EncryptedAssertion element"))})
	}
	if len(r.Assertions) > 1 {
		add(Finding{Warn, "multiple-assertions",
			fmt.Sprintf("Response carries %d assertions; most SPs process only the first and some are confused by extras", len(r.Assertions))})
	}

	// Signature coverage: at least one of Response/Assertion must be
	// signed for the SP to trust anything in the message.
	assertionSigned := false
	for i := range r.Assertions {
		if r.Assertions[i].Signature != nil {
			assertionSigned = true
		}
	}
	if r.Signature == nil && len(r.Assertions) > 0 {
		if assertionSigned {
			add(Finding{Info, "response-not-signed", "Response element itself is unsigned (the assertion is signed, which most SPs accept)"})
		} else {
			add(Finding{Error, "nothing-signed", "neither the Response nor any Assertion is signed; no SP should accept this"})
		}
	}
	signatureAlgorithms(r.Signature, "Response", add)
	signatureCerts(r.Signature, "Response", opts, add)

	for i := range r.Assertions {
		f = append(f, checkAssertion(&r.Assertions[i], opts, true)...)
	}
	return f
}

// checkAssertion lints one assertion. insideResponse suppresses the
// signature-coverage rule that checkResponse already handles.
func checkAssertion(a *saml.Assertion, opts Options, insideResponse bool) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	versionCheck(a.Version, "Assertion", add)
	checkTime(a.IssueInstant, "Assertion IssueInstant", add)
	if a.Issuer == "" {
		add(Finding{Error, "missing-issuer", "Assertion has no Issuer; SPs match assertions to IdP configuration by this value"})
	}
	if !insideResponse && a.Signature == nil {
		add(Finding{Error, "nothing-signed", "bare Assertion is unsigned; no SP should accept this"})
	}
	signatureAlgorithms(a.Signature, "Assertion", add)
	signatureCerts(a.Signature, "Assertion", opts, add)

	checkSubject(a.Subject, opts, add)
	checkConditions(a.Conditions, opts, add)

	for _, st := range a.AuthnStatements {
		checkTime(st.AuthnInstant, "AuthnStatement AuthnInstant", add)
		if t, ok := checkTime(st.SessionNotOnOrAfter, "SessionNotOnOrAfter", add); ok && !opts.Now.IsZero() {
			if !opts.Now.Before(t.Add(opts.Skew)) {
				add(Finding{Warn, "session-expired",
					fmt.Sprintf("SessionNotOnOrAfter %s is already past; the IdP session this assertion describes has ended", st.SessionNotOnOrAfter)})
			}
		}
	}
	return f
}

// checkSubject lints NameID and bearer confirmations.
func checkSubject(s *saml.Subject, opts Options, add func(Finding)) {
	if s == nil {
		add(Finding{Warn, "missing-subject", "Assertion has no Subject; almost every SP requires one to identify the user"})
		return
	}
	switch {
	case s.NameID == nil && s.EncryptedID != nil:
		add(Finding{Info, "encrypted-nameid", "Subject uses EncryptedID; samlpeek cannot inspect it without the SP private key"})
	case s.NameID == nil:
		add(Finding{Warn, "missing-nameid", "Subject has no NameID; SPs that key users on NameID will fail this login"})
	default:
		if s.NameID.HasComment {
			add(Finding{Error, "nameid-comment",
				fmt.Sprintf("NameID %q contains an XML comment; comment-truncation bugs in several SAML stacks let attackers impersonate other users this way — reject this message", s.NameID.Value)})
		}
		if s.NameID.Value == "" {
			add(Finding{Warn, "empty-nameid", "NameID element is present but empty"})
		}
	}

	bearer := false
	for _, c := range s.Confirmations {
		if c.Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			bearer = true
			checkBearerData(c.Data, opts, add)
		}
	}
	if len(s.Confirmations) > 0 && !bearer {
		add(Finding{Info, "no-bearer-confirmation", "no bearer SubjectConfirmation present; Web Browser SSO requires the bearer method"})
	}
}

// checkBearerData lints SubjectConfirmationData for the bearer method,
// where SAML profiles require Recipient and NotOnOrAfter.
func checkBearerData(d *saml.SubjectConfirmationData, opts Options, add func(Finding)) {
	if d == nil {
		add(Finding{Warn, "bearer-no-data", "bearer SubjectConfirmation has no SubjectConfirmationData; profiles require Recipient and NotOnOrAfter here"})
		return
	}
	if d.Recipient == "" {
		add(Finding{Warn, "bearer-no-recipient", "bearer SubjectConfirmationData has no Recipient; the SP cannot verify the assertion was addressed to its ACS URL"})
	} else if opts.Recipient != "" && d.Recipient != opts.Recipient {
		add(Finding{Error, "recipient-mismatch",
			fmt.Sprintf("bearer Recipient is %q but you expected %q; the SP will reject this assertion", d.Recipient, opts.Recipient)})
	}
	if d.NotOnOrAfter == "" {
		add(Finding{Warn, "bearer-no-expiry", "bearer SubjectConfirmationData has no NotOnOrAfter; the assertion is replayable forever"})
	} else if t, ok := checkTime(d.NotOnOrAfter, "bearer NotOnOrAfter", add); ok && !opts.Now.IsZero() {
		if !opts.Now.Before(t.Add(opts.Skew)) {
			add(Finding{Error, "bearer-expired",
				fmt.Sprintf("bearer NotOnOrAfter %s is %s in the past; the SP will reject this assertion", d.NotOnOrAfter, saml.FormatDuration(opts.Now.Sub(t)))})
		}
	}
}

// checkConditions lints the Conditions window and audience restriction.
func checkConditions(c *saml.Conditions, opts Options, add func(Finding)) {
	if c == nil {
		add(Finding{Warn, "no-conditions", "Assertion has no Conditions element; there is no validity window and no audience restriction"})
		return
	}

	nb, nbOK := checkTime(c.NotBefore, "Conditions NotBefore", add)
	na, naOK := checkTime(c.NotOnOrAfter, "Conditions NotOnOrAfter", add)
	if !opts.Now.IsZero() {
		if nbOK && opts.Now.Before(nb.Add(-opts.Skew)) {
			add(Finding{Error, "assertion-not-yet-valid",
				fmt.Sprintf("Conditions NotBefore %s is %s in the future; check for clock skew between IdP and SP", c.NotBefore, saml.FormatDuration(nb.Sub(opts.Now)))})
		}
		if naOK && !opts.Now.Before(na.Add(opts.Skew)) {
			add(Finding{Error, "assertion-expired",
				fmt.Sprintf("Conditions NotOnOrAfter %s is %s in the past; the assertion is dead — re-test with a fresh login", c.NotOnOrAfter, saml.FormatDuration(opts.Now.Sub(na)))})
		}
	}
	if nbOK && naOK {
		if window := na.Sub(nb); window > 24*time.Hour {
			add(Finding{Warn, "long-validity-window",
				fmt.Sprintf("Conditions window is %s; windows beyond a few minutes widen the replay surface", saml.FormatDuration(window))})
		} else if window <= 0 {
			add(Finding{Error, "inverted-validity-window",
				fmt.Sprintf("Conditions NotBefore %s is not before NotOnOrAfter %s; the assertion can never be valid", c.NotBefore, c.NotOnOrAfter)})
		}
	}

	audiences := c.Audiences()
	switch {
	case len(c.AudienceRestrictions) == 0:
		add(Finding{Warn, "no-audience-restriction", "Conditions has no AudienceRestriction; the assertion can be replayed to any SP that trusts this IdP"})
	case opts.Audience != "" && !contains(audiences, opts.Audience):
		add(Finding{Error, "audience-mismatch",
			fmt.Sprintf("AudienceRestriction %s does not include your entity ID %q; fix the SP entity ID configured at the IdP", quoteList(audiences), opts.Audience)})
	}
}

// orMissing renders empty attribute values readably in messages.
func orMissing(s string) string {
	if s == "" {
		return "(missing)"
	}
	return s
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// quoteList renders a short list of values for a message.
func quoteList(list []string) string {
	if len(list) == 0 {
		return "(empty)"
	}
	out := ""
	for i, v := range list {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%q", v)
	}
	return out
}

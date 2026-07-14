// Package render turns parsed documents and lint findings into the two
// output surfaces samlpeek supports: aligned human-readable text and stable
// machine-readable JSON (schema_version 1).
package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/certs"
	"github.com/JaydenCJ/samlpeek/internal/decode"
	"github.com/JaydenCJ/samlpeek/internal/lint"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// labelWidth aligns the key column of explain output.
const labelWidth = 14

// kv prints one aligned "  key  value" line, skipping empty values so the
// output only shows what the message actually contains.
func kv(w io.Writer, key, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(w, "  %-*s %s\n", labelWidth, key, value)
}

// Explain writes the human summary for any document kind.
func Explain(w io.Writer, doc *saml.Document, dec *decode.Result, now time.Time) {
	fmt.Fprintf(w, "samlpeek — SAML %s", doc.Kind)
	if dec.Binding != "" {
		fmt.Fprintf(w, " (%s)", dec.Binding)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "decode: %s, %d bytes of XML\n", strings.Join(dec.Steps, " → "), len(dec.XML))
	if dec.RelayState != "" {
		fmt.Fprintf(w, "relay-state: %s\n", dec.RelayState)
	}
	if dec.SigAlg != "" {
		fmt.Fprintf(w, "query-signed: yes (SigAlg %s)\n", saml.AlgorithmName(dec.SigAlg))
	}

	switch doc.Kind {
	case saml.KindResponse:
		explainResponse(w, doc.Response, now)
	case saml.KindAssertion:
		fmt.Fprintln(w)
		explainAssertion(w, doc.Assertion, now)
	case saml.KindAuthnRequest:
		explainAuthnRequest(w, doc.AuthnRequest)
	case saml.KindLogoutRequest:
		explainLogoutRequest(w, doc.LogoutRequest)
	case saml.KindLogoutResponse:
		explainLogoutResponse(w, doc.LogoutResponse)
	case saml.KindEntityDescriptor:
		explainEntity(w, doc.Entity, now)
	case saml.KindEntitiesDescriptor:
		fmt.Fprintf(w, "\n%d entities in EntitiesDescriptor\n", len(doc.Entities))
		for i := range doc.Entities {
			explainEntity(w, &doc.Entities[i], now)
		}
	}
}

// explainResponse prints the response header block and its assertions.
func explainResponse(w io.Writer, r *saml.Response, now time.Time) {
	fmt.Fprintln(w, "\nResponse")
	kv(w, "ID", r.ID)
	kv(w, "IssueInstant", r.IssueInstant)
	kv(w, "Issuer", r.Issuer)
	kv(w, "Destination", r.Destination)
	kv(w, "InResponseTo", r.InResponseTo)
	kv(w, "Status", statusLine(r.Status))
	kv(w, "Signed", signatureLine(r.Signature, now))

	for i := range r.Assertions {
		fmt.Fprintln(w)
		explainAssertion(w, &r.Assertions[i], now)
	}
	if n := len(r.EncryptedAssertions); n > 0 {
		fmt.Fprintf(w, "\n%s — supply the SP private key to your SAML stack for inspection\n", countNoun(n, "EncryptedAssertion element"))
	}
}

// statusLine renders "Success — the request succeeded" style summaries.
func statusLine(s saml.Status) string {
	code := s.Code.Value
	if code == "" {
		return "(missing)"
	}
	line := saml.ShortStatus(code)
	if s.Code.Sub != nil {
		line += " / " + saml.ShortStatus(s.Code.Sub.Value)
		line += " — " + saml.StatusMeaning(s.Code.Sub.Value)
	} else {
		line += " — " + saml.StatusMeaning(code)
	}
	if s.Message != "" {
		line += fmt.Sprintf(" (IdP says: %q)", s.Message)
	}
	return line
}

// signatureLine summarizes a signature, or reports its absence explicitly.
func signatureLine(sig *saml.Signature, now time.Time) string {
	if sig == nil {
		return "no"
	}
	line := fmt.Sprintf("yes (%s / %s)", saml.AlgorithmName(sig.SignatureAlg), saml.AlgorithmName(sig.DigestAlg))
	if len(sig.Certificates) > 0 {
		if info, err := certs.Parse(sig.Certificates[0]); err == nil {
			line += fmt.Sprintf(", cert %s expires %s", firstRDN(info.Subject), info.NotAfter.Format("2006-01-02"))
			if !now.IsZero() && info.Status(now) != "valid" {
				line += " [" + info.Status(now) + "]"
			}
		}
	}
	return line
}

// explainAssertion prints one assertion block.
func explainAssertion(w io.Writer, a *saml.Assertion, now time.Time) {
	fmt.Fprintf(w, "Assertion %s\n", a.ID)
	kv(w, "Issuer", a.Issuer)
	kv(w, "Signed", signatureLine(a.Signature, now))
	if s := a.Subject; s != nil {
		if s.NameID != nil {
			name := s.NameID.Value
			if s.NameID.HasComment {
				name += "  [!] contains an XML comment"
			}
			kv(w, "Subject", fmt.Sprintf("%s  [%s]", name, saml.NameIDFormatName(s.NameID.Format)))
		} else if s.EncryptedID != nil {
			kv(w, "Subject", "(EncryptedID — cannot inspect without the SP private key)")
		}
		for _, c := range s.Confirmations {
			if c.Data == nil {
				kv(w, "Confirmation", shortMethod(c.Method))
				continue
			}
			line := shortMethod(c.Method)
			if c.Data.Recipient != "" {
				line += " → " + c.Data.Recipient
			}
			if c.Data.NotOnOrAfter != "" {
				line += ", valid until " + c.Data.NotOnOrAfter
			}
			if c.Data.InResponseTo != "" {
				line += ", answers " + c.Data.InResponseTo
			}
			kv(w, "Confirmation", line)
		}
	}
	if c := a.Conditions; c != nil {
		window := fmt.Sprintf("%s → %s", orDash(c.NotBefore), orDash(c.NotOnOrAfter))
		if nb, err1 := saml.ParseTime(c.NotBefore); err1 == nil {
			if na, err2 := saml.ParseTime(c.NotOnOrAfter); err2 == nil {
				window += fmt.Sprintf("  (window %s)", saml.FormatDuration(na.Sub(nb)))
			}
		}
		kv(w, "Conditions", window)
		if audiences := c.Audiences(); len(audiences) > 0 {
			kv(w, "Audience", strings.Join(audiences, ", "))
		}
	}
	for _, st := range a.AuthnStatements {
		line := shortContext(st.ContextClassRef)
		if st.AuthnInstant != "" {
			line += " at " + st.AuthnInstant
		}
		if st.SessionIndex != "" {
			line += fmt.Sprintf("  (session %s)", st.SessionIndex)
		}
		kv(w, "AuthnContext", line)
	}
	if attrs := a.Attributes(); len(attrs) > 0 {
		fmt.Fprintf(w, "  Attributes (%d)\n", len(attrs))
		width := 0
		for _, at := range attrs {
			if len(at.Name) > width {
				width = len(at.Name)
			}
		}
		for _, at := range attrs {
			fmt.Fprintf(w, "    %-*s  %s\n", width, at.Name, strings.Join(at.Values, ", "))
		}
	}
}

// explainAuthnRequest prints an AuthnRequest summary.
func explainAuthnRequest(w io.Writer, r *saml.AuthnRequest) {
	fmt.Fprintln(w, "\nAuthnRequest")
	kv(w, "ID", r.ID)
	kv(w, "IssueInstant", r.IssueInstant)
	kv(w, "Issuer", r.Issuer)
	kv(w, "Destination", r.Destination)
	kv(w, "ACS URL", r.ACSURL)
	kv(w, "Binding", saml.BindingName(r.ProtocolBinding))
	if r.NameIDPolicy != nil {
		policy := saml.NameIDFormatName(r.NameIDPolicy.Format)
		if r.NameIDPolicy.AllowCreate != "" {
			policy += fmt.Sprintf("  (AllowCreate=%s)", r.NameIDPolicy.AllowCreate)
		}
		kv(w, "NameIDPolicy", policy)
	}
	if r.ForceAuthn != "" {
		kv(w, "ForceAuthn", r.ForceAuthn)
	}
	if r.IsPassive != "" {
		kv(w, "IsPassive", r.IsPassive)
	}
	if r.RequestedAuthnContext != nil {
		kv(w, "AuthnContext", strings.Join(shortContexts(r.RequestedAuthnContext.ClassRefs), ", "))
	}
	kv(w, "Signed", signatureLine(r.Signature, time.Time{}))
}

// explainLogoutRequest prints a LogoutRequest summary.
func explainLogoutRequest(w io.Writer, r *saml.LogoutRequest) {
	fmt.Fprintln(w, "\nLogoutRequest")
	kv(w, "ID", r.ID)
	kv(w, "IssueInstant", r.IssueInstant)
	kv(w, "Issuer", r.Issuer)
	kv(w, "Destination", r.Destination)
	if r.NameID != nil {
		kv(w, "NameID", fmt.Sprintf("%s  [%s]", r.NameID.Value, saml.NameIDFormatName(r.NameID.Format)))
	}
	kv(w, "SessionIndex", strings.Join(r.SessionIndex, ", "))
	kv(w, "NotOnOrAfter", r.NotOnOrAfter)
}

// explainLogoutResponse prints a LogoutResponse summary.
func explainLogoutResponse(w io.Writer, r *saml.LogoutResponse) {
	fmt.Fprintln(w, "\nLogoutResponse")
	kv(w, "ID", r.ID)
	kv(w, "IssueInstant", r.IssueInstant)
	kv(w, "Issuer", r.Issuer)
	kv(w, "InResponseTo", r.InResponseTo)
	kv(w, "Status", statusLine(r.Status))
}

// explainEntity prints one metadata entity with its roles and endpoints.
func explainEntity(w io.Writer, e *saml.EntityDescriptor, now time.Time) {
	fmt.Fprintln(w, "\nEntityDescriptor")
	kv(w, "EntityID", e.EntityID)
	kv(w, "ValidUntil", e.ValidUntil)
	kv(w, "CacheDuration", e.CacheDuration)

	if idp := e.IDPSSO; idp != nil {
		fmt.Fprintln(w, "  IdP role")
		for _, ep := range idp.SSOServices {
			fmt.Fprintf(w, "    SSO   %-14s %s\n", saml.BindingName(ep.Binding), ep.Location)
		}
		for _, ep := range idp.SLOServices {
			fmt.Fprintf(w, "    SLO   %-14s %s\n", saml.BindingName(ep.Binding), ep.Location)
		}
		printFormats(w, idp.NameIDFormats)
		printKeys(w, idp.KeyDescriptors, now)
	}
	if sp := e.SPSSO; sp != nil {
		fmt.Fprintln(w, "  SP role")
		for _, acs := range sp.ACS {
			marker := ""
			if strings.EqualFold(acs.IsDefault, "true") {
				marker = "  (default)"
			}
			fmt.Fprintf(w, "    ACS %s %-14s %s%s\n", orDash(acs.Index), saml.BindingName(acs.Binding), acs.Location, marker)
		}
		printFormats(w, sp.NameIDFormats)
		printKeys(w, sp.KeyDescriptors, now)
	}
}

// printFormats lists advertised NameID formats.
func printFormats(w io.Writer, formats []string) {
	for _, f := range formats {
		fmt.Fprintf(w, "    NameIDFormat  %s\n", saml.NameIDFormatName(f))
	}
}

// printKeys summarizes metadata certificates inline.
func printKeys(w io.Writer, kds []saml.KeyDescriptor, now time.Time) {
	for _, kd := range kds {
		use := kd.Use
		if use == "" {
			use = "signing+encryption"
		}
		for _, blob := range kd.Certificates {
			info, err := certs.Parse(blob)
			if err != nil {
				fmt.Fprintf(w, "    key   %-14s (unparseable certificate: %v)\n", use, err)
				continue
			}
			line := fmt.Sprintf("%s, %s, expires %s", firstRDN(info.Subject), info.Key, info.NotAfter.Format("2006-01-02"))
			if !now.IsZero() && info.Status(now) != "valid" {
				line += "  [" + info.Status(now) + "]"
			}
			fmt.Fprintf(w, "    key   %-14s %s\n", use, line)
		}
	}
}

// Lint writes findings as aligned text plus a PASS/FAIL summary line.
func Lint(w io.Writer, doc *saml.Document, findings []lint.Finding, opts lint.Options) {
	fmt.Fprintf(w, "samlpeek lint — SAML %s, evaluated at %s (skew %s)\n\n",
		doc.Kind, opts.Now.UTC().Format(time.RFC3339), saml.FormatDuration(opts.Skew))
	for _, f := range findings {
		fmt.Fprintf(w, "%-5s  %-28s %s\n", strings.ToUpper(f.Severity.String()), f.Rule, f.Message)
	}
	errors, warnings, infos := lint.Count(findings)
	if len(findings) > 0 {
		fmt.Fprintln(w)
	}
	verdict := "PASS"
	if errors > 0 {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "%s, %s, %d info — %s\n", countNoun(errors, "error"), countNoun(warnings, "warning"), infos, verdict)
}

// countNoun renders "1 error" / "3 errors" — no lazy "(s)" suffixes.
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// Certs writes the certificate listing.
func Certs(w io.Writer, located []certs.Located, now time.Time) {
	if len(located) == 0 {
		fmt.Fprintln(w, "no certificates found in this document")
		return
	}
	for i, lc := range located {
		info, err := certs.Parse(lc.B64)
		if err != nil {
			fmt.Fprintf(w, "%d. %s — unparseable: %v\n", i+1, lc.Where, err)
			continue
		}
		fmt.Fprintf(w, "%d. %s  (%s)\n", i+1, info.Subject, lc.Where)
		fmt.Fprintf(w, "   serial    %s\n", info.Serial)
		validity := fmt.Sprintf("%s → %s", info.NotBefore.Format("2006-01-02"), info.NotAfter.Format("2006-01-02"))
		if !now.IsZero() {
			switch info.Status(now) {
			case "valid":
				validity += fmt.Sprintf("  (%s, %d days left)", info.Status(now), info.DaysLeft(now))
			default:
				validity += fmt.Sprintf("  [%s]", info.Status(now))
			}
		}
		fmt.Fprintf(w, "   validity  %s\n", validity)
		fmt.Fprintf(w, "   key       %s (%s)%s\n", info.Key, info.SigAlg, selfSignedSuffix(info))
		fmt.Fprintf(w, "   sha256    %s\n", info.SHA256)
	}
}

func selfSignedSuffix(info *certs.Info) string {
	if info.SelfSigned {
		return ", self-signed"
	}
	return ""
}

// firstRDN trims a distinguished name to its first component (usually CN).
func firstRDN(dn string) string {
	if i := strings.IndexByte(dn, ','); i > 0 {
		return dn[:i]
	}
	return dn
}

// orDash renders empty strings as a dash in tabular contexts.
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// shortMethod trims the SubjectConfirmation method URN.
func shortMethod(uri string) string {
	const prefix = "urn:oasis:names:tc:SAML:2.0:cm:"
	if strings.HasPrefix(uri, prefix) {
		return strings.TrimPrefix(uri, prefix)
	}
	return uri
}

// shortContext trims the AuthnContext class URN.
func shortContext(uri string) string {
	const prefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:"
	if strings.HasPrefix(uri, prefix) {
		return strings.TrimPrefix(uri, prefix)
	}
	if uri == "" {
		return "(no AuthnContextClassRef)"
	}
	return uri
}

func shortContexts(uris []string) []string {
	out := make([]string, len(uris))
	for i, u := range uris {
		out[i] = shortContext(u)
	}
	return out
}

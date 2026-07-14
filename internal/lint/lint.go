// Package lint checks parsed SAML documents for the problems that actually
// break SSO logins: expired conditions, audience and recipient mismatches,
// missing signatures, weak algorithms, dead certificates, and a handful of
// known attack shapes (DTDs, comments inside NameID). Every rule has a
// stable kebab-case ID documented in docs/lint-rules.md.
package lint

import (
	"fmt"
	"sort"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// Severity orders findings; Error means "this login will (or should) fail".
type Severity int

const (
	Info Severity = iota
	Warn
	Error
)

// String renders the severity for text output and JSON.
func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// Finding is one lint result.
type Finding struct {
	Severity Severity
	Rule     string // stable kebab-case ID
	Message  string // what is wrong, with the offending values inline
}

// Options carries the evaluation context. Zero values disable the
// corresponding expectation checks (audience/recipient/destination).
type Options struct {
	Now         time.Time     // reference time for all validity checks
	Skew        time.Duration // allowed clock skew, applied on both sides
	Audience    string        // expected SP entity ID
	Recipient   string        // expected ACS URL (SubjectConfirmationData Recipient)
	Destination string        // expected Destination attribute
}

// Check dispatches on document kind and returns findings sorted by
// severity (errors first), then rule ID, then message — a deterministic
// order so output is diffable.
func Check(doc *saml.Document, opts Options) []Finding {
	var f []Finding
	if doc.HasDOCTYPE {
		f = append(f, Finding{Error, "doctype-present",
			"document contains a <!DOCTYPE> declaration; SAML forbids DTDs (XXE / entity-expansion vector) and hardened stacks will reject this message"})
	}

	switch doc.Kind {
	case saml.KindResponse:
		f = append(f, checkResponse(doc.Response, opts)...)
	case saml.KindAssertion:
		f = append(f, checkAssertion(doc.Assertion, opts, false)...)
	case saml.KindAuthnRequest:
		f = append(f, checkAuthnRequest(doc.AuthnRequest, opts)...)
	case saml.KindLogoutRequest:
		f = append(f, checkLogoutRequest(doc.LogoutRequest, opts)...)
	case saml.KindLogoutResponse:
		f = append(f, checkLogoutResponse(doc.LogoutResponse)...)
	case saml.KindEntityDescriptor:
		f = append(f, checkEntity(doc.Entity, opts)...)
	case saml.KindEntitiesDescriptor:
		for i := range doc.Entities {
			f = append(f, checkEntity(&doc.Entities[i], opts)...)
		}
	}

	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].Rule != f[j].Rule {
			return f[i].Rule < f[j].Rule
		}
		return f[i].Message < f[j].Message
	})
	return f
}

// Count tallies findings per severity.
func Count(findings []Finding) (errors, warnings, infos int) {
	for _, f := range findings {
		switch f.Severity {
		case Error:
			errors++
		case Warn:
			warnings++
		default:
			infos++
		}
	}
	return
}

// countNoun renders "1 day" / "3 days" — no lazy "(s)" suffixes.
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// checkTime evaluates one xs:dateTime attribute and returns (parsed, ok).
// Unparseable timestamps produce their own error finding via the callback.
func checkTime(value, where string, add func(Finding)) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	t, err := saml.ParseTime(value)
	if err != nil {
		add(Finding{Error, "bad-timestamp", fmt.Sprintf("%s %q is not a valid xs:dateTime", where, value)})
		return time.Time{}, false
	}
	if saml.IsNaive(value) {
		add(Finding{Warn, "naive-timestamp", fmt.Sprintf("%s %q has no timezone; SAML requires UTC (\"Z\") and peers will disagree on its meaning", where, value)})
	}
	return t, true
}

// versionCheck flags anything other than SAML 2.0.
func versionCheck(version, what string, add func(Finding)) {
	if version != "" && version != "2.0" {
		add(Finding{Error, "version-mismatch", fmt.Sprintf("%s declares Version=%q; samlpeek and virtually all SPs expect \"2.0\"", what, version)})
	}
}

// signatureAlgorithms flags SHA-1-family digests and signatures, which
// every current SAML profile deprecates.
func signatureAlgorithms(sig *saml.Signature, what string, add func(Finding)) {
	if sig == nil {
		return
	}
	if saml.AlgorithmName(sig.SignatureAlg) == "rsa-sha1" {
		add(Finding{Warn, "weak-signature-algorithm", fmt.Sprintf("%s is signed with rsa-sha1; SHA-1 signatures are deprecated — move the IdP to rsa-sha256", what)})
	}
	if saml.AlgorithmName(sig.DigestAlg) == "sha1" {
		add(Finding{Warn, "weak-digest-algorithm", fmt.Sprintf("%s digest uses sha1; move the IdP to sha256", what)})
	}
	if sig.ReferenceURI == "" {
		add(Finding{Warn, "signature-no-reference", fmt.Sprintf("%s signature has an empty Reference URI; the signature does not clearly bind to the element it lives in", what)})
	}
}

// signatureCerts lints the certificates embedded in a signature.
func signatureCerts(sig *saml.Signature, what string, opts Options, add func(Finding)) {
	if sig == nil {
		return
	}
	lintCertificates(sig.Certificates, what+" signature", opts, add)
}

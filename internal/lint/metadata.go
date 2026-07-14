package lint

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/samlpeek/internal/certs"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// certExpiryWarnDays is how far ahead metadata certificate expiry warns.
// 30 days matches the renewal window most IdP operators actually use.
const certExpiryWarnDays = 30

// checkEntity lints one EntityDescriptor (IdP and/or SP roles).
func checkEntity(e *saml.EntityDescriptor, opts Options) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	if e.EntityID == "" {
		add(Finding{Error, "missing-entity-id", "EntityDescriptor has no entityID; peers cannot reference this entity at all"})
	}
	if t, ok := checkTime(e.ValidUntil, "metadata validUntil", add); ok && !opts.Now.IsZero() && !opts.Now.Before(t) {
		add(Finding{Error, "metadata-expired",
			fmt.Sprintf("metadata validUntil %s is %s in the past; conforming peers must stop using this document", e.ValidUntil, saml.FormatDuration(opts.Now.Sub(t)))})
	}
	if e.IDPSSO == nil && e.SPSSO == nil {
		add(Finding{Warn, "no-sso-role",
			fmt.Sprintf("entity %q declares neither an IDPSSODescriptor nor an SPSSODescriptor; samlpeek has nothing to check", orMissing(e.EntityID))})
	}

	if idp := e.IDPSSO; idp != nil {
		lintKeyDescriptors(idp.KeyDescriptors, "IdP", opts, add)
		if len(idp.SSOServices) == 0 {
			add(Finding{Error, "no-sso-endpoint", "IDPSSODescriptor has no SingleSignOnService endpoint; SPs cannot start a login"})
		}
		for _, ep := range idp.SSOServices {
			lintEndpointURL(ep.Location, "SingleSignOnService", add)
		}
		for _, ep := range idp.SLOServices {
			lintEndpointURL(ep.Location, "SingleLogoutService", add)
		}
		if len(idp.NameIDFormats) == 0 {
			add(Finding{Info, "no-nameid-format", "IDPSSODescriptor advertises no NameIDFormat; SPs will have to guess"})
		}
	}

	if sp := e.SPSSO; sp != nil {
		lintKeyDescriptors(sp.KeyDescriptors, "SP", opts, add)
		if len(sp.ACS) == 0 {
			add(Finding{Error, "no-acs-endpoint", "SPSSODescriptor has no AssertionConsumerService; the IdP has nowhere to send responses"})
		}
		seen := map[string]bool{}
		for _, acs := range sp.ACS {
			lintEndpointURL(acs.Location, "AssertionConsumerService", add)
			if acs.Index != "" && seen[acs.Index] {
				add(Finding{Error, "duplicate-acs-index",
					fmt.Sprintf("two AssertionConsumerService entries share index %s; IdPs resolving by index will pick one arbitrarily", acs.Index)})
			}
			seen[acs.Index] = true
		}
		if strings.EqualFold(sp.WantAssertionsSigned, "false") {
			add(Finding{Warn, "unsigned-assertions-accepted", "SPSSODescriptor sets WantAssertionsSigned=\"false\"; the SP announces it will accept unsigned assertions"})
		}
	}
	return f
}

// lintKeyDescriptors checks that a role has a usable signing key and lints
// every embedded certificate.
func lintKeyDescriptors(kds []saml.KeyDescriptor, role string, opts Options, add func(Finding)) {
	signing := false
	for _, kd := range kds {
		if kd.Use == "signing" || kd.Use == "" {
			signing = true
		}
		use := kd.Use
		if use == "" {
			use = "unspecified-use"
		}
		lintCertificates(kd.Certificates, fmt.Sprintf("%s %s KeyDescriptor", role, use), opts, add)
	}
	if !signing {
		add(Finding{Warn, "no-signing-key",
			fmt.Sprintf("%s role advertises no signing certificate; peers cannot validate its signatures from this metadata", role)})
	}
}

// lintCertificates parses each base64 DER blob and applies expiry and
// key-strength rules. Shared by metadata and signature checks.
func lintCertificates(blobs []string, where string, opts Options, add func(Finding)) {
	for _, blob := range blobs {
		info, err := certs.Parse(blob)
		if err != nil {
			add(Finding{Error, "unparseable-certificate", fmt.Sprintf("%s contains a certificate that does not parse: %v", where, err)})
			continue
		}
		if info.WeakKey() {
			add(Finding{Warn, "weak-certificate-key", fmt.Sprintf("%s certificate %s uses %s; below the 2048-bit RSA baseline", where, info.Subject, info.Key)})
		}
		if opts.Now.IsZero() {
			continue
		}
		switch info.Status(opts.Now) {
		case "expired":
			add(Finding{Error, "certificate-expired",
				fmt.Sprintf("%s certificate %s expired %s (%s ago)", where, info.Subject, info.NotAfter.Format("2006-01-02"), saml.FormatDuration(opts.Now.Sub(info.NotAfter)))})
		case "not yet valid":
			add(Finding{Error, "certificate-not-yet-valid",
				fmt.Sprintf("%s certificate %s is not valid before %s", where, info.Subject, info.NotBefore.Format("2006-01-02"))})
		default:
			if days := info.DaysLeft(opts.Now); days <= certExpiryWarnDays {
				add(Finding{Warn, "certificate-expiring-soon",
					fmt.Sprintf("%s certificate %s expires in %s on %s; rotate it before logins start failing", where, info.Subject, countNoun(days, "day"), info.NotAfter.Format("2006-01-02"))})
			}
		}
	}
}

// lintEndpointURL flags plaintext-HTTP SAML endpoints; assertions carry
// credentials-equivalent material and must not transit cleartext.
// Loopback addresses are exempt (local development).
func lintEndpointURL(location, what string, add func(Finding)) {
	if location == "" {
		add(Finding{Warn, "endpoint-no-location", fmt.Sprintf("%s endpoint has an empty Location", what)})
		return
	}
	if strings.HasPrefix(location, "http://") &&
		!strings.HasPrefix(location, "http://127.0.0.1") &&
		!strings.HasPrefix(location, "http://localhost") {
		add(Finding{Warn, "insecure-endpoint", fmt.Sprintf("%s endpoint %s uses plaintext http://; SAML messages must travel over https", what, location)})
	}
}

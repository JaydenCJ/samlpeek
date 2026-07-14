// Package certs decodes the base64 X509Certificate blobs embedded in SAML
// signatures and metadata KeyDescriptors, and summarizes exactly the fields
// an SSO integrator needs: who it names, when it dies, and its fingerprint.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Info is a summarized certificate.
type Info struct {
	Subject    string // RFC 2253-ish subject string
	Issuer     string // issuer subject string
	NotBefore  time.Time
	NotAfter   time.Time
	Serial     string
	Key        string // e.g. "RSA-2048", "ECDSA P-256", "Ed25519"
	SigAlg     string // certificate's own signature algorithm
	SHA256     string // colon-separated fingerprint of the DER bytes
	SelfSigned bool
}

// Parse decodes one base64 DER blob as it appears inside an
// <ds:X509Certificate> element (whitespace-wrapped, no PEM armor).
func Parse(b64 string) (*Info, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, b64)
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("certificate is not valid base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate DER does not parse: %v", err)
	}

	sum := sha256.Sum256(der)
	return &Info{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		NotBefore:  cert.NotBefore.UTC(),
		NotAfter:   cert.NotAfter.UTC(),
		Serial:     cert.SerialNumber.String(),
		Key:        keyDescription(cert),
		SigAlg:     cert.SignatureAlgorithm.String(),
		SHA256:     fingerprint(sum[:]),
		SelfSigned: cert.Subject.String() == cert.Issuer.String(),
	}, nil
}

// Status classifies validity against a reference time.
func (i *Info) Status(now time.Time) string {
	switch {
	case now.Before(i.NotBefore):
		return "not yet valid"
	case now.After(i.NotAfter):
		return "expired"
	default:
		return "valid"
	}
}

// DaysLeft is the number of whole days from now until expiry (negative if
// already expired), for "expires in N days" style messages.
func (i *Info) DaysLeft(now time.Time) int {
	return int(i.NotAfter.Sub(now).Hours() / 24)
}

// keyDescription names the public-key algorithm and size.
func keyDescription(cert *x509.Certificate) string {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", key.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// WeakKey reports keys below current baseline strength (RSA < 2048 bits).
func (i *Info) WeakKey() bool {
	var bits int
	if _, err := fmt.Sscanf(i.Key, "RSA-%d", &bits); err == nil {
		return bits < 2048
	}
	return false
}

// fingerprint renders bytes as colon-separated uppercase hex pairs.
func fingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

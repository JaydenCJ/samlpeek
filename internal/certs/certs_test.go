// Tests for X.509 parsing against the two committed fixture certificates
// (real DER, pinned validity windows) — no crypto/rand, no wall clock.
package certs

import (
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/fixture"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// now is the pinned evaluation instant used across the suite.
var now = time.Date(2026, 7, 12, 9, 1, 0, 0, time.UTC)

func TestParseValidCertificateFields(t *testing.T) {
	info, err := Parse(fixture.CertValid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Subject, "CN=idp.example.test") {
		t.Errorf("subject = %q", info.Subject)
	}
	if info.Key != "RSA-2048" {
		t.Errorf("key = %q", info.Key)
	}
	if !info.SelfSigned {
		t.Error("fixture cert is self-signed")
	}
	if info.NotBefore.Year() != 2025 || info.NotAfter.Year() != 2035 {
		t.Errorf("validity = %v → %v", info.NotBefore, info.NotAfter)
	}
	if len(info.SHA256) != 95 { // 32 bytes as "AA:BB:…" = 32*2 + 31 colons
		t.Errorf("fingerprint length = %d: %q", len(info.SHA256), info.SHA256)
	}
}

func TestStatusAgainstPinnedNow(t *testing.T) {
	valid, _ := Parse(fixture.CertValid)
	expired, _ := Parse(fixture.CertExpired)
	if got := valid.Status(now); got != "valid" {
		t.Errorf("valid cert status = %q", got)
	}
	if got := expired.Status(now); got != "expired" {
		t.Errorf("expired cert status = %q", got)
	}
	before := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := valid.Status(before); got != "not yet valid" {
		t.Errorf("pre-validity status = %q", got)
	}
}

func TestDaysLeftPositiveAndNegative(t *testing.T) {
	valid, _ := Parse(fixture.CertValid)
	if d := valid.DaysLeft(now); d < 3000 || d > 3200 {
		t.Errorf("days left = %d, expected ≈3095", d)
	}
	expired, _ := Parse(fixture.CertExpired)
	if d := expired.DaysLeft(now); d >= 0 {
		t.Errorf("expired cert should have negative days left, got %d", d)
	}
}

func TestParseToleratesWhitespaceWrapping(t *testing.T) {
	// Metadata certs are usually wrapped at 64 columns with indentation.
	var wrapped strings.Builder
	for i := 0; i < len(fixture.CertValid); i += 64 {
		end := i + 64
		if end > len(fixture.CertValid) {
			end = len(fixture.CertValid)
		}
		wrapped.WriteString("\n        " + fixture.CertValid[i:end])
	}
	info, err := Parse(wrapped.String())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Subject, "idp.example.test") {
		t.Errorf("subject = %q", info.Subject)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse("!!!"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("bad base64 error = %v", err)
	}
	if _, err := Parse("aGVsbG8gd29ybGQ="); err == nil || !strings.Contains(err.Error(), "DER") {
		t.Errorf("bad DER error = %v", err)
	}
}

func TestCollectLabelsCertificateLocations(t *testing.T) {
	// From a response: the assertion's signature certificate.
	doc, err := saml.Parse([]byte(fixture.Response(fixture.Good())))
	if err != nil {
		t.Fatal(err)
	}
	located := Collect(doc)
	if len(located) != 1 {
		t.Fatalf("located = %d certs, want 1", len(located))
	}
	if located[0].Where != "Assertion signature" {
		t.Errorf("where = %q", located[0].Where)
	}
	if _, err := Parse(located[0].B64); err != nil {
		t.Errorf("collected blob does not parse: %v", err)
	}

	// From metadata: role and key-use in the label.
	doc2, err := saml.Parse([]byte(fixture.Metadata(fixture.MetadataOpts{})))
	if err != nil {
		t.Fatal(err)
	}
	located = Collect(doc2)
	if len(located) != 1 {
		t.Fatalf("metadata located = %d certs, want 1", len(located))
	}
	if located[0].Where != "IdP signing KeyDescriptor" {
		t.Errorf("where = %q", located[0].Where)
	}
}

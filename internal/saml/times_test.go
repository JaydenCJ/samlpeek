// Tests for xs:dateTime parsing and the human duration formatter. SAML
// timestamps in the wild vary more than the spec allows; the parser must
// take what IdPs actually emit while IsNaive flags the non-conforming case.
package saml

import (
	"testing"
	"time"
)

func TestParseTimeAcceptedShapes(t *testing.T) {
	want := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"2026-07-12T09:00:00Z":      want, // spec-conforming UTC
		"2026-07-12T18:00:00+09:00": want, // numeric offset, normalized
		"2026-07-12T09:00:00":       want, // naive, read as UTC
	}
	for in, wantT := range cases {
		got, err := ParseTime(in)
		if err != nil {
			t.Errorf("ParseTime(%q): %v", in, err)
			continue
		}
		if !got.Equal(wantT) {
			t.Errorf("ParseTime(%q) = %v, want %v", in, got, wantT)
		}
	}
	got, err := ParseTime("2026-07-12T09:00:00.123Z") // fractional seconds
	if err != nil {
		t.Fatal(err)
	}
	if got.Nanosecond() != 123000000 {
		t.Fatalf("nanoseconds = %d", got.Nanosecond())
	}
}

func TestParseTimeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "yesterday", "2026-07-12", "12:00:00Z", "2026-13-40T99:00:00Z"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("ParseTime(%q) should fail", bad)
		}
	}
}

func TestIsNaive(t *testing.T) {
	cases := map[string]bool{
		"2026-07-12T09:00:00Z":      false,
		"2026-07-12T09:00:00+09:00": false,
		"2026-07-12T09:00:00-05:00": false,
		"2026-07-12T09:00:00":       true,
		"2026-07-12T09:00:00.5":     true,
		"":                          false,
	}
	for in, want := range cases {
		if got := IsNaive(in); got != want {
			t.Errorf("IsNaive(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFormatDurationCompact(t *testing.T) {
	cases := map[time.Duration]string{
		0:                                    "0s",
		45 * time.Second:                     "45s",
		10 * time.Minute:                     "10m",
		90 * time.Minute:                     "1h30m",
		26 * time.Hour:                       "1d2h",
		-3 * time.Minute:                     "3m", // sign handled by caller's phrasing
		2*time.Minute + 30*time.Second:       "2m30s",
		48*time.Hour + 5*time.Minute:         "2d",
		1*time.Hour + 59*time.Second + 500e6: "1h1m", // rounds to seconds first
	}
	for in, want := range cases {
		if got := FormatDuration(in); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestStatusMeaningKnownAndUnknown(t *testing.T) {
	if got := StatusMeaning("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"); got == "" || got == StatusMeaning("urn:x:unknown") {
		t.Fatalf("AuthnFailed should have a specific meaning, got %q", got)
	}
	if got := ShortStatus("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"); got != "RequestDenied" {
		t.Fatalf("ShortStatus = %q", got)
	}
	if got := ShortStatus(""); got != "(missing)" {
		t.Fatalf("empty status = %q", got)
	}
}

package saml

import (
	"fmt"
	"strings"
	"time"
)

// ParseTime parses a SAML xs:dateTime. The standard requires UTC ("Z"), but
// real IdPs emit fractional seconds, numeric offsets, and even naive
// timestamps; we accept all of those and let the linter comment on the
// naive case separately via IsNaive.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999", // naive, fractional
		"2006-01-02T15:04:05",           // naive
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as xs:dateTime", s)
}

// IsNaive reports whether the timestamp lacks a timezone designator.
// SAML requires UTC "Z"; a naive timestamp will be interpreted differently
// by every peer, which is a real interop bug worth flagging.
func IsNaive(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, "Z") || strings.HasSuffix(s, "z") {
		return false
	}
	// An offset looks like +09:00 / -05:00 after the time-of-day part.
	if i := strings.IndexByte(s, 'T'); i >= 0 {
		rest := s[i+1:]
		return !strings.ContainsAny(rest, "+-")
	}
	return false
}

// FormatDuration renders a duration compactly for humans (e.g. "1h30m",
// "45s", "2d3h"), avoiding Go's default "1h30m0s" noise.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	d = d.Round(time.Second)
	if d == 0 {
		return "0s"
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	secs := d - mins*time.Minute

	var b strings.Builder
	if days > 0 {
		fmt.Fprintf(&b, "%dd", days)
	}
	if hours > 0 {
		fmt.Fprintf(&b, "%dh", hours)
	}
	if mins > 0 && days == 0 {
		fmt.Fprintf(&b, "%dm", mins)
	}
	if secs > 0 && days == 0 && hours == 0 {
		fmt.Fprintf(&b, "%ds", secs/time.Second)
	}
	return b.String()
}

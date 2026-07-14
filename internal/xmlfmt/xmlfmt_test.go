// Tests for the lexical pretty-printer. The invariant that matters: the
// formatter may only insert or remove whitespace BETWEEN tokens — tag
// names, attributes, namespace prefixes, comments, and text values must
// survive byte-for-byte, because the whole point is showing the IdP's
// document faithfully.
package xmlfmt

import (
	"strings"
	"testing"
)

func TestSingleTextElementStaysOnOneLine(t *testing.T) {
	out := Pretty([]byte(`<a><b>value</b></a>`))
	want := "<a>\n  <b>value</b>\n</a>\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestNestedElementsIndentTwoSpaces(t *testing.T) {
	out := Pretty([]byte(`<a><b><c/></b></a>`))
	want := "<a>\n  <b>\n    <c/>\n  </b>\n</a>\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestNamespacePrefixesSurviveVerbatim(t *testing.T) {
	// This is the reason xmlfmt exists: encoding/xml's encoder rewrites
	// prefixes, which makes a SAML dump useless for comparing with logs.
	in := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp</saml:Issuer></samlp:Response>`
	out := Pretty([]byte(in))
	if !strings.Contains(out, `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">`) {
		t.Fatalf("start tag was rewritten:\n%s", out)
	}
	if !strings.Contains(out, `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp</saml:Issuer>`) {
		t.Fatalf("issuer line was rewritten:\n%s", out)
	}
}

func TestCommentsArePreservedNotDropped(t *testing.T) {
	// Comments are attack-relevant in SAML (NameID truncation); the
	// pretty-printer must keep them visible.
	out := Pretty([]byte(`<a><n>alice<!-- x -->@example.test</n></a>`))
	if !strings.Contains(out, "<!-- x -->") {
		t.Fatalf("comment dropped:\n%s", out)
	}
}

func TestCDATAAndProcessingInstructionsKeptIntact(t *testing.T) {
	// A '>' inside CDATA must not terminate the token early.
	out := Pretty([]byte(`<a><![CDATA[if (a<b) > 0]]></a>`))
	if !strings.Contains(out, `<![CDATA[if (a<b) > 0]]>`) {
		t.Fatalf("CDATA mangled:\n%s", out)
	}
	out = Pretty([]byte(`<?xml version="1.0" encoding="UTF-8"?><a/>`))
	if !strings.HasPrefix(out, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatalf("XML declaration lost:\n%s", out)
	}
}

func TestDoctypeWithInternalSubsetNotSplit(t *testing.T) {
	// The '>' inside the entity declaration must not end the DOCTYPE token.
	in := `<!DOCTYPE a [<!ENTITY x "1">]><a>&x;</a>`
	out := Pretty([]byte(in))
	if !strings.Contains(out, `<!DOCTYPE a [<!ENTITY x "1">]>`) {
		t.Fatalf("DOCTYPE split incorrectly:\n%s", out)
	}
}

func TestWhitespaceNormalizationAndEmptyElements(t *testing.T) {
	// <b></b> collapses to one line; noise whitespace between elements
	// is replaced by clean indentation.
	out := Pretty([]byte(`<a><b></b></a>`))
	want := "<a>\n  <b></b>\n</a>\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	out = Pretty([]byte("<a>\n\n\t   <b>v</b>   \n</a>"))
	want = "<a>\n  <b>v</b>\n</a>\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestTruncatedInputDoesNotPanic(t *testing.T) {
	for _, in := range []string{"<a", "<a><!-- unterminated", "<a><![CDATA[oops", "<a><b>text"} {
		_ = Pretty([]byte(in)) // must not panic; output content is best-effort
	}
}

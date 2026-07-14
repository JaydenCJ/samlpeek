// Tests for the transport-decoding chain: every encoding a SAML payload
// realistically arrives in must land on the same XML, with the applied
// steps recorded, and garbage must fail with a descriptive error.
package decode

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

const sampleXML = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.test</saml:Issuer></samlp:AuthnRequest>`

// deflate compresses with raw DEFLATE, as the HTTP-Redirect binding does.
func deflate(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// decodeOK asserts the input decodes to sampleXML and returns the Result.
func decodeOK(t *testing.T, input string) *Result {
	t.Helper()
	res, err := Auto([]byte(input))
	if err != nil {
		t.Fatalf("Auto(%.40q…): %v", input, err)
	}
	if string(res.XML) != sampleXML {
		t.Fatalf("decoded XML mismatch for %.40q…", input)
	}
	return res
}

func TestRawXMLPassesThroughUntouched(t *testing.T) {
	res := decodeOK(t, sampleXML)
	if res.Binding != "raw-xml" {
		t.Fatalf("binding = %q, want raw-xml", res.Binding)
	}
}

func TestRawXMLWithLeadingWhitespaceAndBOM(t *testing.T) {
	// Some Windows IdPs prepend a UTF-8 BOM; pastes often carry newlines.
	decodeOK(t, "\xEF\xBB\xBF\n  "+sampleXML+"\n")
}

func TestPostBindingBase64RecordsSteps(t *testing.T) {
	res := decodeOK(t, base64.StdEncoding.EncodeToString([]byte(sampleXML)))
	if res.Binding != "http-post" {
		t.Fatalf("binding = %q, want http-post", res.Binding)
	}
	joined := strings.Join(res.Steps, " → ")
	if !strings.Contains(joined, "base64 (standard)") || !strings.Contains(joined, "already XML") {
		t.Fatalf("steps missing detail: %q", joined)
	}
}

func TestBase64AlphabetAndWrappingVariants(t *testing.T) {
	// Wrapped at 64 columns, as openssl and mail clients emit.
	b64 := base64.StdEncoding.EncodeToString([]byte(sampleXML))
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		wrapped.WriteString(b64[i:end] + "\n")
	}
	decodeOK(t, wrapped.String())

	// Unpadded (some JWT-adjacent tooling strips '=').
	unpadded := base64.RawStdEncoding.EncodeToString([]byte(sampleXML))
	if strings.HasSuffix(unpadded, "=") {
		t.Fatal("test setup: sample should produce unpadded base64")
	}
	decodeOK(t, unpadded)

	// URL-safe alphabet ('-' and '_' instead of '+' and '/').
	decodeOK(t, base64.URLEncoding.EncodeToString([]byte(sampleXML)))
}

func TestRedirectBindingDeflatedBlob(t *testing.T) {
	res := decodeOK(t, base64.StdEncoding.EncodeToString(deflate(t, sampleXML)))
	if res.Binding != "http-redirect" {
		t.Fatalf("binding = %q, want http-redirect", res.Binding)
	}
	if !strings.Contains(strings.Join(res.Steps, " → "), "inflate") {
		t.Fatalf("steps %v do not mention inflation", res.Steps)
	}
}

func TestZlibFallbackForBrokenCompressors(t *testing.T) {
	// Some stacks emit zlib (with header) instead of raw DEFLATE; the
	// decoder must still succeed and name the method honestly.
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(sampleXML))
	zw.Close()
	res := decodeOK(t, base64.StdEncoding.EncodeToString(buf.Bytes()))
	if !strings.Contains(strings.Join(res.Steps, " "), "zlib") {
		t.Fatalf("steps should record zlib: %v", res.Steps)
	}
}

func TestFullRedirectURL(t *testing.T) {
	payload := url.QueryEscape(base64.StdEncoding.EncodeToString(deflate(t, sampleXML)))
	full := "https://idp.example.test/sso?SAMLRequest=" + payload +
		"&RelayState=%2Fdashboard&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") +
		"&Signature=" + url.QueryEscape("ZmFrZQ==")
	res := decodeOK(t, full)
	if res.Param != "SAMLRequest" {
		t.Fatalf("param = %q, want SAMLRequest", res.Param)
	}
	if res.RelayState != "/dashboard" {
		t.Fatalf("RelayState = %q, want /dashboard", res.RelayState)
	}
	if res.SigAlg == "" || !res.HasSig {
		t.Fatalf("SigAlg/Signature query parameters were not captured")
	}
}

func TestBareQueryStringWithSAMLResponse(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(sampleXML))
	res := decodeOK(t, "SAMLResponse="+url.QueryEscape(b64)+"&RelayState=abc")
	if res.Param != "SAMLResponse" {
		t.Fatalf("param = %q, want SAMLResponse", res.Param)
	}
}

func TestSAMLResponseWinsOverSAMLRequest(t *testing.T) {
	// When a paste contains both parameters, the response is what the
	// integrator is debugging; it must be chosen deterministically.
	respB64 := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(sampleXML)))
	res := decodeOK(t, "SAMLRequest=aWdub3JlZA%3D%3D&SAMLResponse="+respB64)
	if res.Param != "SAMLResponse" {
		t.Fatalf("param = %q, want SAMLResponse", res.Param)
	}
}

func TestPercentEncodedBlobWithoutQueryContext(t *testing.T) {
	// A copied parameter *value* (percent-encoded base64, no key=) must
	// still decode: %2B is '+', %3D is '='.
	b64 := base64.StdEncoding.EncodeToString(deflate(t, sampleXML))
	escaped := url.QueryEscape(b64)
	if escaped == b64 {
		t.Fatal("test setup: deflated base64 should contain characters that percent-encode")
	}
	decodeOK(t, escaped)
}

func TestGarbageInputsFailDescriptively(t *testing.T) {
	cases := []struct {
		name, input, wantErr string
	}{
		{"empty", "   \n ", "empty"},
		{"not base64", "!!!not-base64!!!", "base64"},
		{"base64 of binary junk", base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03, 0xFF}), "neither XML nor DEFLATE"},
		{"url without SAML parameter", "https://idp.example.test/sso?foo=bar", "no SAMLResponse or SAMLRequest"},
	}
	for _, c := range cases {
		_, err := Auto([]byte(c.input))
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.wantErr)
		}
	}
}

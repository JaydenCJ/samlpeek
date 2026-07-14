// Package decode unwraps the transport encodings that SAML messages travel
// in: percent-encoding, HTTP-Redirect query strings, base64 (all four
// alphabets), and raw-DEFLATE or zlib compression. Auto works out the chain
// from the input itself and records every step it took, so the CLI can show
// the user exactly how their blob became XML.
package decode

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// maxInflated caps decompressed output so a hostile zip bomb cannot exhaust
// memory: real SAML messages are a few KB, metadata rarely passes 1 MB.
const maxInflated = 16 << 20

// Result is a decoded SAML payload plus the provenance of how it was found.
type Result struct {
	XML     []byte   // the decoded XML document
	Steps   []string // decoding steps applied, in order
	Param   string   // query/form parameter the payload came from, if any
	Binding string   // "http-redirect", "http-post", or "raw-xml"

	// Companion query parameters seen alongside a redirect-binding payload.
	RelayState string
	SigAlg     string
	HasSig     bool // a Signature= query parameter was present
}

// Auto decodes an arbitrary paste — raw XML, a base64 blob, a full redirect
// URL, or a query/form string — into SAML XML. It never guesses silently:
// every transformation is appended to Result.Steps.
func Auto(input []byte) (*Result, error) {
	trimmed := bytes.TrimSpace(stripBOM(input))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input is empty")
	}

	if looksLikeXML(trimmed) {
		return &Result{XML: trimmed, Steps: []string{"raw XML"}, Binding: "raw-xml"}, nil
	}

	if q, ok := extractQuery(string(trimmed)); ok {
		return fromQuery(q)
	}

	return fromBlob(trimmed, nil)
}

// stripBOM removes a UTF-8 byte-order mark, which some Windows IdPs prepend.
func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

// looksLikeXML reports whether the payload already starts with markup.
func looksLikeXML(b []byte) bool {
	return len(b) > 0 && b[0] == '<'
}

// extractQuery pulls the query/form portion out of a full URL, a bare
// "?..." string, or a raw "key=value&..." body that mentions a SAML
// parameter.
func extractQuery(s string) (string, bool) {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(s); err == nil && u.RawQuery != "" {
			return u.RawQuery, true
		}
		return "", false
	}
	if strings.HasPrefix(s, "?") {
		return s[1:], true
	}
	if strings.Contains(s, "SAMLResponse=") || strings.Contains(s, "SAMLRequest=") {
		return s, true
	}
	return "", false
}

// fromQuery finds the SAML parameter in a parsed query string and decodes
// its value. SAMLResponse wins over SAMLRequest when both are present,
// because a response is nearly always what a debugging integrator holds.
func fromQuery(rawQuery string) (*Result, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("cannot parse query string: %v", err)
	}
	param := ""
	for _, candidate := range []string{"SAMLResponse", "SAMLRequest"} {
		if values.Get(candidate) != "" {
			param = candidate
			break
		}
	}
	if param == "" {
		return nil, fmt.Errorf("query string has no SAMLResponse or SAMLRequest parameter")
	}

	seed := []string{fmt.Sprintf("extract %s from query", param), "percent-decode"}
	res, err := fromBlob([]byte(values.Get(param)), seed)
	if err != nil {
		return nil, fmt.Errorf("%s parameter: %v", param, err)
	}
	res.Param = param
	res.RelayState = values.Get("RelayState")
	res.SigAlg = values.Get("SigAlg")
	res.HasSig = values.Get("Signature") != ""
	if res.Binding == "http-post" {
		// Query-borne but not DEFLATEd: someone pasted a POST body as a
		// query string. Keep the binding honest about the compression.
		res.Binding = "http-redirect"
	}
	return res, nil
}

// fromBlob decodes a bare payload: optional percent-decoding, then base64,
// then — if the result is not already XML — DEFLATE or zlib inflation.
func fromBlob(blob []byte, steps []string) (*Result, error) {
	s := strings.TrimSpace(string(blob))

	// A percent-encoded base64 value (contains %2B, %3D, …) shows up when
	// users copy a parameter value straight out of an address bar.
	if strings.Contains(s, "%") && !strings.ContainsAny(s, " \t\n<>") {
		if unescaped, err := url.QueryUnescape(s); err == nil && unescaped != s {
			s = unescaped
			steps = append(steps, "percent-decode")
		}
	}

	raw, alphabet, err := base64Any(s)
	if err != nil {
		return nil, err
	}
	steps = append(steps, "base64 ("+alphabet+")")

	trimmedRaw := bytes.TrimSpace(stripBOM(raw))
	if looksLikeXML(trimmedRaw) {
		return &Result{XML: trimmedRaw, Steps: append(steps, "already XML"), Binding: "http-post"}, nil
	}

	inflated, method, err := inflate(raw)
	if err != nil {
		return nil, fmt.Errorf("decoded payload is neither XML nor DEFLATE/zlib compressed: %v", err)
	}
	inflated = bytes.TrimSpace(stripBOM(inflated))
	if !looksLikeXML(inflated) {
		return nil, fmt.Errorf("inflated payload does not look like XML (starts with %q)", preview(inflated))
	}
	return &Result{XML: inflated, Steps: append(steps, "inflate ("+method+")"), Binding: "http-redirect"}, nil
}

// base64Any tries the standard alphabet first (what the SAML bindings
// mandate), then the URL-safe alphabet, each with and without padding.
// Interior whitespace is stripped first because many tools wrap base64
// at 64 or 76 columns.
func base64Any(s string) ([]byte, string, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if compact == "" {
		return nil, "", fmt.Errorf("input is empty after removing whitespace")
	}
	attempts := []struct {
		name string
		enc  *base64.Encoding
	}{
		{"standard", base64.StdEncoding},
		{"standard, unpadded", base64.RawStdEncoding},
		{"url-safe", base64.URLEncoding},
		{"url-safe, unpadded", base64.RawURLEncoding},
	}
	for _, a := range attempts {
		if raw, err := a.enc.DecodeString(compact); err == nil {
			return raw, a.name, nil
		}
	}
	return nil, "", fmt.Errorf("input is not valid base64 in any alphabet (standard or url-safe, padded or not)")
}

// inflate decompresses raw-DEFLATE (what the HTTP-Redirect binding
// specifies) and falls back to zlib, which several IdP stacks emit by
// mistake because their compressor added the two-byte header.
func inflate(raw []byte) ([]byte, string, error) {
	if out, err := readAll(flate.NewReader(bytes.NewReader(raw))); err == nil && len(out) > 0 {
		return out, "raw DEFLATE", nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("not raw DEFLATE and no zlib header")
	}
	out, err := readAll(zr)
	if err != nil || len(out) == 0 {
		return nil, "", fmt.Errorf("zlib stream is corrupt")
	}
	return out, "zlib", nil
}

// readAll drains r with the inflation cap applied.
func readAll(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxInflated+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflated {
		return nil, fmt.Errorf("decompressed payload exceeds %d bytes", maxInflated)
	}
	return out, nil
}

// preview returns a short printable prefix for error messages.
func preview(b []byte) string {
	const n = 24
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

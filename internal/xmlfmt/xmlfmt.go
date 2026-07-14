// Package xmlfmt re-indents XML lexically, without parsing it into a tree.
// This matters for SAML: encoding/xml's encoder rewrites namespace prefixes
// and drops the exact byte layout, but a debugging integrator wants to see
// the document *exactly* as the IdP produced it — only with line breaks.
// The formatter therefore never renames, reorders, or unescapes anything;
// it only inserts whitespace between markup tokens.
package xmlfmt

import "strings"

// tokenKind classifies a lexical XML token.
type tokenKind int

const (
	kindText    tokenKind = iota // character data between tags
	kindOpen                     // <name ...>
	kindClose                    // </name>
	kindSelf                     // <name ... />
	kindSpecial                  // comment, CDATA, PI, DOCTYPE — no depth change
)

type token struct {
	kind tokenKind
	text string
}

// Pretty re-indents the document with two-space indentation. Elements whose
// entire content is a single text node stay on one line, so values such as
// <saml:Audience>https://sp.example.test</saml:Audience> remain readable.
// Malformed markup is passed through untouched rather than mangled.
func Pretty(src []byte) string {
	tokens := lex(string(src))
	var b strings.Builder
	depth := 0
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		switch t.kind {
		case kindClose:
			if depth > 0 {
				depth--
			}
			writeLine(&b, depth, t.text)
			i++
		case kindOpen:
			// Look ahead for the <a>text</a> single-line case.
			if i+2 < len(tokens) && tokens[i+1].kind == kindText && tokens[i+2].kind == kindClose {
				writeLine(&b, depth, t.text+strings.TrimSpace(tokens[i+1].text)+tokens[i+2].text)
				i += 3
				continue
			}
			// Immediately-empty element written as <a></a>.
			if i+1 < len(tokens) && tokens[i+1].kind == kindClose {
				writeLine(&b, depth, t.text+tokens[i+1].text)
				i += 2
				continue
			}
			writeLine(&b, depth, t.text)
			depth++
			i++
		case kindSelf, kindSpecial:
			writeLine(&b, depth, t.text)
			i++
		case kindText:
			if s := strings.TrimSpace(t.text); s != "" {
				writeLine(&b, depth, s)
			}
			i++
		}
	}
	return b.String()
}

// writeLine emits one indented line.
func writeLine(b *strings.Builder, depth int, text string) {
	for i := 0; i < depth; i++ {
		b.WriteString("  ")
	}
	b.WriteString(text)
	b.WriteByte('\n')
}

// lex splits src into markup and text tokens. Comments, CDATA sections,
// processing instructions, and DOCTYPE declarations (including an internal
// subset in brackets) are each captured as a single opaque token so that a
// '>' inside them cannot end the token early.
func lex(src string) []token {
	var tokens []token
	i := 0
	for i < len(src) {
		if src[i] != '<' {
			j := strings.IndexByte(src[i:], '<')
			if j < 0 {
				tokens = append(tokens, token{kindText, src[i:]})
				break
			}
			tokens = append(tokens, token{kindText, src[i : i+j]})
			i += j
			continue
		}
		rest := src[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest, "-->")
			tokens, i = appendSpan(tokens, src, i, end, 3, kindSpecial)
		case strings.HasPrefix(rest, "<![CDATA["):
			end := strings.Index(rest, "]]>")
			tokens, i = appendSpan(tokens, src, i, end, 3, kindSpecial)
		case strings.HasPrefix(rest, "<?"):
			end := strings.Index(rest, "?>")
			tokens, i = appendSpan(tokens, src, i, end, 2, kindSpecial)
		case strings.HasPrefix(rest, "<!"):
			end := doctypeEnd(rest)
			tokens, i = appendSpan(tokens, src, i, end, 1, kindSpecial)
		default:
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				tokens = append(tokens, token{kindText, rest})
				return tokens
			}
			tag := rest[:end+1]
			kind := kindOpen
			if strings.HasPrefix(tag, "</") {
				kind = kindClose
			} else if strings.HasSuffix(tag, "/>") {
				kind = kindSelf
			}
			tokens = append(tokens, token{kind, tag})
			i += end + 1
		}
	}
	return tokens
}

// appendSpan appends one opaque token that ends `tail` bytes after the
// located terminator, or swallows the remainder when the terminator is
// missing (truncated input).
func appendSpan(tokens []token, src string, start, end, tail int, kind tokenKind) ([]token, int) {
	if end < 0 {
		return append(tokens, token{kind, src[start:]}), len(src)
	}
	stop := start + end + tail
	return append(tokens, token{kind, src[start:stop]}), stop
}

// doctypeEnd finds the closing '>' of a <!DOCTYPE …> declaration, skipping
// over an internal subset delimited by [ … ].
func doctypeEnd(rest string) int {
	depth := 0
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case '[':
			depth++
		case ']':
			depth--
		case '>':
			if depth <= 0 {
				return i // caller adds tail=1
			}
		}
	}
	return -1
}

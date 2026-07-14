// Package cli implements the samlpeek command-line interface. Run takes
// argv plus the three standard streams and returns an exit code, so the
// whole surface is testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/certs"
	"github.com/JaydenCJ/samlpeek/internal/decode"
	"github.com/JaydenCJ/samlpeek/internal/lint"
	"github.com/JaydenCJ/samlpeek/internal/render"
	"github.com/JaydenCJ/samlpeek/internal/saml"
	"github.com/JaydenCJ/samlpeek/internal/version"
	"github.com/JaydenCJ/samlpeek/internal/xmlfmt"
)

// Exit codes, documented in the README. `lint` uses ExitFindings as its
// machine-readable verdict.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitRuntime  = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "decode":
		return runDecode(args[1:], stdin, stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdin, stdout, stderr)
	case "lint":
		return runLint(args[1:], stdin, stdout, stderr)
	case "certs":
		return runCerts(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "samlpeek %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "samlpeek: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

// usage prints the top-level help.
func usage(w io.Writer) {
	fmt.Fprint(w, `samlpeek — decode and lint SAML responses, requests, and metadata

Usage:
  samlpeek <command> [flags] [file|-]

Commands:
  decode    unwrap base64 / DEFLATE / redirect-URL transport and print the XML
  explain   decode, parse, and print a human-readable summary
  lint      decode, parse, and check conditions, audience, signatures, certs
  certs     list every X.509 certificate embedded in the document
  version   print the samlpeek version

Input is a file path, "-" for stdin, omitted (also stdin), or the payload
itself pasted as the argument (URLs, query strings, raw XML). The payload
may be raw XML, base64 (padded or not, standard or url-safe alphabet), a
full redirect URL, or a query/form string containing SAMLResponse=/
SAMLRequest=; samlpeek works out the encoding chain itself.

Common flags (explain / lint / certs):
  --format text|json   output format (default text)
  --now <RFC3339>      evaluation time for validity checks (default: current time)

Lint flags:
  --skew <duration>    allowed clock skew, e.g. 90s, 2m (default 90s)
  --audience <id>      expected SP entity ID (checks AudienceRestriction)
  --recipient <url>    expected ACS URL (checks bearer Recipient)
  --destination <url>  expected Destination attribute
  --strict             exit 1 on warnings too, not just errors

Exit codes: 0 ok/pass, 1 lint findings, 2 usage error, 3 undecodable input.
`)
}

// commonFlags are shared by explain, lint, and certs.
type commonFlags struct {
	format string
	now    string
}

// register adds the shared flags to a FlagSet.
func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.format, "format", "text", "output format: text or json")
	fs.StringVar(&c.now, "now", "", "evaluation time (RFC3339); defaults to the current time")
}

// resolve validates the shared flags and resolves the evaluation time.
func (c *commonFlags) resolve(stderr io.Writer) (time.Time, bool) {
	if c.format != "text" && c.format != "json" {
		fmt.Fprintf(stderr, "samlpeek: --format must be text or json, got %q\n", c.format)
		return time.Time{}, false
	}
	if c.now == "" {
		return time.Now().UTC(), true
	}
	t, err := time.Parse(time.RFC3339, c.now)
	if err != nil {
		fmt.Fprintf(stderr, "samlpeek: --now must be RFC3339 (e.g. 2026-07-12T09:01:00Z): %v\n", err)
		return time.Time{}, false
	}
	return t.UTC(), true
}

// newFlagSet builds a silent FlagSet whose errors we render ourselves.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// readInput loads the payload from the positional argument or stdin. When
// the argument is not a readable file but is recognizably a payload (a URL,
// a query string, raw XML, or a long blob), it is used directly — so
// `samlpeek explain "https://idp…?SAMLRequest=…"` works as pasted.
func readInput(fs *flag.FlagSet, stdin io.Reader, stderr io.Writer) ([]byte, bool) {
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "samlpeek: expected at most one input, got %d\n", fs.NArg())
		return nil, false
	}
	arg := fs.Arg(0)
	if arg == "" || arg == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "samlpeek: reading stdin: %v\n", err)
			return nil, false
		}
		return data, true
	}
	data, err := os.ReadFile(arg)
	if err == nil {
		return data, true
	}
	if looksLikePayload(arg) {
		return []byte(arg), true
	}
	fmt.Fprintf(stderr, "samlpeek: %v\n", err)
	return nil, false
}

// looksLikePayload reports whether a non-file argument is plausibly the
// SAML payload itself rather than a mistyped path.
func looksLikePayload(s string) bool {
	return strings.Contains(s, "://") ||
		strings.Contains(s, "SAMLRequest=") ||
		strings.Contains(s, "SAMLResponse=") ||
		strings.HasPrefix(strings.TrimSpace(s), "<") ||
		len(s) > 512
}

// decodeAndParse runs the full input pipeline shared by every subcommand.
func decodeAndParse(input []byte, stderr io.Writer) (*saml.Document, *decode.Result, bool) {
	dec, err := decode.Auto(input)
	if err != nil {
		fmt.Fprintf(stderr, "samlpeek: cannot decode input: %v\n", err)
		return nil, nil, false
	}
	doc, err := saml.Parse(dec.XML)
	if err != nil {
		fmt.Fprintf(stderr, "samlpeek: %v\n", err)
		return nil, nil, false
	}
	return doc, dec, true
}

// runDecode implements `samlpeek decode`.
func runDecode(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("decode", stderr)
	pretty := fs.Bool("pretty", false, "re-indent the XML for reading (lexical, never rewrites content)")
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	input, ok := readInput(fs, stdin, stderr)
	if !ok {
		return ExitRuntime
	}
	dec, err := decode.Auto(input)
	if err != nil {
		fmt.Fprintf(stderr, "samlpeek: cannot decode input: %v\n", err)
		return ExitRuntime
	}
	if *pretty {
		fmt.Fprint(stdout, xmlfmt.Pretty(dec.XML))
	} else {
		stdout.Write(dec.XML)
		fmt.Fprintln(stdout)
	}
	return ExitOK
}

// runExplain implements `samlpeek explain`.
func runExplain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("explain", stderr)
	var common commonFlags
	common.register(fs)
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	now, ok := common.resolve(stderr)
	if !ok {
		return ExitUsage
	}
	input, ok := readInput(fs, stdin, stderr)
	if !ok {
		return ExitRuntime
	}
	doc, dec, ok := decodeAndParse(input, stderr)
	if !ok {
		return ExitRuntime
	}
	if common.format == "json" {
		if err := render.ExplainJSON(stdout, doc, dec); err != nil {
			fmt.Fprintf(stderr, "samlpeek: %v\n", err)
			return ExitRuntime
		}
		return ExitOK
	}
	render.Explain(stdout, doc, dec, now)
	return ExitOK
}

// runLint implements `samlpeek lint`.
func runLint(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("lint", stderr)
	var common commonFlags
	common.register(fs)
	skew := fs.Duration("skew", 90*time.Second, "allowed clock skew for validity checks")
	audience := fs.String("audience", "", "expected SP entity ID")
	recipient := fs.String("recipient", "", "expected ACS URL (bearer Recipient)")
	destination := fs.String("destination", "", "expected Destination attribute")
	strict := fs.Bool("strict", false, "exit 1 on warnings too")
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	now, ok := common.resolve(stderr)
	if !ok {
		return ExitUsage
	}
	input, ok := readInput(fs, stdin, stderr)
	if !ok {
		return ExitRuntime
	}
	doc, dec, ok := decodeAndParse(input, stderr)
	if !ok {
		return ExitRuntime
	}

	opts := lint.Options{
		Now:         now,
		Skew:        *skew,
		Audience:    *audience,
		Recipient:   *recipient,
		Destination: *destination,
	}
	findings := lint.Check(doc, opts)

	if common.format == "json" {
		if err := render.LintJSON(stdout, doc, dec, findings, opts); err != nil {
			fmt.Fprintf(stderr, "samlpeek: %v\n", err)
			return ExitRuntime
		}
	} else {
		render.Lint(stdout, doc, findings, opts)
	}

	errors, warnings, _ := lint.Count(findings)
	if errors > 0 || (*strict && warnings > 0) {
		return ExitFindings
	}
	return ExitOK
}

// runCerts implements `samlpeek certs`.
func runCerts(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("certs", stderr)
	var common commonFlags
	common.register(fs)
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	now, ok := common.resolve(stderr)
	if !ok {
		return ExitUsage
	}
	input, ok := readInput(fs, stdin, stderr)
	if !ok {
		return ExitRuntime
	}
	doc, _, ok := decodeAndParse(input, stderr)
	if !ok {
		return ExitRuntime
	}
	located := certs.Collect(doc)
	if common.format == "json" {
		if err := render.CertsJSON(stdout, doc, located, now); err != nil {
			fmt.Fprintf(stderr, "samlpeek: %v\n", err)
			return ExitRuntime
		}
		return ExitOK
	}
	render.Certs(stdout, located, now)
	return ExitOK
}

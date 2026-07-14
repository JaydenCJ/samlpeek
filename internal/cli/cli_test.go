// In-process integration tests for the CLI: every subcommand, both
// formats, stdin and file input, and the documented exit codes — without
// building a binary or touching the network.
package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/samlpeek/internal/fixture"
	"github.com/JaydenCJ/samlpeek/internal/version"
)

// run invokes the CLI with stdin content and returns (exit, stdout, stderr).
func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// writeTemp puts content into a temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionPrintsManifestVersion(t *testing.T) {
	code, out, _ := run(t, "", "version")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(out) != "samlpeek "+version.Version {
		t.Fatalf("out = %q", out)
	}
}

func TestHelpAndUnknownCommandRouting(t *testing.T) {
	code, out, _ := run(t, "", "help")
	if code != ExitOK || !strings.Contains(out, "Usage:") {
		t.Fatalf("help failed: exit=%d out=%q", code, out)
	}
	code, _, errOut := run(t, "")
	if code != ExitUsage || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no-args: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "", "frobnicate")
	if code != ExitUsage || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: exit=%d stderr=%q", code, errOut)
	}
}

func TestDecodeRawAndPretty(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(fixture.Response(fixture.Good())))
	code, out, _ := run(t, b64, "decode", "-")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "<samlp:Response") || !strings.Contains(out, "alice@example.test") {
		t.Fatalf("decoded XML not printed:\n%s", out)
	}

	code, out, _ = run(t, b64, "decode", "--pretty")
	if code != ExitOK {
		t.Fatalf("pretty exit = %d", code)
	}
	if !strings.Contains(out, "\n  <saml:Issuer>https://idp.example.test/saml</saml:Issuer>") {
		t.Fatalf("pretty output not indented:\n%s", out)
	}
}

func TestExplainFromFileAndInlinePayload(t *testing.T) {
	path := writeTemp(t, "resp.b64", base64.StdEncoding.EncodeToString([]byte(fixture.Response(fixture.Good()))))
	code, out, _ := run(t, "", "explain", "--now", fixture.Now, path)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "alice@example.test") || !strings.Contains(out, "http-post") {
		t.Fatalf("explain output incomplete:\n%s", out)
	}

	// A pasted URL argument is not a file; it must be used as the payload.
	b64 := base64.StdEncoding.EncodeToString([]byte(fixture.Response(fixture.Good())))
	urlArg := "https://sp.example.test/saml/acs?SAMLResponse=" + url.QueryEscape(b64)
	code, out, _ = run(t, "", "explain", "--now", fixture.Now, urlArg)
	if code != ExitOK {
		t.Fatalf("url arg exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "extract SAMLResponse from query") {
		t.Fatalf("url arg not decoded from query:\n%s", out)
	}
}

func TestExplainJSONFormat(t *testing.T) {
	code, out, _ := run(t, fixture.Response(fixture.Good()), "explain", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if env["kind"] != "Response" {
		t.Fatalf("kind = %v", env["kind"])
	}
}

func TestLintCleanExitsZero(t *testing.T) {
	code, out, _ := run(t, fixture.Metadata(fixture.MetadataOpts{}),
		"lint", "--now", fixture.Now)
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Fatalf("verdict missing:\n%s", out)
	}
}

func TestLintErrorsExitOne(t *testing.T) {
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T08:30:00Z"
	code, out, _ := run(t, fixture.Response(o), "lint", "--now", fixture.Now)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitFindings, out)
	}
	if !strings.Contains(out, "assertion-expired") {
		t.Fatalf("finding missing:\n%s", out)
	}
}

func TestLintWarningsPassUnlessStrict(t *testing.T) {
	o := fixture.Good()
	o.SigAlg = fixture.SigRSASHA1 // warning only
	xml := fixture.Response(o)

	code, _, _ := run(t, xml, "lint", "--now", fixture.Now)
	if code != ExitOK {
		t.Fatalf("non-strict exit = %d, want 0", code)
	}
	code, _, _ = run(t, xml, "lint", "--now", fixture.Now, "--strict")
	if code != ExitFindings {
		t.Fatalf("strict exit = %d, want %d", code, ExitFindings)
	}
}

func TestLintAudienceFlagWiredThrough(t *testing.T) {
	code, out, _ := run(t, fixture.Response(fixture.Good()),
		"lint", "--now", fixture.Now, "--audience", "https://wrong.example.test")
	if code != ExitFindings || !strings.Contains(out, "audience-mismatch") {
		t.Fatalf("audience flag not applied: exit=%d\n%s", code, out)
	}
}

func TestLintSkewFlagWiredThrough(t *testing.T) {
	// Expired by 4 minutes: fails at the default 90s skew, passes at 10m.
	o := fixture.Good()
	o.NotOnOrAfter = "2026-07-12T08:57:00Z"
	o.BearerExpiry = "2026-07-12T08:57:00Z"
	xml := fixture.Response(o)
	code, _, _ := run(t, xml, "lint", "--now", fixture.Now)
	if code != ExitFindings {
		t.Fatalf("default skew should fail, exit = %d", code)
	}
	code, _, _ = run(t, xml, "lint", "--now", fixture.Now, "--skew", "10m")
	if code != ExitOK {
		t.Fatalf("10m skew should pass, exit = %d", code)
	}
}

func TestLintJSONFormat(t *testing.T) {
	code, out, _ := run(t, fixture.Response(fixture.Good()),
		"lint", "--now", fixture.Now, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var env struct {
		Summary struct{ Verdict string } `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if env.Summary.Verdict != "pass" {
		t.Fatalf("verdict = %q", env.Summary.Verdict)
	}
}

func TestCertsCommand(t *testing.T) {
	code, out, _ := run(t, fixture.Response(fixture.Good()),
		"certs", "--now", fixture.Now)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "CN=idp.example.test") || !strings.Contains(out, "sha256") {
		t.Fatalf("certs output incomplete:\n%s", out)
	}
}

func TestFlagValidationUsageErrors(t *testing.T) {
	code, _, errOut := run(t, fixture.Response(fixture.Good()), "explain", "--format", "yaml")
	if code != ExitUsage || !strings.Contains(errOut, "--format") {
		t.Fatalf("bad format: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "", "lint", "--now", "yesterday")
	if code != ExitUsage || !strings.Contains(errOut, "RFC3339") {
		t.Fatalf("bad now: exit=%d stderr=%q", code, errOut)
	}
}

func TestRuntimeErrorsExitThree(t *testing.T) {
	code, _, errOut := run(t, "", "explain", "/nonexistent/response.b64")
	if code != ExitRuntime || errOut == "" {
		t.Fatalf("missing file: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "!!!definitely not saml!!!", "explain")
	if code != ExitRuntime || !strings.Contains(errOut, "cannot decode input") {
		t.Fatalf("garbage: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "<html><body>login page, not SAML</body></html>", "lint")
	if code != ExitRuntime || !strings.Contains(errOut, "unrecognized root element") {
		t.Fatalf("non-SAML XML: exit=%d stderr=%q", code, errOut)
	}
	code, _, errOut = run(t, "", "explain", "a.xml", "b.xml")
	if code != ExitRuntime || !strings.Contains(errOut, "at most one input") {
		t.Fatalf("two files: exit=%d stderr=%q", code, errOut)
	}
}

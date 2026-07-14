// Command samlpeek decodes SAML responses, requests, and metadata from any
// transport encoding (base64, DEFLATE, redirect URLs) and lints them for the
// problems that actually break SSO logins: expired conditions, audience
// mismatches, weak algorithms, dead certificates.
package main

import (
	"os"

	"github.com/JaydenCJ/samlpeek/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

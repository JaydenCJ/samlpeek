package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/JaydenCJ/samlpeek/internal/certs"
	"github.com/JaydenCJ/samlpeek/internal/decode"
	"github.com/JaydenCJ/samlpeek/internal/lint"
	"github.com/JaydenCJ/samlpeek/internal/saml"
)

// schemaVersion identifies the JSON envelope layout; bump on breaking
// changes so scripts can pin what they parse.
const schemaVersion = 1

// envelope is the common JSON wrapper for every subcommand. The document
// types below are deliberate DTOs rather than the internal model, so the
// published schema never changes by accident when the parser does.
type envelope struct {
	Tool          string   `json:"tool"`
	SchemaVersion int      `json:"schema_version"`
	Kind          string   `json:"kind"`
	Binding       string   `json:"binding,omitempty"`
	DecodeSteps   []string `json:"decode_steps,omitempty"`

	Response       *jsonResponse   `json:"response,omitempty"`
	Assertion      *jsonAssertion  `json:"assertion,omitempty"`
	AuthnRequest   *jsonAuthnReq   `json:"authn_request,omitempty"`
	LogoutRequest  *jsonLogoutReq  `json:"logout_request,omitempty"`
	LogoutResponse *jsonLogoutResp `json:"logout_response,omitempty"`
	Entities       []jsonEntity    `json:"entities,omitempty"`
	Findings       []jsonFinding   `json:"findings,omitempty"`
	Summary        *jsonSummary    `json:"summary,omitempty"`
	Certs          []jsonCert      `json:"certificates,omitempty"`
	EvaluatedAt    string          `json:"evaluated_at,omitempty"`
	SkewSeconds    *int            `json:"skew_seconds,omitempty"`
}

type jsonResponse struct {
	ID                  string          `json:"id"`
	IssueInstant        string          `json:"issue_instant"`
	Issuer              string          `json:"issuer"`
	Destination         string          `json:"destination,omitempty"`
	InResponseTo        string          `json:"in_response_to,omitempty"`
	Status              string          `json:"status"`
	StatusSub           string          `json:"status_sub,omitempty"`
	StatusMessage       string          `json:"status_message,omitempty"`
	Signed              bool            `json:"signed"`
	Signature           *jsonSignature  `json:"signature,omitempty"`
	Assertions          []jsonAssertion `json:"assertions,omitempty"`
	EncryptedAssertions int             `json:"encrypted_assertions,omitempty"`
}

type jsonAssertion struct {
	ID            string          `json:"id"`
	Issuer        string          `json:"issuer"`
	IssueInstant  string          `json:"issue_instant"`
	Signed        bool            `json:"signed"`
	Signature     *jsonSignature  `json:"signature,omitempty"`
	NameID        string          `json:"name_id,omitempty"`
	NameIDFormat  string          `json:"name_id_format,omitempty"`
	NameIDComment bool            `json:"name_id_has_comment,omitempty"`
	Confirmations []jsonConfirm   `json:"subject_confirmations,omitempty"`
	NotBefore     string          `json:"not_before,omitempty"`
	NotOnOrAfter  string          `json:"not_on_or_after,omitempty"`
	Audiences     []string        `json:"audiences,omitempty"`
	AuthnContext  string          `json:"authn_context,omitempty"`
	AuthnInstant  string          `json:"authn_instant,omitempty"`
	SessionIndex  string          `json:"session_index,omitempty"`
	Attributes    []jsonAttribute `json:"attributes,omitempty"`
}

type jsonConfirm struct {
	Method       string `json:"method"`
	Recipient    string `json:"recipient,omitempty"`
	NotOnOrAfter string `json:"not_on_or_after,omitempty"`
	InResponseTo string `json:"in_response_to,omitempty"`
}

type jsonAttribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type jsonSignature struct {
	SignatureAlg string `json:"signature_algorithm"`
	DigestAlg    string `json:"digest_algorithm"`
	ReferenceURI string `json:"reference_uri,omitempty"`
	Certificates int    `json:"certificates"`
}

type jsonAuthnReq struct {
	ID           string `json:"id"`
	IssueInstant string `json:"issue_instant"`
	Issuer       string `json:"issuer"`
	Destination  string `json:"destination,omitempty"`
	ACSURL       string `json:"acs_url,omitempty"`
	Binding      string `json:"protocol_binding,omitempty"`
	NameIDPolicy string `json:"name_id_policy,omitempty"`
	ForceAuthn   string `json:"force_authn,omitempty"`
	IsPassive    string `json:"is_passive,omitempty"`
	Signed       bool   `json:"signed"`
}

type jsonLogoutReq struct {
	ID           string   `json:"id"`
	IssueInstant string   `json:"issue_instant"`
	Issuer       string   `json:"issuer"`
	NameID       string   `json:"name_id,omitempty"`
	SessionIndex []string `json:"session_index,omitempty"`
	NotOnOrAfter string   `json:"not_on_or_after,omitempty"`
}

type jsonLogoutResp struct {
	ID           string `json:"id"`
	IssueInstant string `json:"issue_instant"`
	Issuer       string `json:"issuer"`
	InResponseTo string `json:"in_response_to,omitempty"`
	Status       string `json:"status"`
}

type jsonEntity struct {
	EntityID   string         `json:"entity_id"`
	ValidUntil string         `json:"valid_until,omitempty"`
	Roles      []string       `json:"roles"`
	SSO        []jsonEndpoint `json:"sso_endpoints,omitempty"`
	ACS        []jsonEndpoint `json:"acs_endpoints,omitempty"`
}

type jsonEndpoint struct {
	Binding  string `json:"binding"`
	Location string `json:"location"`
}

type jsonFinding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
}

type jsonSummary struct {
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Info     int    `json:"info"`
	Verdict  string `json:"verdict"`
}

type jsonCert struct {
	Where      string `json:"where"`
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Serial     string `json:"serial,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	Key        string `json:"key,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	Status     string `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
}

// writeJSON marshals with indentation and a trailing newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// newEnvelope fills the common fields.
func newEnvelope(doc *saml.Document, dec *decode.Result) envelope {
	return envelope{
		Tool:          "samlpeek",
		SchemaVersion: schemaVersion,
		Kind:          string(doc.Kind),
		Binding:       dec.Binding,
		DecodeSteps:   dec.Steps,
	}
}

// ExplainJSON emits the parsed document inside the envelope.
func ExplainJSON(w io.Writer, doc *saml.Document, dec *decode.Result) error {
	env := newEnvelope(doc, dec)
	switch doc.Kind {
	case saml.KindResponse:
		env.Response = toJSONResponse(doc.Response)
	case saml.KindAssertion:
		a := toJSONAssertion(doc.Assertion)
		env.Assertion = &a
	case saml.KindAuthnRequest:
		env.AuthnRequest = toJSONAuthnReq(doc.AuthnRequest)
	case saml.KindLogoutRequest:
		env.LogoutRequest = toJSONLogoutReq(doc.LogoutRequest)
	case saml.KindLogoutResponse:
		env.LogoutResponse = toJSONLogoutResp(doc.LogoutResponse)
	case saml.KindEntityDescriptor:
		env.Entities = []jsonEntity{toJSONEntity(doc.Entity)}
	case saml.KindEntitiesDescriptor:
		for i := range doc.Entities {
			env.Entities = append(env.Entities, toJSONEntity(&doc.Entities[i]))
		}
	}
	return writeJSON(w, env)
}

func toJSONResponse(r *saml.Response) *jsonResponse {
	out := &jsonResponse{
		ID:                  r.ID,
		IssueInstant:        r.IssueInstant,
		Issuer:              r.Issuer,
		Destination:         r.Destination,
		InResponseTo:        r.InResponseTo,
		Status:              saml.ShortStatus(r.Status.Code.Value),
		StatusMessage:       r.Status.Message,
		Signed:              r.Signature != nil,
		Signature:           toJSONSignature(r.Signature),
		EncryptedAssertions: len(r.EncryptedAssertions),
	}
	if r.Status.Code.Sub != nil {
		out.StatusSub = saml.ShortStatus(r.Status.Code.Sub.Value)
	}
	for i := range r.Assertions {
		out.Assertions = append(out.Assertions, toJSONAssertion(&r.Assertions[i]))
	}
	return out
}

func toJSONAssertion(a *saml.Assertion) jsonAssertion {
	out := jsonAssertion{
		ID:           a.ID,
		Issuer:       a.Issuer,
		IssueInstant: a.IssueInstant,
		Signed:       a.Signature != nil,
		Signature:    toJSONSignature(a.Signature),
	}
	if s := a.Subject; s != nil {
		if s.NameID != nil {
			out.NameID = s.NameID.Value
			out.NameIDFormat = saml.NameIDFormatName(s.NameID.Format)
			out.NameIDComment = s.NameID.HasComment
		}
		for _, c := range s.Confirmations {
			jc := jsonConfirm{Method: c.Method}
			if c.Data != nil {
				jc.Recipient = c.Data.Recipient
				jc.NotOnOrAfter = c.Data.NotOnOrAfter
				jc.InResponseTo = c.Data.InResponseTo
			}
			out.Confirmations = append(out.Confirmations, jc)
		}
	}
	if c := a.Conditions; c != nil {
		out.NotBefore = c.NotBefore
		out.NotOnOrAfter = c.NotOnOrAfter
		out.Audiences = c.Audiences()
	}
	if len(a.AuthnStatements) > 0 {
		st := a.AuthnStatements[0]
		out.AuthnContext = st.ContextClassRef
		out.AuthnInstant = st.AuthnInstant
		out.SessionIndex = st.SessionIndex
	}
	for _, at := range a.Attributes() {
		out.Attributes = append(out.Attributes, jsonAttribute{Name: at.Name, Values: at.Values})
	}
	return out
}

func toJSONSignature(sig *saml.Signature) *jsonSignature {
	if sig == nil {
		return nil
	}
	return &jsonSignature{
		SignatureAlg: saml.AlgorithmName(sig.SignatureAlg),
		DigestAlg:    saml.AlgorithmName(sig.DigestAlg),
		ReferenceURI: sig.ReferenceURI,
		Certificates: len(sig.Certificates),
	}
}

func toJSONAuthnReq(r *saml.AuthnRequest) *jsonAuthnReq {
	out := &jsonAuthnReq{
		ID:           r.ID,
		IssueInstant: r.IssueInstant,
		Issuer:       r.Issuer,
		Destination:  r.Destination,
		ACSURL:       r.ACSURL,
		Binding:      saml.BindingName(r.ProtocolBinding),
		ForceAuthn:   r.ForceAuthn,
		IsPassive:    r.IsPassive,
		Signed:       r.Signature != nil,
	}
	if r.NameIDPolicy != nil {
		out.NameIDPolicy = saml.NameIDFormatName(r.NameIDPolicy.Format)
	}
	return out
}

func toJSONLogoutReq(r *saml.LogoutRequest) *jsonLogoutReq {
	out := &jsonLogoutReq{
		ID:           r.ID,
		IssueInstant: r.IssueInstant,
		Issuer:       r.Issuer,
		SessionIndex: r.SessionIndex,
		NotOnOrAfter: r.NotOnOrAfter,
	}
	if r.NameID != nil {
		out.NameID = r.NameID.Value
	}
	return out
}

func toJSONLogoutResp(r *saml.LogoutResponse) *jsonLogoutResp {
	return &jsonLogoutResp{
		ID:           r.ID,
		IssueInstant: r.IssueInstant,
		Issuer:       r.Issuer,
		InResponseTo: r.InResponseTo,
		Status:       saml.ShortStatus(r.Status.Code.Value),
	}
}

func toJSONEntity(e *saml.EntityDescriptor) jsonEntity {
	out := jsonEntity{EntityID: e.EntityID, ValidUntil: e.ValidUntil, Roles: []string{}}
	if e.IDPSSO != nil {
		out.Roles = append(out.Roles, "idp")
		for _, ep := range e.IDPSSO.SSOServices {
			out.SSO = append(out.SSO, jsonEndpoint{Binding: saml.BindingName(ep.Binding), Location: ep.Location})
		}
	}
	if e.SPSSO != nil {
		out.Roles = append(out.Roles, "sp")
		for _, acs := range e.SPSSO.ACS {
			out.ACS = append(out.ACS, jsonEndpoint{Binding: saml.BindingName(acs.Binding), Location: acs.Location})
		}
	}
	return out
}

// LintJSON emits findings plus the pass/fail summary.
func LintJSON(w io.Writer, doc *saml.Document, dec *decode.Result, findings []lint.Finding, opts lint.Options) error {
	jf := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		jf = append(jf, jsonFinding{Severity: f.Severity.String(), Rule: f.Rule, Message: f.Message})
	}
	errors, warnings, infos := lint.Count(findings)
	verdict := "pass"
	if errors > 0 {
		verdict = "fail"
	}
	skew := int(opts.Skew / time.Second)
	env := newEnvelope(doc, dec)
	env.Findings = jf
	env.Summary = &jsonSummary{Errors: errors, Warnings: warnings, Info: infos, Verdict: verdict}
	env.EvaluatedAt = opts.Now.UTC().Format(time.RFC3339)
	env.SkewSeconds = &skew
	return writeJSON(w, env)
}

// CertsJSON emits the certificate listing.
func CertsJSON(w io.Writer, doc *saml.Document, located []certs.Located, now time.Time) error {
	jc := make([]jsonCert, 0, len(located))
	for _, lc := range located {
		info, err := certs.Parse(lc.B64)
		if err != nil {
			jc = append(jc, jsonCert{Where: lc.Where, Error: err.Error()})
			continue
		}
		c := jsonCert{
			Where:      lc.Where,
			Subject:    info.Subject,
			Issuer:     info.Issuer,
			Serial:     info.Serial,
			NotBefore:  info.NotBefore.Format(time.RFC3339),
			NotAfter:   info.NotAfter.Format(time.RFC3339),
			Key:        info.Key,
			SHA256:     info.SHA256,
			SelfSigned: info.SelfSigned,
		}
		if !now.IsZero() {
			c.Status = info.Status(now)
		}
		jc = append(jc, c)
	}
	env := envelope{Tool: "samlpeek", SchemaVersion: schemaVersion, Kind: string(doc.Kind), Certs: jc}
	return writeJSON(w, env)
}

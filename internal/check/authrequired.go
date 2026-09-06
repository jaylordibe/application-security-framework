// Package check contains AppSec Framework's native checks.
//
// A check turns an expectation into requests, classifies what came back, and
// returns a result the engine records. Checks never write files, never decide
// coverage, and never contact anything except through the scope-enforced client.
package check

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/outcome"
)

// AuthRequiredID identifies the declared-authentication check.
const AuthRequiredID = "declared-auth-not-enforced"

// Result is what a check reports back to the engine.
type Result struct {
	// Disposition says whether the check produced a usable outcome.
	Disposition model.Disposition
	Cause       model.BlockedCause
	Detail      string
	// Finding is set when the check produced one. A check may execute and
	// legitimately produce nothing.
	Finding *model.Finding
	// Exchanges are the evidence gathered, already redacted.
	Exchanges []model.Exchange
}

// AuthRequired tests whether an operation whose own specification declares that
// it requires authentication will nonetheless serve an unauthenticated request.
//
// This is CWE-306 / OWASP API2. What makes it worth running is not the technique,
// which is trivial, but the oracle: the expectation is derived from the
// application's own artefact rather than from a human's guess.
//
// A single unauthenticated 200 is emphatically not proof. Too many things return
// 200 without being a vulnerability: single-page-app catch-all routes serving
// index.html, soft-404s, cached edge responses, CORS preflights, and endpoints
// that are genuinely public under a document that marks everything as protected.
// So the check runs a ladder of discriminators and only rises in confidence as
// each is passed.
type AuthRequired struct {
	Client  *httpx.Client
	Signals outcome.Signals
	// BaselineProbes is how many random paths are fetched to fingerprint the
	// target's catch-all behaviour.
	BaselineProbes int
}

// Metadata describes the check.
func (AuthRequired) Metadata() Metadata {
	return Metadata{
		ID:    AuthRequiredID,
		Title: "Operation declared as requiring authentication responds without credentials",
		CWE:   []string{"CWE-306"},
		OWASP: []string{"API2:2023 Broken Authentication"},
	}
}

// Metadata is a check's static description.
type Metadata struct {
	ID    string
	Title string
	CWE   []string
	OWASP []string
}

// RequiredProfile reports the safety profile needed to exercise an operation.
//
// It is a property of the (check, operation) pair rather than of the check
// alone. This check iterates every operation in a document; declaring one static
// impact would mean sending an unauthenticated DELETE under the discovery
// profile — and if that endpoint really is missing authentication, which is
// exactly what is being hunted, the check would destroy data while proving it.
func (AuthRequired) RequiredProfile(op model.Operation) model.Profile {
	return model.RequiredProfileForMethod(op.Method)
}

// Applicable reports whether the check has an oracle for this operation, and why
// not when it does not. A "no" here becomes an untested ledger row with a
// reason, never a silent skip.
func (AuthRequired) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	if op.Security == nil {
		return false, model.CauseNoOracle,
			"the specification states no security requirement for this operation, so there is " +
				"nothing to test it against"
	}
	if op.DeclaresPublic() {
		return false, model.CauseNoOracle,
			"the specification declares this operation public, so an unauthenticated success is expected"
	}
	if !op.DeclaresAuthRequired() {
		return false, model.CauseNoOracle,
			"the specification makes authentication optional for this operation, so an " +
				"unauthenticated success is correct behaviour"
	}
	if params := op.RequiredPathParams(); len(params) > 0 {
		return false, model.CauseMissingResource, fmt.Sprintf(
			"this operation requires path parameter(s) %s and no resource was supplied; probing "+
				"it with an invented identifier would exercise a resource that does not exist, and "+
				"the resulting response would say nothing about access control",
			strings.Join(params, ", "))
	}
	return true, model.CauseNone, ""
}

// Run executes the check against one operation.
func (c AuthRequired) Run(ctx context.Context, op model.Operation) Result {
	var exchanges []model.Exchange

	target := operationURL(op)

	// Step 1: fingerprint the target's behaviour for paths that do not exist, so
	// a catch-all route cannot be mistaken for an exposed endpoint.
	baseline, baselineEx, err := c.baselineFingerprint(ctx, op)
	exchanges = append(exchanges, baselineEx...)
	if err != nil {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseTransportError,
			Detail:      "could not establish a catch-all baseline: " + err.Error(),
			Exchanges:   exchanges,
		}
	}

	// Step 2: the unauthenticated request, with cache defeated.
	primary, err := c.probe(ctx, op, nil)
	if primary.Request.URL != "" {
		exchanges = append(exchanges, primary)
	}
	if err != nil {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       transportCause(err),
			Detail:      "the unauthenticated request could not be completed: " + summarize(err),
			Exchanges:   exchanges,
		}
	}

	cls := outcome.Classify(primary.Response, c.Signals)

	steps := []model.VerificationStep{}

	switch cls.Outcome {
	case model.OutcomeRateLimited:
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseRateLimited,
			Detail: "the target is rate limiting, so a denial cannot be distinguished from " +
				"a block; results after this point would be false negatives",
			Exchanges: exchanges,
		}
	case model.OutcomeError:
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseTransportError,
			Detail:      "the target returned an error: " + cls.Reason,
			Exchanges:   exchanges,
		}
	case model.OutcomeIndeterminate:
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseIndeterminateOutcome,
			Detail:      cls.Reason,
			Exchanges:   exchanges,
		}
	case model.OutcomeDenied, model.OutcomeNotFound:
		// The declared control appears to hold. This is the expected result and
		// is not a finding.
		//
		// It is recorded as executed rather than as proof: without an
		// authenticated control request we know the endpoint refused us, not
		// that it would have served a legitimate caller.
		detail := "the operation refused an unauthenticated request, which matches its declaration"
		if edge := edgeFingerprint(primary.Response); edge != "" {
			detail += "; note that " + edge + ", so the refusal may come from an intermediary rather than the application"
		}
		return Result{
			Disposition: model.DispositionExecuted,
			Detail:      detail,
			Exchanges:   exchanges,
		}
	}

	// The response was a success. Now try to disprove it.
	steps = append(steps, model.VerificationStep{
		Name: "unauthenticated-request-succeeded", Passed: true,
		Detail: fmt.Sprintf("status %d", primary.Response.Status),
	})

	// Discriminator: does this look exactly like the catch-all?
	if baseline.matches(primary.Response) {
		return Result{
			Disposition: model.DispositionExecuted,
			Detail: "the response is indistinguishable from the target's response to a " +
				"non-existent path, so it is a catch-all route rather than an exposed operation",
			Exchanges: exchanges,
		}
	}
	if baseline.established {
		steps = append(steps, model.VerificationStep{
			Name: "distinct-from-catch-all", Passed: true,
			Detail: "the response differs from the target's not-found fingerprint",
		})
	} else {
		// No stable not-found behaviour was observed, so there is nothing to
		// differ from. Recording this as passed would publish a discriminator
		// that never ran and inflate confidence in a high-severity finding.
		steps = append(steps, model.VerificationStep{
			Name: "distinct-from-catch-all", Passed: false,
			Detail: "the target has no stable not-found behaviour, so a catch-all route could " +
				"not be ruled out",
		})
	}

	// Discriminator: content type. HTML served for an API operation is almost
	// always a single-page-app shell or a login page.
	ct := strings.ToLower(primary.Response.HeaderValue("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseIndeterminateOutcome,
			Detail: "the operation returned HTML, which is typically a single-page-app shell " +
				"or a login page rather than the operation's data; this cannot be scored either way",
			Exchanges: exchanges,
		}
	}
	steps = append(steps, model.VerificationStep{
		Name: "content-type-plausible", Passed: true, Detail: "response is not HTML",
	})

	// Discriminator: was this served from a cache? If so we have learned nothing
	// about the origin.
	if cache := cacheFingerprint(primary.Response); cache != "" {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseIndeterminateOutcome,
			Detail: "the response appears to have been served from a cache (" + cache +
				"), so it does not demonstrate the origin's behaviour",
			Exchanges: exchanges,
		}
	}
	steps = append(steps, model.VerificationStep{
		Name: "not-served-from-cache", Passed: true, Detail: "no cache-hit indicators present",
	})

	// Discriminator: repeat it. One-off successes are more often session or
	// state artefacts than real findings.
	repeat, err := c.probe(ctx, op, nil)
	if repeat.Request.URL != "" {
		exchanges = append(exchanges, repeat)
	}
	if err != nil || repeat.Response == nil {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseTransportError,
			Detail:      "the confirming request could not be completed, so the result is not reproducible",
			Exchanges:   exchanges,
		}
	}
	repeatCls := outcome.Classify(repeat.Response, c.Signals)
	if repeatCls.Outcome != model.OutcomeAllowed {
		return Result{
			Disposition: model.DispositionBlocked,
			Cause:       model.CauseIndeterminateOutcome,
			Detail: "the operation succeeded once and then did not, so the behaviour is not " +
				"reproducible and must not be reported as a finding",
			Exchanges: exchanges,
		}
	}
	steps = append(steps, model.VerificationStep{
		Name: "reproducible", Passed: true, Detail: "two consecutive unauthenticated requests succeeded",
	})

	// Discriminator: does a garbage credential also succeed? This separates
	// "authentication is absent" from "authentication is present but broken",
	// which have different fixes.
	garbageToken, terr := randomToken()
	if terr != nil {
		garbageToken = ""
	}
	garbage, gerr := c.probe(ctx, op, map[string][]string{
		"Authorization": {"Bearer " + garbageToken},
	})
	if garbage.Request.URL != "" {
		exchanges = append(exchanges, garbage)
	}
	// Distinguishing "authentication is absent" from "authentication exists but is
	// not enforced" needs this probe to have succeeded. If it did not, say so
	// rather than asserting the stronger claim on no evidence.
	credentialProbeInconclusive := gerr != nil || garbage.Response == nil || terr != nil
	missingRatherThanBroken := true
	if !credentialProbeInconclusive {
		if outcome.Classify(garbage.Response, c.Signals).Outcome != model.OutcomeAllowed {
			// A malformed token is rejected, so a credential path exists; it just
			// is not required.
			missingRatherThanBroken = false
		}
	}

	title := "Operation declared as requiring authentication is served without credentials"
	expected := "the specification declares this operation requires authentication, so an " +
		"unauthenticated request should be refused"
	actualDetail := fmt.Sprintf("the operation returned %d to a request carrying no credentials, twice",
		primary.Response.Status)
	switch {
	case credentialProbeInconclusive:
		// Say nothing about which of the two it is.
	case !missingRatherThanBroken:
		actualDetail += "; a malformed credential was rejected, so a credential path exists but is not enforced"
	default:
		actualDetail += "; a malformed credential was also accepted, so no credential is required"
	}

	verification := model.VerificationRecord{
		Strategy:  "unauthenticated-probe-with-catch-all-cache-and-repetition-discriminators",
		Steps:     steps,
		Performed: true,
		Result:    "the operation served an unauthenticated request and no discriminator explained it away",
		// Without credentials there is no authenticated control request, so we
		// cannot show that the content returned is the content a legitimate
		// caller would receive. Confidence is capped accordingly and the gap is
		// named rather than hidden.
		Unavailable: unavailable(baseline.established, credentialProbeInconclusive),
	}

	finding := &model.Finding{
		CheckID:      AuthRequiredID,
		Title:        title,
		State:        model.StateSuspected,
		Severity:     model.SeverityHigh,
		Confidence:   model.ConfidenceMedium,
		CWE:          []string{"CWE-306"},
		OWASP:        []string{"API2:2023 Broken Authentication"},
		OperationID:  op.ID,
		IdentityID:   model.AnonymousIdentity().ID,
		Expected:     expected,
		Actual:       actualDetail,
		Verification: verification,
		Remediation: "Confirm that this operation is intended to require authentication. If it is, " +
			"apply the authentication control at the operation. If it is genuinely public, correct " +
			"the specification so that the declared and actual posture agree.",
		Reproduction: []string{
			fmt.Sprintf("%s %s with no Authorization header", op.Method, target),
		},
	}

	return Result{
		Disposition: model.DispositionExecuted,
		Detail:      "an unauthenticated request succeeded against a declared-protected operation",
		Finding:     finding,
		Exchanges:   exchanges,
	}
}

// unavailable names the corroboration this run could not obtain. Naming a gap
// caps confidence honestly; omitting it would round the result up.
func unavailable(baselineEstablished, credentialProbeInconclusive bool) []string {
	out := []string{
		"authenticated-control-request: no identity is configured, so the response could " +
			"not be compared against what a legitimate caller receives",
	}
	if !baselineEstablished {
		out = append(out, "catch-all-baseline: the target has no stable not-found behaviour, so a "+
			"catch-all route could not be excluded")
	}
	if credentialProbeInconclusive {
		out = append(out, "credential-probe: the malformed-credential request did not complete, so "+
			"missing authentication could not be distinguished from unenforced authentication")
	}
	return out
}

// probe performs one unauthenticated request with caching defeated.
func (c AuthRequired) probe(ctx context.Context, op model.Operation, extra map[string][]string) (model.Exchange, error) {
	header := map[string][]string{
		"Accept":        {"application/json, */*"},
		"Cache-Control": {"no-cache"},
		"Pragma":        {"no-cache"},
	}
	for k, v := range extra {
		header[k] = v
	}
	url, err := cacheBust(operationURL(op))
	if err != nil {
		return model.Exchange{}, err
	}
	return c.Client.Do(ctx, httpx.Request{
		Method: op.Method,
		URL:    url,
		Header: header,
	})
}

// fingerprint describes how a target responds to a path that does not exist.
type fingerprint struct {
	established bool
	status      int
	contentType string
	bodyLen     int
}

// matches reports whether a response looks like the catch-all.
//
// Body length is compared with tolerance because catch-all pages often embed a
// varying path or nonce.
func (f fingerprint) matches(resp *model.CapturedResponse) bool {
	if !f.established || resp == nil {
		return false
	}
	if resp.Status != f.status {
		return false
	}
	if normalizeContentType(resp.HeaderValue("Content-Type")) != f.contentType {
		return false
	}
	got, want := len(resp.Body), f.bodyLen
	if want == 0 {
		return got == 0
	}
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(want) < 0.05
}

// baselineFingerprint probes random paths to learn the target's not-found
// behaviour. Random paths cannot collide with real routes.
func (c AuthRequired) baselineFingerprint(ctx context.Context, op model.Operation) (fingerprint, []model.Exchange, error) {
	probes := c.BaselineProbes
	if probes <= 0 {
		probes = 2
	}
	var exchanges []model.Exchange
	var last fingerprint
	for i := 0; i < probes; i++ {
		nonce, nerr := randomToken()
		if nerr != nil {
			return fingerprint{}, exchanges, nerr
		}
		u := baselineURL(op, nonce)
		ex, err := c.Client.Do(ctx, httpx.Request{
			Method: http.MethodGet,
			URL:    u,
			Header: map[string][]string{"Accept": {"application/json, */*"}, "Cache-Control": {"no-cache"}},
		})
		if ex.Request.URL != "" {
			exchanges = append(exchanges, ex)
		}
		if err != nil {
			return fingerprint{}, exchanges, fmt.Errorf("%s", summarize(err))
		}
		if ex.Response == nil {
			return fingerprint{}, exchanges, fmt.Errorf("no response to a baseline probe")
		}
		cur := fingerprint{
			established: true,
			status:      ex.Response.Status,
			contentType: normalizeContentType(ex.Response.HeaderValue("Content-Type")),
			bodyLen:     len(ex.Response.Body),
		}
		if i > 0 && !last.matches(ex.Response) {
			// The target's not-found behaviour is not stable, so it cannot be
			// used to exclude anything. Report an unestablished baseline rather
			// than a misleading one.
			return fingerprint{}, exchanges, nil
		}
		last = cur
	}
	return last, exchanges, nil
}

// operationURL builds the concrete URL for an operation.
func operationURL(op model.Operation) string {
	return strings.TrimRight(op.BaseURL, "/") + "/" + strings.TrimLeft(op.PathTemplate, "/")
}

// baselineURL builds a sibling path that cannot exist, preserving the prefix so
// that routing behaves as it would for the real operation.
func baselineURL(op model.Operation, nonce string) string {
	base := strings.TrimRight(op.BaseURL, "/")
	path := "/" + strings.TrimLeft(op.PathTemplate, "/")
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		path = path[:i]
	} else {
		path = ""
	}
	return base + path + "/appsec-nonexistent-" + nonce
}

// cacheBust appends a unique query parameter so an intermediary cache cannot
// serve a stored response.
func cacheBust(raw string) (string, error) {
	nonce, err := randomToken()
	if err != nil {
		return "", err
	}
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
	}
	return raw + sep + "__appsec_cb=" + nonce, nil
}

// cacheFingerprint reports evidence that a response came from a cache.
func cacheFingerprint(resp *model.CapturedResponse) string {
	if resp == nil {
		return ""
	}
	if age := resp.HeaderValue("Age"); age != "" && age != "0" {
		return "Age: " + sanitizeHeader(age)
	}
	for _, h := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Drupal-Cache"} {
		if v := resp.HeaderValue(h); v != "" && strings.Contains(strings.ToUpper(v), "HIT") {
			return h + ": " + sanitizeHeader(v)
		}
	}
	return ""
}

// edgeFingerprint reports evidence that a CDN, WAF or gateway sits in front of
// the application. A denial from an intermediary says nothing about whether the
// application itself enforces anything.
func edgeFingerprint(resp *model.CapturedResponse) string {
	if resp == nil {
		return ""
	}
	for _, h := range []string{"CF-Ray", "X-Amzn-Waf-Action", "X-Amz-Cf-Id", "X-Akamai-Transformed", "X-Sucuri-ID"} {
		if resp.HasHeader(h) {
			return "an intermediary was detected (" + h + ")"
		}
	}
	server := strings.ToLower(resp.HeaderValue("Server"))
	for _, s := range []string{"cloudflare", "akamaighost", "awselb", "envoy"} {
		if strings.Contains(server, s) {
			return "an intermediary was detected (Server: " + sanitizeHeader(server) + ")"
		}
	}
	return ""
}

func normalizeContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

func sanitizeHeader(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	if len(v) > 64 {
		return v[:64]
	}
	return v
}

// randomToken returns a short random hex string for nonces and cache busting.
//
// It returns an error rather than a constant on failure: a fixed token would
// make both baseline probes hit the same path and turn cache busting into a
// no-op, silently disabling two discriminators.
func randomToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate a nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// transportCause maps a transport failure to a coverage cause.
func transportCause(err error) model.BlockedCause {
	if err == nil {
		return model.CauseNone
	}
	if strings.Contains(err.Error(), "out of scope") {
		return model.CauseOutOfScope
	}
	return model.CauseTransportError
}

// summarize renders an error briefly. The error has already been redacted by the
// HTTP client before it reaches evidence; this is for a ledger detail line.
func summarize(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

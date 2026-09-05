package outcome

import (
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func resp(status int, contentType, body string) *model.CapturedResponse {
	return &model.CapturedResponse{
		Status: status,
		Header: map[string][]string{"Content-Type": {contentType}},
		Body:   []byte(body),
	}
}

func TestStatusCodeBasics(t *testing.T) {
	cases := []struct {
		status int
		want   model.Outcome
	}{
		{200, model.OutcomeAllowed},
		{204, model.OutcomeAllowed},
		{401, model.OutcomeDenied},
		{403, model.OutcomeDenied},
		{429, model.OutcomeRateLimited},
		{500, model.OutcomeError},
		{503, model.OutcomeError},
		{302, model.OutcomeIndeterminate},
	}
	for _, c := range cases {
		got := Classify(resp(c.status, "application/json", "{}"), Signals{})
		if got.Outcome != c.want {
			t.Errorf("status %d = %s, want %s", c.status, got.Outcome, c.want)
		}
	}
}

// Returning 404 for a resource the caller may not see is a deliberate
// anti-enumeration pattern. Treating it as anything but a denial would report
// good security design as a finding.
func TestNotFoundIsTreatedAsDenial(t *testing.T) {
	got := Classify(resp(404, "application/json", `{"message":"not found"}`), Signals{})
	if got.Outcome != model.OutcomeDenied {
		t.Fatalf("404 = %s, want denied", got.Outcome)
	}
}

// A rejection before the authorization decision says nothing about access
// control, so it must not be scored either way.
func TestValidationFailureIsIndeterminate(t *testing.T) {
	for _, status := range []int{400, 422} {
		got := Classify(resp(status, "application/json", `{"message":"validation failed"}`), Signals{})
		if got.Outcome != model.OutcomeIndeterminate {
			t.Errorf("status %d = %s, want indeterminate", status, got.Outcome)
		}
	}
}

// Applications that return 200 with an error envelope are common. Reading the
// status alone would call these successes.
func TestSoftDenialWithSuccessStatus(t *testing.T) {
	cases := []string{
		`{"success":false,"message":"Unauthenticated."}`,
		`{"message":"Access denied"}`,
		`{"error":"forbidden"}`,
		`{"message":"Authentication required"}`,
	}
	for _, body := range cases {
		got := Classify(resp(200, "application/json", body), Signals{})
		if got.Outcome != model.OutcomeDenied {
			t.Errorf("body %s = %s, want denied", body, got.Outcome)
		}
	}
}

func TestSoftNotFoundWithSuccessStatus(t *testing.T) {
	got := Classify(resp(200, "application/json", `{"success":false,"message":"Record not found"}`), Signals{})
	if got.Outcome != model.OutcomeNotFound {
		t.Fatalf("= %s, want not_found", got.Outcome)
	}
}

// A genuine success must not be mistaken for a denial just because it contains
// a field named "message".
func TestGenuineSuccessIsNotMisreadAsDenial(t *testing.T) {
	got := Classify(resp(200, "application/json", `{"id":1,"message":"Welcome back"}`), Signals{})
	if got.Outcome != model.OutcomeAllowed {
		t.Fatalf("= %s, want allowed", got.Outcome)
	}
}

// The operator-supplied error code is the most reliable oracle when an
// application publishes one, and must beat the status code.
func TestOperatorErrorCodeOverridesStatus(t *testing.T) {
	sig := Signals{
		ErrorCodePointer: "/errorCode",
		DeniedCodes:      []string{"PERMISSION_DENIED"},
		NotFoundCodes:    []string{"RESOURCE_NOT_FOUND"},
	}
	denied := Classify(resp(200, "application/json", `{"errorCode":"PERMISSION_DENIED"}`), sig)
	if denied.Outcome != model.OutcomeDenied {
		t.Errorf("= %s, want denied via error code despite status 200", denied.Outcome)
	}
	if denied.Signal != "operator-error-code" {
		t.Errorf("signal = %s, want operator-error-code", denied.Signal)
	}
	nf := Classify(resp(200, "application/json", `{"errorCode":"RESOURCE_NOT_FOUND"}`), sig)
	if nf.Outcome != model.OutcomeNotFound {
		t.Errorf("= %s, want not_found via error code", nf.Outcome)
	}
}

func TestNestedErrorCodePointer(t *testing.T) {
	sig := Signals{ErrorCodePointer: "/error/code", DeniedCodes: []string{"DENIED"}}
	got := Classify(resp(200, "application/json", `{"error":{"code":"DENIED"}}`), sig)
	if got.Outcome != model.OutcomeDenied {
		t.Fatalf("= %s, want denied", got.Outcome)
	}
}

// A non-JSON body must not be parsed as an envelope.
func TestNonJSONBodyIsNotTreatedAsEnvelope(t *testing.T) {
	got := Classify(resp(200, "text/html", `<html>Access denied</html>`), Signals{})
	if got.Outcome != model.OutcomeAllowed {
		t.Fatalf("= %s; HTML must not be parsed as a JSON envelope", got.Outcome)
	}
}

func TestNilResponseIsAnError(t *testing.T) {
	if got := Classify(nil, Signals{}); got.Outcome != model.OutcomeError {
		t.Fatalf("= %s, want error", got.Outcome)
	}
}

func TestReasonIsAlwaysPopulated(t *testing.T) {
	for _, status := range []int{200, 302, 400, 401, 404, 429, 500, 599} {
		got := Classify(resp(status, "application/json", "{}"), Signals{})
		if got.Reason == "" {
			t.Errorf("status %d produced an empty reason", status)
		}
	}
}

// Malformed JSON must not panic or be over-interpreted.
func TestMalformedJSONIsHandled(t *testing.T) {
	for _, body := range []string{`{`, `[1,2,3`, "\x00\x01\x02", ``} {
		got := Classify(resp(200, "application/json", body), Signals{})
		if !got.Outcome.Valid() {
			t.Errorf("body %q produced an invalid outcome %q", body, got.Outcome)
		}
	}
}

// A numeric error code must survive lookup intact. Trimming trailing zeros would
// turn 100 into "1" and silently break every configured mapping — producing a
// false HIGH finding on an application that correctly denied the request.
func TestNumericErrorCodesAreNotMangled(t *testing.T) {
	cases := map[string]string{
		`{"code":403}`:  "403",
		`{"code":100}`:  "100",
		`{"code":1200}`: "1200",
		`{"code":10}`:   "10",
		`{"code":0}`:    "0",
		`{"code":1.5}`:  "1.5",
	}
	for body, want := range cases {
		sig := Signals{ErrorCodePointer: "/code", DeniedCodes: []string{want}}
		got := Classify(resp(200, "application/json", body), sig)
		if got.Outcome != model.OutcomeDenied {
			t.Errorf("body %s: outcome = %s, want denied via code %q", body, got.Outcome, want)
		}
	}
}

// A hostile target can bolt an inert denial field onto a data-bearing 200 and,
// if we believed it, have a missing control reported as holding. Ambiguity must
// be indeterminate — which blocks the row — never a denial, which reads as a pass.
func TestDenialAlongsidePayloadIsIndeterminate(t *testing.T) {
	cases := []string{
		`{"reason":"access denied","users":[{"ssn":"123-45-6789"}]}`,
		`{"message":"forbidden","id":1,"email":"a@b.test"}`,
		`{"success":false,"message":"unauthorized","records":[{"id":1}]}`,
	}
	for _, body := range cases {
		got := Classify(resp(200, "application/json", body), Signals{})
		if got.Outcome != model.OutcomeIndeterminate {
			t.Errorf("body %s: outcome = %s, want indeterminate (a target must not be able to "+
				"reclassify a payload-bearing success as a denial)", body, got.Outcome)
		}
	}
}

// A genuine soft denial carries no payload and must still classify as denied, or
// we regress into false positives on applications that return 200 with an error.
func TestPureDenialEnvelopeStillClassifiesAsDenied(t *testing.T) {
	cases := []string{
		`{"success":false,"message":"Unauthenticated."}`,
		`{"message":"Access denied","status":403,"path":"/api/x"}`,
		`{"error":"forbidden","timestamp":"2026-01-01T00:00:00Z"}`,
	}
	for _, body := range cases {
		got := Classify(resp(200, "application/json", body), Signals{})
		if got.Outcome != model.OutcomeDenied {
			t.Errorf("body %s: outcome = %s, want denied", body, got.Outcome)
		}
	}
}

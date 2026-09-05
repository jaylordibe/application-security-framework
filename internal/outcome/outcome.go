// Package outcome classifies an observed HTTP response into an access-control
// result.
//
// This looks trivial and is not. Evidence from two real applications:
//
//   - One returns 400 for a sign-in failure, 400 for a validation failure, 400
//     for a missing record, 403 only from five explicit authorization call
//     sites, and 200 for a record owned by a different user.
//   - The other returns 404 for a cross-tenant read (a deliberate and correct
//     pattern), 403 for a cross-tenant write, 400 for missing tenant context and
//     409 for an integrity refusal. Its reliable machine oracle is an errorCode
//     field, not the status code.
//
// An engine hard-coding "2xx means allowed, 401/403 mean denied" is wrong on
// both, in opposite directions. So classification is explicit, it accepts
// operator-supplied signals, and it is willing to answer "I could not tell".
//
// Signals come from operator configuration only. If a target could define its
// own oracle it could map allowed to denied and suppress every finding.
package outcome

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// Signals are the application-specific hints an operator supplies.
type Signals struct {
	// ErrorCodePointer is a JSON pointer to a stable error-code field.
	ErrorCodePointer string
	// DeniedCodes and NotFoundCodes map error-code values to outcomes.
	DeniedCodes   []string
	NotFoundCodes []string
}

// Classification is a decision together with the reason for it, so that a
// reviewer can audit why an outcome was assigned.
type Classification struct {
	Outcome model.Outcome
	// Reason is operator-facing and always populated.
	Reason string
	// Signal names which discriminator decided the result.
	Signal string
}

// denyVocabulary matches error envelopes that indicate refusal even when the
// status code is a success. Applications that return 200 with
// {"success": false} are common enough that ignoring this produces false
// positives on every one of them.
var denyVocabulary = []string{
	"unauthenticated", "unauthorized", "unauthorised", "forbidden",
	"permission denied", "access denied", "not permitted", "not allowed",
	"invalid token", "invalid credentials", "token expired", "expired token",
	"authentication required", "login required", "missing token",
	"insufficient privileges", "insufficient permissions",
}

// notFoundVocabulary matches not-found envelopes returned with a success status.
var notFoundVocabulary = []string{
	"not found", "does not exist", "no such", "resource_not_found",
}

// Classify decides what a response says about access.
//
// Order matters: operator-supplied signals win, then error envelopes carried in
// a success response, then status codes. Anything ambiguous becomes
// INDETERMINATE rather than a guess.
func Classify(resp *model.CapturedResponse, sig Signals) Classification {
	if resp == nil {
		return Classification{model.OutcomeError, "no response was received", "transport"}
	}

	if c, ok := classifyByOperatorSignal(resp, sig); ok {
		return c
	}
	if c, ok := classifyByEnvelope(resp); ok {
		return c
	}
	return classifyByStatus(resp)
}

// classifyByOperatorSignal applies the configured error-code mapping. This is the
// most reliable oracle when an application publishes one.
func classifyByOperatorSignal(resp *model.CapturedResponse, sig Signals) (Classification, bool) {
	if sig.ErrorCodePointer == "" || len(resp.Body) == 0 {
		return Classification{}, false
	}
	code, ok := jsonPointerString(resp.Body, sig.ErrorCodePointer)
	if !ok || code == "" {
		return Classification{}, false
	}
	for _, want := range sig.DeniedCodes {
		if strings.EqualFold(code, want) {
			return Classification{
				model.OutcomeDenied,
				"application error code " + sanitizeShort(code) + " is configured as a denial",
				"operator-error-code",
			}, true
		}
	}
	for _, want := range sig.NotFoundCodes {
		if strings.EqualFold(code, want) {
			return Classification{
				model.OutcomeNotFound,
				"application error code " + sanitizeShort(code) + " is configured as not-found",
				"operator-error-code",
			}, true
		}
	}
	return Classification{}, false
}

// classifyByEnvelope catches refusals delivered with a success status.
func classifyByEnvelope(resp *model.CapturedResponse) (Classification, bool) {
	if resp.Status < 200 || resp.Status > 299 || len(resp.Body) == 0 {
		return Classification{}, false
	}
	if !looksLikeJSON(resp) {
		return Classification{}, false
	}
	var envelope map[string]any
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		return Classification{}, false
	}
	// A response that both denies and carries payload is ambiguous, and the
	// ambiguity is attacker-controllable: a target can bolt one inert
	// "access denied" field onto a data-bearing 200 and have the missing control
	// reported as holding. Ambiguity must therefore be indeterminate — which
	// blocks the row — rather than a denial, which would read as a pass.
	carriesPayload := hasNonEnvelopeContent(envelope)

	if v, ok := envelope["success"]; ok {
		if b, isBool := v.(bool); isBool && !b {
			text := strings.ToLower(envelopeText(envelope))
			if carriesPayload {
				return Classification{model.OutcomeIndeterminate,
					"the body reports success:false but also carries substantive content, so it " +
						"is not clear whether access was refused or granted", "envelope"}, true
			}
			if matchesAny(text, notFoundVocabulary) {
				return Classification{model.OutcomeNotFound,
					"success:false with a not-found message despite a 2xx status", "envelope"}, true
			}
			return Classification{model.OutcomeDenied,
				"the body reports success:false despite a 2xx status", "envelope"}, true
		}
	}
	text := strings.ToLower(envelopeText(envelope))
	if text == "" {
		return Classification{}, false
	}
	if matchesAny(text, denyVocabulary) {
		if carriesPayload {
			return Classification{model.OutcomeIndeterminate,
				"the body carries a denial message alongside substantive content, so it is not " +
					"clear whether access was refused or granted", "envelope"}, true
		}
		return Classification{model.OutcomeDenied,
			"a 2xx response carries a denial message in its body and no other content", "envelope"}, true
	}
	if matchesAny(text, notFoundVocabulary) && !carriesPayload {
		return Classification{model.OutcomeNotFound,
			"a 2xx response carries a not-found message in its body", "envelope"}, true
	}
	return Classification{}, false
}

// envelopeKeys are the fields an error envelope is built from. Anything else in
// the object is substantive content.
var envelopeKeys = map[string]bool{
	"success": true, "message": true, "error": true, "errors": true, "detail": true,
	"details": true, "title": true, "errorcode": true, "error_code": true, "code": true,
	"reason": true, "status": true, "statuscode": true, "status_code": true,
	"timestamp": true, "path": true, "type": true, "instance": true, "traceid": true,
	"trace_id": true, "requestid": true, "request_id": true,
}

// hasNonEnvelopeContent reports whether the object carries fields beyond a
// recognised error envelope, or a non-empty nested payload.
func hasNonEnvelopeContent(envelope map[string]any) bool {
	for k, v := range envelope {
		if envelopeKeys[strings.ToLower(k)] {
			continue
		}
		switch t := v.(type) {
		case nil:
			continue
		case string:
			if t == "" {
				continue
			}
		case []any:
			if len(t) == 0 {
				continue
			}
		case map[string]any:
			if len(t) == 0 {
				continue
			}
		}
		return true
	}
	return false
}

// classifyByStatus is the fallback.
//
// 404 maps to denial, not to not-found. Returning 404 instead of 403 for a
// resource the caller may not see is a deliberate and correct pattern that
// prevents enumeration; treating it as a distinct non-denial would report good
// security design as a finding. The ambiguity it creates — a genuine missing
// resource looks identical — is handled by callers, which must not count an
// undisambiguated 404 as meaningful coverage.
func classifyByStatus(resp *model.CapturedResponse) Classification {
	s := resp.Status
	switch {
	case s == 401 || s == 403:
		return Classification{model.OutcomeDenied, "status indicates authentication or authorization failure", "status"}
	case s == 404:
		return Classification{model.OutcomeDenied,
			"status 404 is treated as a denial, because returning not-found for an " +
				"inaccessible resource is a legitimate anti-enumeration pattern", "status"}
	case s == 405 || s == 501:
		return Classification{model.OutcomeError, "the method is not supported by the target", "status"}
	case s == 429:
		return Classification{model.OutcomeRateLimited,
			"the target is rate limiting; later responses cannot be trusted as denials", "status"}
	case s == 408 || s == 503 || s == 502 || s == 504:
		return Classification{model.OutcomeError, "the target or an intermediary is unavailable", "status"}
	case s >= 200 && s <= 299:
		return Classification{model.OutcomeAllowed, "the request succeeded", "status"}
	case s >= 300 && s <= 399:
		return Classification{model.OutcomeIndeterminate,
			"a redirect does not say whether access was granted; the target must be " +
				"re-evaluated against scope and followed deliberately", "status"}
	case s == 400 || s == 422:
		return Classification{model.OutcomeIndeterminate,
			"the request was rejected before any authorization decision was necessarily " +
				"reached, so this says nothing about access control", "status"}
	case s >= 500:
		return Classification{model.OutcomeError, "the target returned a server error", "status"}
	default:
		return Classification{model.OutcomeIndeterminate, "the status code has no access-control meaning here", "status"}
	}
}

// looksLikeJSON reports whether the response claims to be JSON.
func looksLikeJSON(resp *model.CapturedResponse) bool {
	ct := strings.ToLower(resp.HeaderValue("Content-Type"))
	return strings.Contains(ct, "json")
}

// envelopeText gathers the message-bearing fields of an error envelope.
func envelopeText(envelope map[string]any) string {
	var parts []string
	for _, key := range []string{"message", "error", "detail", "title", "errorCode", "error_code", "code", "reason", "status"} {
		if v, ok := envelope[key]; ok {
			switch t := v.(type) {
			case string:
				parts = append(parts, t)
			case map[string]any:
				if m, ok := t["message"].(string); ok {
					parts = append(parts, m)
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

func matchesAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// jsonPointerString resolves a JSON pointer to a scalar rendered as a string.
// Only object traversal is supported, which is all an error-code field needs.
func jsonPointerString(body []byte, pointer string) (string, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return "", false
	}
	var cur any
	if err := json.Unmarshal(body, &cur); err != nil {
		return "", false
	}
	for _, rawToken := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = obj[token]
		if !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case float64:
		// Numeric error codes are common. Trimming trailing zeros here would
		// turn 100 into "1" and silently break every configured mapping.
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// sanitizeShort trims and bounds a target-controlled string for use in a reason.
func sanitizeShort(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

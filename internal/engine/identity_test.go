package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
)

// The ledger gained a second dimension in M1. The headline counts must keep
// meaning "checks against operations", or configuring an identity would inflate
// the number of checks a run claims to have executed.
func TestCountersIgnoreTheIdentityDimension(t *testing.T) {
	res := Result{Coverage: []model.CoverageEntry{
		{Dimension: DimensionOperation, Disposition: model.DispositionExecuted},
		{Dimension: DimensionOperation, Disposition: model.DispositionBlocked},
		{Dimension: DimensionIdentity, Disposition: model.DispositionExecuted},
		{Dimension: DimensionIdentity, Disposition: model.DispositionBlocked},
	}}
	if got := res.ExecutedCount(); got != 1 {
		t.Errorf("ExecutedCount = %d, want 1", got)
	}
	if got := res.BlockedCount(); got != 1 {
		t.Errorf("BlockedCount = %d, want 1", got)
	}
}

func TestIdentityCoverageRows(t *testing.T) {
	past := time.Unix(1000, 0)
	tests := []struct {
		name        string
		status      identity.Status
		disposition model.Disposition
		cause       model.BlockedCause
		mentions    string
	}{
		{
			name:        "credential could not be resolved",
			status:      identity.Status{ID: "admin", Usable: false, Source: "environment variable X", Problem: "X is not set"},
			disposition: model.DispositionBlocked,
			cause:       model.CauseMissingIdentity,
			mentions:    "environment variable X",
		},
		{
			name:        "identity rejected by the target",
			status:      identity.Status{ID: "admin", Usable: true, Monitored: true, Liveness: identity.LivenessBad, Problem: "canary returned 401"},
			disposition: model.DispositionBlocked,
			cause:       model.CauseAuthenticationFailed,
			mentions:    "not trustworthy",
		},
		{
			name:        "identity confirmed live",
			status:      identity.Status{ID: "admin", Usable: true, Monitored: true, Liveness: identity.LivenessGood, LastGood: past},
			disposition: model.DispositionExecuted,
			mentions:    "confirmed this identity authenticates",
		},
		{
			name:        "no canary configured",
			status:      identity.Status{ID: "admin", Usable: true, Monitored: false, Liveness: identity.LivenessUnknown},
			disposition: model.DispositionUntested,
			cause:       model.CauseNoOracle,
			mentions:    "expiry during the run could not be detected",
		},
		{
			name:        "canary configured but never completed",
			status:      identity.Status{ID: "admin", Usable: true, Monitored: true, Liveness: identity.LivenessUnknown},
			disposition: model.DispositionBlocked,
			cause:       model.CauseAuthenticationFailed,
			mentions:    "not known whether this identity can authenticate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := identityCoverage([]identity.Status{tc.status})
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			r := rows[0]
			if r.Dimension != DimensionIdentity {
				t.Errorf("dimension = %q, want %q", r.Dimension, DimensionIdentity)
			}
			if r.Disposition != tc.disposition {
				t.Errorf("disposition = %s, want %s", r.Disposition, tc.disposition)
			}
			if r.Cause != tc.cause {
				t.Errorf("cause = %q, want %q", r.Cause, tc.cause)
			}
			if !strings.Contains(r.Detail, tc.mentions) {
				t.Errorf("detail %q does not mention %q", r.Detail, tc.mentions)
			}
		})
	}
}

// Temporal validity: a control issued inside the uncertainty window was
// produced by a credential that may already have expired.
func TestInvalidateExpiredControls(t *testing.T) {
	lastGood := time.Unix(1000, 0)
	firstBad := time.Unix(2000, 0)
	bad := identity.Status{
		ID: "admin", Usable: true, Monitored: true,
		Liveness: identity.LivenessBad, LastGood: lastGood, FirstBad: firstBad,
	}

	newResult := func() *Result {
		return &Result{
			Coverage: []model.CoverageEntry{
				{Dimension: DimensionOperation, Subject: "GET /a", CheckID: "c",
					Disposition: model.DispositionExecuted, Detail: "ran"},
				{Dimension: DimensionOperation, Subject: "GET /b", CheckID: "c",
					Disposition: model.DispositionExecuted, Detail: "ran"},
			},
			Findings: []model.Finding{
				{OperationID: "GET /a", CheckID: "c", State: model.StateConfirmed, Confidence: model.ConfidenceHigh},
				{OperationID: "GET /b", CheckID: "c", State: model.StateConfirmed, Confidence: model.ConfidenceHigh},
			},
		}
	}

	t.Run("control inside the window is withdrawn", func(t *testing.T) {
		res := newResult()
		invalidateExpiredControls(res, []controlUse{
			{subject: "GET /a", checkID: "c", identityID: "admin", at: time.Unix(1500, 0)},
		}, []identity.Status{bad})

		if res.Coverage[0].Disposition != model.DispositionBlocked {
			t.Errorf("row = %s, want blocked", res.Coverage[0].Disposition)
		}
		if res.Coverage[0].Cause != model.CauseAuthenticationFailed {
			t.Errorf("cause = %s, want authentication_failed", res.Coverage[0].Cause)
		}
		if res.Findings[0].State != model.StateSuspected {
			t.Errorf("finding = %s, want suspected", res.Findings[0].State)
		}
		if res.Findings[0].Confidence != model.ConfidenceMedium {
			t.Errorf("confidence = %s, want medium", res.Findings[0].Confidence)
		}
		if len(res.Findings[0].Verification.Unavailable) == 0 {
			t.Error("the withdrawal was not explained")
		}
		// The finding survives: the anonymous observation behind it never
		// involved the credential, so deleting it would hide a real bypass.
		if len(res.Findings) != 2 {
			t.Errorf("findings = %d, want 2; a withdrawal must not delete a finding", len(res.Findings))
		}

		// The untouched row is unaffected.
		if res.Coverage[1].Disposition != model.DispositionExecuted {
			t.Error("a row that used no control was withdrawn")
		}
		if res.Findings[1].State != model.StateConfirmed {
			t.Error("a finding that used no control was demoted")
		}
	})

	t.Run("control before the last good canary is trusted", func(t *testing.T) {
		res := newResult()
		invalidateExpiredControls(res, []controlUse{
			{subject: "GET /a", checkID: "c", identityID: "admin", at: time.Unix(500, 0)},
		}, []identity.Status{bad})

		if res.Coverage[0].Disposition != model.DispositionBlocked &&
			res.Findings[0].State != model.StateConfirmed {
			t.Error("a control confirmed good by a later canary was withdrawn anyway")
		}
		if res.Findings[0].State != model.StateConfirmed {
			t.Errorf("finding = %s, want confirmed; the canary vouched for the credential after "+
				"this control ran", res.Findings[0].State)
		}
	})

	t.Run("a live identity withdraws nothing", func(t *testing.T) {
		res := newResult()
		good := identity.Status{ID: "admin", Usable: true, Monitored: true,
			Liveness: identity.LivenessGood, LastGood: lastGood}
		invalidateExpiredControls(res, []controlUse{
			{subject: "GET /a", checkID: "c", identityID: "admin", at: time.Unix(1500, 0)},
		}, []identity.Status{good})

		if res.Findings[0].State != model.StateConfirmed {
			t.Error("a live identity's corroboration was withdrawn")
		}
	})

	t.Run("an identity that was never good withdraws everything it touched", func(t *testing.T) {
		res := newResult()
		neverGood := identity.Status{ID: "admin", Usable: true, Monitored: true,
			Liveness: identity.LivenessBad, FirstBad: firstBad}
		invalidateExpiredControls(res, []controlUse{
			{subject: "GET /a", checkID: "c", identityID: "admin", at: time.Unix(500, 0)},
		}, []identity.Status{neverGood})

		if res.Findings[0].State != model.StateSuspected {
			t.Errorf("finding = %s, want suspected", res.Findings[0].State)
		}
		if !strings.Contains(strings.Join(res.Findings[0].Verification.Unavailable, " "), "never confirmed good") {
			t.Errorf("the absence of any good observation is not stated: %v",
				res.Findings[0].Verification.Unavailable)
		}
	})
}

// Nothing about identities may change behaviour when none is configured.
func TestRunWithoutIdentitiesAddsNoRows(t *testing.T) {
	c := &stubCheck{id: "stub", applies: true, result: check.Result{
		Disposition: model.DispositionExecuted, Detail: "ok",
	}}
	res, err := Run(context.Background(), baseOptions([]model.Operation{op("GET", "/a")}, []Check{c}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, e := range res.Coverage {
		if e.Dimension != DimensionOperation {
			t.Errorf("unexpected ledger dimension %q with no identity configured", e.Dimension)
		}
	}
	if res.Identities != nil {
		t.Errorf("identities reported with none configured: %+v", res.Identities)
	}
}

// probeIdentities must tolerate a nil set, which is the ordinary no-identity
// path, and must not panic on a cancelled context.
func TestProbeIdentitiesHandlesNilAndCancellation(t *testing.T) {
	probeIdentities(context.Background(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probeIdentities(ctx, nil)
}

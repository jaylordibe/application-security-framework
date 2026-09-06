package check

import (
	"context"
	"fmt"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/outcome"
	"github.com/jaylordibe/application-security-framework/internal/resource"
)

// A write is confirmed by observing the owner's view of the resource change,
// never by the status the write returned.
//
// This is not pedantry. An application with no authorization on its update path
// frequently still returns 200 for a write it silently discarded — because the
// record was filtered out of the query the update ran against, because a
// validation layer dropped unknown fields, or because the handler returns its
// input rather than the stored row. Confirming on the status alone reports those
// as unauthorized writes, and every one of them is wrong.
//
// So the sequence is: read as the owner, write as the non-owner, read as the
// owner again, and compare the two owner-side reads. Only a change visible to
// the owner proves the write landed.

// runMutation performs the read-write-read sequence.
func (c CrossOwner) runMutation(ctx context.Context, p ResourcePlan) Result {
	var exchanges []model.Exchange
	uses := []ControlUse{}

	block := func(cause model.BlockedCause, detail string) Result {
		return Result{
			Disposition: model.DispositionBlocked, Cause: cause, Detail: detail,
			Exchanges: exchanges, ControlsUsed: uses,
		}
	}

	if cause, why := identitiesUsable(p); cause != model.CauseNone {
		return block(cause, why)
	}
	if p.ReadURL == "" {
		return block(model.CauseNoOracle, fmt.Sprintf(
			"no readable operation addresses fixture %q, so an unauthorized write could not be "+
				"verified by observing the owner's view of the resource. A write is never confirmed "+
				"from its own response status", p.Fixture.ID))
	}
	if p.Fixture.Mutation == nil {
		return block(model.CauseNoOracle, "no mutation values are configured for this fixture")
	}
	body, err := mutationBody(p.Fixture.Mutation.Values)
	if err != nil {
		return block(model.CauseNoOracle, "the configured mutation values could not be encoded: "+err.Error())
	}

	// Step 1: the owner's view before the write.
	beforeEx, err := p.Owner.Do(ctx, p.ReadOperation.Method, p.ReadURL, probeHeaders())
	if beforeEx.Request.URL != "" {
		exchanges = append(exchanges, beforeEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || beforeEx.Response == nil {
		return block(transportCause(err), "the owner's before-state could not be read, so a change "+
			"could not have been detected: "+summarize(err))
	}
	if cls := outcome.Classify(beforeEx.Response, c.Signals); cls.Outcome != model.OutcomeAllowed {
		return block(model.CauseMissingResource, fmt.Sprintf(
			"the owner %s could not read fixture %q before the write (%s), so it is not a valid "+
				"ownership fixture and no change could be attributed", p.Owner.ID(), p.Fixture.ID, cls.Reason))
	}

	// Step 2: the unauthorized write.
	attackerEx, err := p.Attacker.DoWithBody(ctx, p.Operation.Method, p.URL, map[string][]string{
		"Accept":        {"application/json, */*"},
		"Content-Type":  {"application/json"},
		"Cache-Control": {"no-cache"},
	}, body)
	if attackerEx.Request.URL != "" {
		exchanges = append(exchanges, attackerEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Attacker.ID(), At: c.now()})
	if err != nil || attackerEx.Response == nil {
		return block(transportCause(err), "the cross-owner write could not be completed: "+summarize(err))
	}
	writeCls := outcome.Classify(attackerEx.Response, c.Signals)

	// Step 3: the owner's view after the write.
	afterEx, err := p.Owner.Do(ctx, p.ReadOperation.Method, p.ReadURL, probeHeaders())
	if afterEx.Request.URL != "" {
		exchanges = append(exchanges, afterEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || afterEx.Response == nil {
		return block(transportCause(err), "the owner's after-state could not be read, so it is not "+
			"known whether the write landed. The resource may have been modified: "+summarize(err))
	}
	if cls := outcome.Classify(afterEx.Response, c.Signals); cls.Outcome != model.OutcomeAllowed {
		return block(model.CauseIndeterminateOutcome, fmt.Sprintf(
			"the owner could read fixture %q before the write and not after (%s). Something changed, "+
				"but it cannot be established that the non-owner's write caused it — the resource may "+
				"equally have been removed by the application or by another actor",
			p.Fixture.ID, cls.Reason))
	}

	applied := mutationApplied(beforeEx.Response, afterEx.Response, p.Fixture.Mutation.Values)

	if !applied.Changed {
		// The write did not land. If it nevertheless returned success, that is
		// worth saying plainly: it is exactly the response that would have been
		// reported as a vulnerability by a status-only check.
		detail := fmt.Sprintf("the cross-owner write by %s did not change fixture %q as its owner "+
			"sees it, so the authorization boundary held", p.Attacker.ID(), p.Fixture.ID)
		if writeCls.Outcome == model.OutcomeAllowed {
			detail += fmt.Sprintf(". The write reported success (%s) but the owner's view is "+
				"unchanged, so the success was not real — confirming on the status alone would "+
				"have been a false positive", writeCls.Reason)
		}
		return Result{
			Disposition: model.DispositionExecuted, Detail: detail,
			Exchanges: exchanges, ControlsUsed: uses,
		}
	}

	// The owner's view changed. Restore it if we can, and say what happened
	// either way.
	restore := c.restore(ctx, p, applied, &exchanges, &uses)

	if p.Fixture.CrossOwnerAccess == resource.CrossOwnerAllowed {
		return Result{
			Disposition: model.DispositionExecuted,
			Detail: fmt.Sprintf("fixture %q is declared as legitimately shared, so the write by %s "+
				"is expected behaviour and is not a finding. %s",
				p.Fixture.ID, p.Attacker.ID(), restore.detail),
			Exchanges: exchanges, ControlsUsed: uses,
		}
	}

	finding := &model.Finding{
		CheckID:         CrossOwnerWriteID,
		Title:           "A resource is modifiable by an identity that does not own it",
		State:           model.StateConfirmed,
		Severity:        model.SeverityCritical,
		Confidence:      model.ConfidenceHigh,
		CWE:             []string{"CWE-639", "CWE-284"},
		OWASP:           []string{"API1:2023 Broken Object Level Authorization"},
		OperationID:     p.Operation.ID,
		IdentityID:      p.Attacker.ID(),
		ResourceID:      p.Fixture.ID,
		OwnerIdentityID: p.Fixture.Owner,
		Expected: fmt.Sprintf("fixture %q is owned by %s and is declared as not accessible to other "+
			"identities, so a write by %s should have been refused and should have changed nothing",
			p.Fixture.ID, p.Owner.ID(), p.Attacker.ID()),
		Actual: fmt.Sprintf("%s modified a resource owned by %s. %s",
			p.Attacker.ID(), p.Owner.ID(), applied.Detail),
		Verification: model.VerificationRecord{
			Strategy: "owner-read-then-cross-owner-write-then-owner-reread",
			Steps: []model.VerificationStep{
				{Name: "owner-control-established", Passed: true,
					Detail: "the owner " + p.Owner.ID() + " could read the resource before the write"},
				{Name: "non-owner-identity-live", Passed: true,
					Detail: "the non-owner " + p.Attacker.ID() + " authenticates successfully"},
				{Name: "owner-visible-state-changed", Passed: true, Detail: applied.Detail},
				{Name: "change-matches-written-values", Passed: true,
					Detail: "the owner now sees the values the non-owner wrote, so the change is " +
						"attributable to that request rather than to unrelated activity"},
			},
			Performed: true,
			Result: "an identity that does not own the resource changed it, and the change is " +
				"visible to the owner",
		},
		Remediation: "Scope the update path by the calling identity, not by the identifier alone. " +
			"Returning success for a write that was silently discarded is also worth correcting, " +
			"because it hides the failure from legitimate clients.",
		Reproduction: []string{
			fmt.Sprintf("%s %s as %s (the owner) — note the current state", p.ReadOperation.Method, p.ReadURL, p.Owner.ID()),
			fmt.Sprintf("%s %s as %s (not the owner) with the configured values", p.Operation.Method, p.URL, p.Attacker.ID()),
			fmt.Sprintf("%s %s as %s again — the state has changed", p.ReadOperation.Method, p.ReadURL, p.Owner.ID()),
		},
	}

	return Result{
		Disposition: model.DispositionExecuted,
		Detail: fmt.Sprintf("a non-owner (%s) changed fixture %q owned by %s, confirmed by the owner's "+
			"own view of the resource. %s", p.Attacker.ID(), p.Fixture.ID, p.Owner.ID(), restore.detail),
		Finding:      finding,
		Exchanges:    exchanges,
		ControlsUsed: uses,
		ToolFailure:  restore.toolFailure,
	}
}

// restoreOutcome is what happened when we tried to put the resource back.
type restoreOutcome struct {
	detail string
	// toolFailure is set when the resource was left modified. It is surfaced as
	// run-level tool state rather than buried in a detail string, because a
	// failed cleanup means somebody's data is still wrong.
	toolFailure string
}

// restore attempts to put the mutated fields back as the owner.
//
// This is explicitly best-effort and its outcome is always reported. Rollback is
// not promised: the application may reject the write, may have recomputed
// dependent fields, or may not accept the same shape on the way back. What is
// promised is that the report says which of those happened, because silently
// leaving a resource modified is the kind of side effect that makes a team stop
// running a security tool.
func (c CrossOwner) restore(
	ctx context.Context,
	p ResourcePlan,
	applied mutationResult,
	exchanges *[]model.Exchange,
	uses *[]ControlUse,
) restoreOutcome {
	if len(applied.Before) == 0 {
		return restoreOutcome{
			detail: "The original values of the changed fields were not present in the owner's " +
				"before-state, so no restoration was attempted and the resource is left modified.",
			toolFailure: fmt.Sprintf("fixture %q was modified by the cross-owner write check and could "+
				"not be restored: the original values were not observable", p.Fixture.ID),
		}
	}
	body, err := mutationBody(applied.Before)
	if err != nil {
		return restoreOutcome{
			detail:      "The original values could not be encoded, so the resource is left modified.",
			toolFailure: fmt.Sprintf("fixture %q was modified and could not be restored: %v", p.Fixture.ID, err),
		}
	}

	ex, err := p.Owner.DoWithBody(ctx, p.Operation.Method, p.URL, map[string][]string{
		"Accept":       {"application/json, */*"},
		"Content-Type": {"application/json"},
	}, body)
	if ex.Request.URL != "" {
		*exchanges = append(*exchanges, ex)
	}
	*uses = append(*uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || ex.Response == nil {
		return restoreOutcome{
			detail: "Restoration as the owner could not be completed, so the resource is left modified.",
			toolFailure: fmt.Sprintf("fixture %q was modified by the cross-owner write check and the "+
				"restoring request failed: %s", p.Fixture.ID, summarize(err)),
		}
	}

	// Confirm the restoration rather than assuming it.
	verifyEx, verr := p.Owner.Do(ctx, p.ReadOperation.Method, p.ReadURL, probeHeaders())
	if verifyEx.Request.URL != "" {
		*exchanges = append(*exchanges, verifyEx)
	}
	*uses = append(*uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if verr != nil || verifyEx.Response == nil {
		return restoreOutcome{
			detail: "Restoration was attempted but could not be verified, so the resource may still be modified.",
			toolFailure: fmt.Sprintf("fixture %q was modified and the restoration could not be "+
				"verified: %s", p.Fixture.ID, summarize(verr)),
		}
	}
	back := valuesPresent(verifyEx.Response, applied.Before)
	if !back {
		return restoreOutcome{
			detail: "Restoration was attempted as the owner but the original values are not back, so " +
				"the resource is left modified.",
			toolFailure: fmt.Sprintf("fixture %q was modified by the cross-owner write check and the "+
				"restoration did not take effect", p.Fixture.ID),
		}
	}
	return restoreOutcome{
		detail: "The changed fields were restored to their original values as the owner, and the " +
			"restoration was verified by re-reading the resource.",
	}
}

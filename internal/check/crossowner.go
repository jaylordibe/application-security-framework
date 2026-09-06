package check

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/outcome"
	"github.com/jaylordibe/application-security-framework/internal/resource"
)

// CrossOwnerReadID identifies the cross-owner read check.
const CrossOwnerReadID = "cross-owner-resource-read"

// CrossOwnerWriteID identifies the cross-owner mutation check.
const CrossOwnerWriteID = "cross-owner-resource-write"

// ResourcePlan is one unit of cross-owner work: one operation, against one
// fixture, with one owner and one non-owner.
//
// The engine builds these because planning is where combinatorial growth would
// happen and the engine is where that has to be bounded. The check executes one
// and knows nothing about how many there are.
type ResourcePlan struct {
	Operation model.Operation
	Fixture   resource.Fixture
	// URL is the operation's address with the fixture's values already bound
	// and encoded. The check never builds URLs itself.
	URL string
	// Owner is the identity that owns the fixture.
	Owner *identity.Control
	// Attacker is the identity that must not be able to reach it.
	Attacker *identity.Control
	// FrameworkControl describes an authorization control a framework adapter
	// found on this operation, or is empty when no adapter said anything.
	//
	// It never decides anything. A framework declaring a control is an
	// expectation; whether the control works is what the probe establishes. What
	// it does is sharpen the finding: a non-owner reaching a resource the
	// application itself marks as controlled is a control that does not work,
	// which is a different and more actionable statement than an absent one.
	FrameworkControl string
	// ReadOperation and ReadURL address the same resource for reading. They are
	// set only for mutation plans, where the state change has to be observed
	// independently of the response that claimed it.
	ReadOperation model.Operation
	ReadURL       string
	// Mutate is true when this plan attempts a state change rather than a read.
	Mutate bool
}

// Subject renders the ledger subject for a plan.
func (p ResourcePlan) Subject() string { return p.Operation.ID }

// CrossOwner tests whether a non-owner can reach or change a resource that
// belongs to somebody else.
//
// This is CWE-639 / OWASP API1, the largest class of real API findings. The
// technique is trivial — ask for another person's record — and the difficulty is
// entirely in knowing what the answer means. Four things have to be true before
// a non-owner's 200 means anything at all: the resource exists, the owner can
// reach it, the non-owner's credential works, and the resource is still there
// afterwards. Skip any of them and a 404 from a deleted record reads as a
// working access control.
type CrossOwner struct {
	Signals outcome.Signals
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
}

func (c CrossOwner) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Metadata describes the check for one plan.
func (c CrossOwner) Metadata() Metadata {
	return Metadata{
		ID:    CrossOwnerReadID,
		Title: "A resource is readable by an identity that does not own it",
		CWE:   []string{"CWE-639", "CWE-284"},
		OWASP: []string{"API1:2023 Broken Object Level Authorization"},
	}
}

// WriteMetadata describes the mutation variant.
func (c CrossOwner) WriteMetadata() Metadata {
	return Metadata{
		ID:    CrossOwnerWriteID,
		Title: "A resource is modifiable by an identity that does not own it",
		CWE:   []string{"CWE-639", "CWE-284"},
		OWASP: []string{"API1:2023 Broken Object Level Authorization"},
	}
}

// MetadataFor returns the metadata matching a plan.
func (c CrossOwner) MetadataFor(p ResourcePlan) Metadata {
	if p.Mutate {
		return c.WriteMetadata()
	}
	return c.Metadata()
}

// probeHeaders are sent on every request this check makes. Caching is defeated
// so that the owner's response cannot be replayed to the non-owner by an
// intermediary, which would make the two trivially identical.
func probeHeaders() map[string][]string {
	return map[string][]string{
		"Accept":        {"application/json, */*"},
		"Cache-Control": {"no-cache"},
		"Pragma":        {"no-cache"},
	}
}

// RunResource executes one cross-owner unit.
func (c CrossOwner) RunResource(ctx context.Context, p ResourcePlan) Result {
	if p.Mutate {
		return c.runMutation(ctx, p)
	}
	return c.runRead(ctx, p)
}

// identitiesUsable refuses the unit unless both identities can authenticate.
//
// This gate is the difference between a security result and a coin flip. A dead
// non-owner credential produces 401 on every request, which is indistinguishable
// from a correctly enforced boundary — so an assessment that skipped this check
// would report "cross-owner access denied" for an application that has no access
// control at all.
func identitiesUsable(p ResourcePlan) (model.BlockedCause, string) {
	if p.Owner == nil || p.Attacker == nil {
		return model.CauseMissingIdentity, "a cross-owner test needs both an owner identity and a " +
			"non-owner identity, and one of them is not configured"
	}
	if ok, cause, why := p.Owner.Usable(); !ok {
		return cause, "the owner identity " + p.Owner.ID() + " cannot be used, so ownership of the " +
			"fixture could not be established: " + why
	}
	if ok, cause, why := p.Attacker.Usable(); !ok {
		return cause, "the non-owner identity " + p.Attacker.ID() + " cannot be used, so its denial " +
			"would be an authentication failure rather than an access-control decision: " + why
	}
	return model.CauseNone, ""
}

// runRead performs owner control, the cross-owner probe, and the owner re-check.
func (c CrossOwner) runRead(ctx context.Context, p ResourcePlan) Result {
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

	// Step 1: the owner control. A resource its owner cannot fetch is not a
	// valid ownership fixture for this operation, and probing it as somebody
	// else would measure nothing.
	ownerEx, err := p.Owner.Do(ctx, p.Operation.Method, p.URL, probeHeaders())
	if ownerEx.Request.URL != "" {
		exchanges = append(exchanges, ownerEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || ownerEx.Response == nil {
		return block(transportCause(err), "the owner control request could not be completed, so "+
			"ownership of the fixture was never established: "+summarize(err))
	}
	ownerCls := outcome.Classify(ownerEx.Response, c.Signals)
	if ownerCls.Outcome != model.OutcomeAllowed {
		p.Owner.NoteSuspicious(ctx)
		return block(model.CauseMissingResource, fmt.Sprintf(
			"the owner %s could not read fixture %q through this operation (%s), so it is not a valid "+
				"ownership fixture here. A non-owner's response would say nothing about access control: "+
				"a denial could simply mean the resource does not exist",
			p.Owner.ID(), p.Fixture.ID, ownerCls.Reason))
	}
	if cache := cacheFingerprint(ownerEx.Response); cache != "" {
		return block(model.CauseIndeterminateOutcome, "the owner control was served from a cache ("+
			cache+"), so it does not demonstrate the origin's behaviour and could be replayed to the "+
			"non-owner by the same intermediary")
	}

	// Step 2: the cross-owner probe.
	attackerEx, err := p.Attacker.Do(ctx, p.Operation.Method, p.URL, probeHeaders())
	if attackerEx.Request.URL != "" {
		exchanges = append(exchanges, attackerEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Attacker.ID(), At: c.now()})
	if err != nil || attackerEx.Response == nil {
		return block(transportCause(err), "the cross-owner request could not be completed: "+summarize(err))
	}
	attackerCls := outcome.Classify(attackerEx.Response, c.Signals)

	// Step 3: the owner re-check.
	//
	// Without this, a resource deleted between step 1 and step 2 makes the
	// non-owner's 404 look like an enforced boundary, and the run reports that
	// an untested control works. That is a false negative, and a false negative
	// in a security tool is worse than a false positive because nobody looks at
	// a clean report.
	recheckEx, err := p.Owner.Do(ctx, p.Operation.Method, p.URL, probeHeaders())
	if recheckEx.Request.URL != "" {
		exchanges = append(exchanges, recheckEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || recheckEx.Response == nil {
		return block(transportCause(err), "the owner re-check could not be completed, so it is not "+
			"known whether the resource still existed when the non-owner asked for it: "+summarize(err))
	}
	if recheckCls := outcome.Classify(recheckEx.Response, c.Signals); recheckCls.Outcome != model.OutcomeAllowed {
		return block(model.CauseMissingResource, fmt.Sprintf(
			"the owner could read fixture %q before the cross-owner request and not after (%s). The "+
				"resource changed underneath the test, so the non-owner's response cannot be "+
				"interpreted: a denial may only mean the resource had already gone",
			p.Fixture.ID, recheckCls.Reason))
	}

	// The fixture is valid, both identities work, and the resource was present
	// throughout. Now the answer means something.
	if p.Fixture.CrossOwnerAccess == resource.CrossOwnerAllowed {
		return Result{
			Disposition: model.DispositionExecuted,
			Detail: fmt.Sprintf("fixture %q is declared as legitimately shared, so the non-owner %s "+
				"reaching it (%s) is expected behaviour and is not a finding",
				p.Fixture.ID, p.Attacker.ID(), attackerCls.Outcome),
			Exchanges: exchanges, ControlsUsed: uses,
		}
	}

	switch attackerCls.Outcome {
	case model.OutcomeDenied, model.OutcomeNotFound:
		// A not-found for a resource the caller may not see is a legitimate and
		// deliberate anti-enumeration pattern. One of this project's own
		// reference applications scopes every query by owner precisely so that
		// another user's record "is never loaded and the caller gets a 404".
		// Reporting that as a vulnerability would be reporting good design as a
		// bug.
		return Result{
			Disposition: model.DispositionExecuted,
			Detail: fmt.Sprintf("the cross-owner boundary held: %s owns fixture %q and could read it "+
				"both before and after, and %s was refused (%s). The refusal is a real access-control "+
				"decision because the resource demonstrably existed and the non-owner's credential "+
				"demonstrably works",
				p.Owner.ID(), p.Fixture.ID, p.Attacker.ID(), attackerCls.Reason),
			Exchanges: exchanges, ControlsUsed: uses,
		}
	case model.OutcomeRateLimited:
		return block(model.CauseRateLimited, "the target is rate limiting, so a refusal cannot be "+
			"distinguished from a block")
	case model.OutcomeError:
		return block(model.CauseTransportError, "the target returned an error to the cross-owner "+
			"request: "+attackerCls.Reason)
	case model.OutcomeIndeterminate:
		return block(model.CauseIndeterminateOutcome, "the cross-owner response could not be "+
			"classified as access granted or refused: "+attackerCls.Reason)
	}

	// The non-owner was not refused. Decide how much can be proven.
	return c.judgeUnauthorizedRead(p, ownerEx, attackerEx, exchanges, uses, attackerCls)
}

// judgeUnauthorizedRead decides between confirmed and suspected.
func (c CrossOwner) judgeUnauthorizedRead(
	p ResourcePlan,
	ownerEx, attackerEx model.Exchange,
	exchanges []model.Exchange,
	uses []ControlUse,
	attackerCls outcome.Classification,
) Result {
	steps := []model.VerificationStep{
		{Name: "owner-control-established", Passed: true,
			Detail: "the owner " + p.Owner.ID() + " read the resource before and after the probe"},
		{Name: "non-owner-identity-live", Passed: true,
			Detail: "the non-owner " + p.Attacker.ID() + " authenticates successfully, so its access " +
				"was not an authentication artefact"},
		{Name: "non-owner-access-granted", Passed: true, Detail: attackerCls.Reason},
	}
	var unavailable []string

	eq := materiallyEquivalent(ownerEx.Response, attackerEx.Response)
	steps = append(steps, model.VerificationStep{
		Name: "materially-equivalent-to-owner-response", Passed: eq.Equivalent, Detail: eq.Reason,
	})

	// Shape agreement is necessary and not sufficient: two different records of
	// the same type have the same shape, so an application that quietly returns
	// the caller's own resource instead would match perfectly.
	ev := sameResource(ownerEx.Response, attackerEx.Response, p.Fixture.Values)
	steps = append(steps, model.VerificationStep{
		Name: "same-resource-as-owner-received", Passed: ev.Proven, Detail: ev.Reason,
	})

	if p.FrameworkControl != "" {
		// Corroboration, not proof. The step is recorded whatever the outcome,
		// because "the application says it controls this" is context a reader
		// needs either way.
		steps = append(steps, model.VerificationStep{
			Name: "framework-declares-an-authorization-control", Passed: true,
			Detail: "a framework adapter found that this operation is subject to " +
				p.FrameworkControl + ". That is an expectation the application states about " +
				"itself, not evidence that it is enforced — which is what this check tests",
		})
	}

	if cache := cacheFingerprint(attackerEx.Response); cache != "" {
		steps = append(steps, model.VerificationStep{
			Name: "not-served-from-cache", Passed: false, Detail: cache,
		})
		unavailable = append(unavailable, "cross-owner-response: the response was served from a cache ("+
			cache+"), so it may be the owner's response replayed by an intermediary rather than the "+
			"application's own answer to the non-owner")
	} else {
		steps = append(steps, model.VerificationStep{
			Name: "not-served-from-cache", Passed: true, Detail: "no cache-hit indicators present",
		})
	}

	confirmed := eq.Equivalent && ev.Proven && cacheFingerprint(attackerEx.Response) == ""
	if !eq.Equivalent {
		unavailable = append(unavailable, "owner-comparison: "+eq.Reason)
	}
	if !ev.Proven {
		unavailable = append(unavailable, "resource-identity: "+ev.Reason)
	}

	state := model.StateSuspected
	confidence := model.ConfidenceMedium
	result := "a non-owner was not refused, but the response could not be shown to be the owner's resource"
	if confirmed {
		state = model.StateConfirmed
		confidence = model.ConfidenceHigh
		result = "a non-owner received the owner's resource itself"
	}

	finding := &model.Finding{
		CheckID:         CrossOwnerReadID,
		Title:           "A resource is readable by an identity that does not own it",
		State:           state,
		Severity:        model.SeverityHigh,
		Confidence:      confidence,
		CWE:             []string{"CWE-639", "CWE-284"},
		OWASP:           []string{"API1:2023 Broken Object Level Authorization"},
		OperationID:     p.Operation.ID,
		IdentityID:      p.Attacker.ID(),
		ResourceID:      p.Fixture.ID,
		OwnerIdentityID: p.Fixture.Owner,
		Expected: fmt.Sprintf("fixture %q is owned by %s and is declared as not accessible to other "+
			"identities, so %s should have been refused",
			p.Fixture.ID, p.Owner.ID(), p.Attacker.ID()),
		Actual: fmt.Sprintf("%s read a resource owned by %s. %s%s",
			p.Attacker.ID(), p.Owner.ID(), describeEvidence(eq, ev), frameworkNote(p)),
		Verification: model.VerificationRecord{
			Strategy:    "owner-control-then-cross-owner-probe-then-owner-recheck",
			Steps:       steps,
			Performed:   true,
			Result:      result,
			Unavailable: unavailable,
		},
		Remediation: "Scope the query for this operation by the calling identity rather than by the " +
			"identifier alone, so that a record belonging to somebody else is never loaded. Returning " +
			"404 rather than 403 is a reasonable choice and does not weaken the fix.",
		Reproduction: []string{
			fmt.Sprintf("%s %s as %s (the owner) — succeeds", p.Operation.Method, p.URL, p.Owner.ID()),
			fmt.Sprintf("%s %s as %s (not the owner) — also succeeds", p.Operation.Method, p.URL, p.Attacker.ID()),
		},
	}

	detail := fmt.Sprintf("a non-owner (%s) was not refused access to fixture %q owned by %s",
		p.Attacker.ID(), p.Fixture.ID, p.Owner.ID())
	if confirmed {
		detail += ", and received the owner's resource itself"
	}

	return Result{
		Disposition:  model.DispositionExecuted,
		Detail:       detail,
		Finding:      finding,
		Exchanges:    exchanges,
		ControlsUsed: uses,
	}
}

// describeEvidence renders the two discriminators for a finding's prose.
func describeEvidence(eq equivalence, ev resourceEvidence) string {
	switch {
	case eq.Equivalent && ev.Proven:
		return ev.Reason
	case !eq.Equivalent:
		return "The response was not materially equivalent to the owner's, so it is not established " +
			"that the protected resource itself was returned: " + eq.Reason
	default:
		return "The response matched the owner's in shape but could not be tied to this resource: " + ev.Reason
	}
}

// sortedKeysOf returns a map's keys in order, so evidence and details are
// reproducible across runs.
func sortedKeysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mutationBody renders the configured mutation values as a JSON object.
func mutationBody(values map[string]any) ([]byte, error) {
	// Marshal through an ordered construction so the bytes are identical run to
	// run, which keeps evidence hashes stable.
	var b strings.Builder
	b.WriteString("{")
	for i, k := range sortedKeysOf(values) {
		if i > 0 {
			b.WriteString(",")
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		val, err := json.Marshal(values[k])
		if err != nil {
			return nil, fmt.Errorf("mutation value %q cannot be encoded: %w", k, err)
		}
		b.Write(key)
		b.WriteString(":")
		b.Write(val)
	}
	b.WriteString("}")
	return []byte(b.String()), nil
}

// frameworkNote adds the application's own declared control to a finding.
//
// It sharpens rather than decides. An operation the framework marks as
// controlled, which a non-owner nonetheless reached, is a control that does not
// work — a more actionable finding than one where no control was ever declared,
// and a harder one to dismiss as intended behaviour.
func frameworkNote(p ResourcePlan) string {
	if p.FrameworkControl == "" {
		return ""
	}
	return " The application's own framework metadata marks this operation as subject to " +
		p.FrameworkControl + ", so this is a declared control that is not enforced."
}

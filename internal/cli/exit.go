// Package cli is the command surface.
package cli

// Exit codes are a public contract. Accreted exit codes can never be changed
// without breaking every pipeline that branches on them, so they are defined
// once, here, with a stated meaning and a test for each.
//
// The distinction that matters most is between "ran cleanly and found nothing"
// and "could not meaningfully run". A tool that returns success for both is how
// a pipeline comes to imply safety it never established.
const (
	// ExitOK means the assessment ran and no policy threshold was exceeded.
	ExitOK = 0
	// ExitFindings means confirmed findings exceeded the configured policy.
	ExitFindings = 1
	// ExitUsage means the command line or configuration was invalid. Nothing ran.
	ExitUsage = 2
	// ExitNothingExecuted means the assessment completed but executed no checks,
	// so it establishes nothing. This is deliberately distinct from ExitOK.
	ExitNothingExecuted = 3
	// ExitAborted means the assessment could not complete: the target was
	// unreachable, discovery failed, or it was cancelled.
	ExitAborted = 4
	// ExitInternal means an unexpected internal error.
	ExitInternal = 5
)

// ExitCodeMeaning returns a human explanation for an exit code.
func ExitCodeMeaning(code int) string {
	switch code {
	case ExitOK:
		return "the assessment ran; no configured threshold was exceeded"
	case ExitFindings:
		return "findings exceeded the configured policy"
	case ExitUsage:
		return "invalid command line or configuration; nothing ran"
	case ExitNothingExecuted:
		return "the assessment executed no checks and establishes nothing"
	case ExitAborted:
		return "the assessment could not complete"
	case ExitInternal:
		return "an internal error occurred"
	default:
		return "unknown"
	}
}

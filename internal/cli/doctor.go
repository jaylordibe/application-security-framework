package cli

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/application-security-framework/internal/store"
)

// engineTool describes an optional external engine.
//
// Nothing here is bundled and nothing is required. An absent engine is reported
// as an explicit gap rather than silently reducing what a run covers.
type engineTool struct {
	name    string
	binary  string
	unlocks string
	status  string
}

func newDoctorCommand(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Report what is available and what each missing piece would unlock",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(stdout, "assay %s (%s/%s, %s)\n\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())

			fmt.Fprintln(stdout, "Core")
			fmt.Fprintf(stdout, "  %-22s %s\n", "specification ingest", "available (OpenAPI 3.x)")
			fmt.Fprintf(stdout, "  %-22s %s\n", "declared-auth check", "available")
			if store.PermissionsEnforced() {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "enforced (owner-only)")
			} else {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "NOT enforced on this platform")
			}

			fmt.Fprintln(stdout, "\nOptional external engines (none are bundled; none are required)")
			tools := []engineTool{
				{name: "OWASP ZAP", binary: "zap.sh", unlocks: "runtime DAST: injection, XSS, SSRF and related classes"},
				{name: "Nuclei", binary: "nuclei", unlocks: "known CVEs, misconfigurations, technology fingerprints"},
				{name: "Semgrep", binary: "semgrep", unlocks: "source analysis (bring your own rules; registry rules are not redistributable)"},
				{name: "opengrep", binary: "opengrep", unlocks: "source analysis with cross-function taint"},
				{name: "Hadrian", binary: "hadrian", unlocks: "multi-identity authorization testing"},
			}
			for i := range tools {
				if _, err := exec.LookPath(tools[i].binary); err == nil {
					tools[i].status = "found"
				} else {
					tools[i].status = "not found"
				}
				fmt.Fprintf(stdout, "  %-22s %-10s %s\n", tools[i].name, tools[i].status, tools[i].unlocks)
			}

			fmt.Fprintln(stdout, "\nNote: engine integrations are not implemented yet. This command reports what\n"+
				"is on your PATH so that a future run can say precisely what it could not use.")
			return nil
		},
	}
}

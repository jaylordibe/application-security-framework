package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/application-security-framework/internal/config"
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
	var configPath string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what is available and what each missing piece would unlock",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(stdout, "appsec %s (%s/%s, %s)\n\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())

			fmt.Fprintln(stdout, "Core")
			fmt.Fprintf(stdout, "  %-22s %s\n", "specification ingest", "available (OpenAPI 3.x)")
			fmt.Fprintf(stdout, "  %-22s %s\n", "declared-auth check", "available")
			if store.PermissionsEnforced() {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "enforced (owner-only)")
			} else {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "NOT enforced on this platform")
			}

			reportIdentities(stdout, configPath)

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
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to appsec.yaml (default: ./appsec.yaml if present)")
	return cmd
}

// reportIdentities says whether each configured identity's credential can be
// resolved.
//
// It reports availability and location only. A credential value is never
// printed, and neither is its length or a fingerprint of it: `doctor` output is
// pasted into issues and CI logs, which is exactly where a secret must not be.
//
// This deliberately does not contact the target. Checking whether a credential
// is *accepted* is the liveness canary's job during a run; doing it here would
// turn a local diagnostic into an unannounced authenticated request.
func reportIdentities(stdout io.Writer, configPath string) {
	path := configPath
	if path == "" {
		if _, err := os.Stat("appsec.yaml"); err != nil {
			return
		}
		path = "appsec.yaml"
	}

	fmt.Fprintln(stdout, "\nIdentities (from "+path+")")
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stdout, "  %-22s %s\n", "configuration", "could not be read; run a scan for the full error")
		return
	}
	ids := cfg.IdentityModels()
	if len(ids) == 0 {
		fmt.Fprintf(stdout, "  %-22s %s\n", "none configured",
			"no authenticated control request is possible, so no finding can reach confirmed")
		return
	}
	for _, id := range ids {
		label := id.ID
		status := "credential source configured"
		if _, rerr := id.Auth.Credential.Resolve(); rerr != nil {
			status = "credential unavailable: " + rerr.Error()
		}
		fmt.Fprintf(stdout, "  %-22s %s (%s)\n", label, status, id.Auth.Credential.Describe())
		if !id.Live.Configured() {
			fmt.Fprintf(stdout, "  %-22s %s\n", "",
				"no liveness canary; an expiry during a run could not be detected")
		}
	}
}

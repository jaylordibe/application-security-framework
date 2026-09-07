package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "0.0.0-dev"

// Execute runs the CLI and returns a process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := &cobra.Command{
		Use:   "appsec",
		Short: "Assessment coverage and verification",
		Long: "AppSec Framework assesses an application you own or are explicitly\n" +
			"authorized to test.\n\n" +
			"It runs the security engines you already trust, refuses to overstate what\n" +
			"they found, and produces an account of what was tested, what was blocked,\n" +
			"what was never attempted, and why. It brings its own authentication and\n" +
			"cross-owner checks, which contribute to that account rather than replace it.\n\n" +
			"AppSec Framework does not prove the absence of vulnerabilities. A run\n" +
			"with no findings means only that the checks it executed produced none —\n" +
			"and the report always says how many that was, out of how many it saw.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	root.AddCommand(newScanCommand(stdout, stderr))
	root.AddCommand(newInitCommand(stdout, stderr))
	root.AddCommand(newDoctorCommand(stdout, stderr))

	if err := root.Execute(); err != nil {
		var coded *exitError
		// errors.As rather than a type assertion, so a wrapped exit code keeps
		// its meaning instead of degrading to "invalid usage".
		if errors.As(err, &coded) {
			if coded.message != "" {
				fmt.Fprintln(stderr, coded.message)
			}
			return coded.code
		}
		fmt.Fprintf(stderr, "appsec: %v\n", err)
		return ExitUsage
	}
	return ExitOK
}

// exitError carries a process exit code out through cobra, which distinguishes
// only error from no error.
type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, message: fmt.Sprintf("appsec: "+format, args...)}
}

// Main is the entry point used by cmd/appsec.
func Main() {
	os.Exit(Execute(os.Args[1:], os.Stdout, os.Stderr))
}

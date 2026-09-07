package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/application-security-framework/internal/config"
	"github.com/jaylordibe/application-security-framework/internal/report"
)

// devVersion is what a build reports when nothing better is known.
const devVersion = "0.0.0-dev"

// Version is the build's version, overridable at link time.
//
// The Makefile sets it from `git describe` for release builds. It is a variable
// rather than a constant only so that -ldflags can reach it; resolveVersion
// below is what the CLI actually reports.
var Version = devVersion

// resolveVersion reports the most trustworthy version this build can establish.
//
// There are three ways a copy of this program comes into existence and they
// learn their version differently, so asking only one of them was wrong:
//
//   - A release build from the Makefile has it injected with -ldflags.
//   - `go install <module>/cmd/appsec@v0.1.0` runs the compiler directly and
//     never sees the Makefile, so the ldflags value stays "0.0.0-dev". The Go
//     toolchain does record the module version it resolved, and that is the
//     authoritative answer for exactly the installation path the README tells a
//     new user to take.
//   - `go build` inside a checkout stamps the VCS revision instead, which is the
//     best available answer for a contributor.
//
// Reporting "0.0.0-dev" to everyone who followed the documented install
// instructions would make every bug report ambiguous about what was running.
func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}
	return versionFrom(Version, info)
}

// versionFrom is resolveVersion's logic with its inputs supplied, so the
// precedence can be tested without rebuilding the test binary three ways.
func versionFrom(linked string, info *debug.BuildInfo) string {
	if linked != devVersion && linked != "" {
		return linked
	}
	if info == nil {
		return devVersion
	}

	// The version the module was resolved at, for `go install module@version`.
	// A checkout builds as "(devel)", which says nothing.
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	// Otherwise fall back to the revision, which `go build` stamps in a VCS
	// working tree.
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return devVersion
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	out := devVersion + "+" + revision
	if modified == "true" {
		out += ".dirty"
	}
	return out
}

// newVersionCommand prints the version and the build's own identity.
//
// The extra lines are there because the first thing anyone asks about a bug
// report is what was running and on what, and an issue template cannot make a
// reporter paste something the tool never printed.
func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, Go toolchain and platform",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			var b strings.Builder
			fmt.Fprintf(&b, "appsec %s\n", resolveVersion())
			fmt.Fprintf(&b, "  go:        %s\n", runtime.Version())
			fmt.Fprintf(&b, "  platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(&b, "  schema:    report %s, config %s\n",
				report.SchemaVersion, config.CurrentAPIVersion)
			_, err := io.WriteString(stdout, b.String())
			return err
		},
	}
}

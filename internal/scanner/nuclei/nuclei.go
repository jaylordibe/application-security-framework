// Package nuclei runs ProjectDiscovery's Nuclei as an external engine.
//
// Nuclei is the first engine integrated because it is the cheapest to supervise
// honestly: one static Go binary, no daemon, no JVM, and a structured output
// mode. Proving the boundary here before ZAP is a deliberate ordering — a
// process-supervision mistake found with Nuclei costs a test, and the same
// mistake found with ZAP costs an orphaned JVM.
//
// Every flag below was checked against the flag definitions in Nuclei v3.11.x
// rather than remembered. The distinction that matters is which unsafe
// behaviours are off by default and which have to be turned off explicitly:
// -code, -headless, -allow-local-file-access, -follow-redirects and -dashboard
// all default to false and are simply never passed, while
// -disable-unsigned-templates, -no-interactsh and -disable-update-check default
// to false and must be passed to get the safe behaviour.
package nuclei

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/proc"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// binaryName is what is looked up on PATH when no explicit path is configured.
const binaryName = "nuclei"

// Engine is the Nuclei integration.
type Engine struct{}

// New returns the Nuclei engine.
func New() scanner.Engine { return Engine{} }

// Meta identifies the engine.
func (Engine) Meta() scanner.Meta {
	return scanner.Meta{
		ID:    "nuclei",
		Title: "Nuclei",
		// What Nuclei can look for, given templates that cover it. Claiming a
		// capability is not the same as having covered it: see Normalize, which
		// only reports coverage the run actually earned.
		Capabilities: []scanner.Capability{
			"CWE-1395 known vulnerable component or misconfiguration (CVE/technology templates)",
		},
		Unlocks: "known CVEs, misconfigurations and technology fingerprints, from templates you supply",
		InstallHint: "Install Nuclei from https://github.com/projectdiscovery/nuclei and point " +
			"engines.nuclei.executable at it. AppSec Framework never downloads or installs an engine.",
	}
}

// RequiredProfile is the safety profile a Nuclei run needs.
//
// Verification, not discovery. Nuclei sends real probe requests chosen by
// templates AppSec did not write and cannot read, so it is not reconnaissance
// however benign a particular corpus happens to be. It is not gated at
// intrusive either, which would be its own dishonesty: that would imply AppSec
// knows the templates are destructive, and it does not know what they are at
// all.
func (Engine) RequiredProfile(scanner.Settings) model.Profile { return model.ProfileVerification }

// Detect resolves the executable and asks it for its version.
func (Engine) Detect(ctx context.Context, s scanner.Settings) scanner.Availability {
	path, err := resolve(s.Executable)
	if err != nil {
		return scanner.Availability{Problem: err.Error()}
	}

	res, runErr := scanner.ProbeVersion(ctx, proc.Spec{
		Name: "nuclei --version",
		Path: path,
		Args: []string{"-version"},
		// The version probe gets no environment either. It is still a foreign
		// binary, and this is still the process that holds the credentials.
		Env:       []string{},
		Timeout:   scanner.DefaultVersionTimeout,
		MaxStdout: 64 << 10,
		MaxStderr: 64 << 10,
	})
	// Nuclei prints its version banner on stderr.
	version := parseVersion(string(res.Stdout) + " " + res.Stderr)
	if version == "" {
		problem := "the executable did not report a recognisable version"
		if runErr != nil {
			problem = fmt.Sprintf("the version probe failed: %v", runErr)
		}
		return scanner.Availability{Problem: problem, Path: path}
	}

	return scanner.Availability{
		Present: true,
		Path:    path,
		Version: version,
		Warnings: []string{
			"the Nuclei executable is whatever is installed at " + path + "; AppSec Framework " +
				"records its path and self-reported version but cannot establish that it is a " +
				"genuine ProjectDiscovery build",
		},
	}
}

// resolve finds the executable without searching anything unexpected.
func resolve(configured string) (string, error) {
	if configured != "" {
		info, err := os.Stat(configured)
		if err != nil {
			return "", fmt.Errorf("the configured executable %s cannot be read: %w", configured, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("the configured executable %s is a directory", configured)
		}
		abs, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("the configured executable path is not usable: %w", err)
		}
		return abs, nil
	}
	path, err := exec.LookPath(binaryName)
	if err != nil {
		return "", errors.New("no " + binaryName + " executable was found on PATH and none is " +
			"configured at engines.nuclei.executable")
	}
	return path, nil
}

// parseVersion pulls a version out of Nuclei's banner.
func parseVersion(out string) string {
	for _, field := range strings.Fields(proc.Sanitize(out, 4096)) {
		trimmed := strings.TrimPrefix(field, "v")
		if trimmed == "" {
			continue
		}
		if _, err := strconv.Atoi(strings.SplitN(trimmed, ".", 2)[0]); err == nil &&
			strings.Count(trimmed, ".") >= 1 {
			return field
		}
	}
	return ""
}

// Invocation builds the argument vector.
//
// It is a vector, never a string, so a target URL containing a semicolon, a
// backtick or a newline is one argument and stays data.
func (Engine) Invocation(
	t scanner.Target, s scanner.Settings, w scanner.Workspace, a scanner.Availability,
) (scanner.Invocation, error) {
	if t.BaseURL == "" {
		return scanner.Invocation{}, errors.New("no target URL was given")
	}
	templates := strings.TrimSpace(s.RuleSource)
	if templates == "" {
		// Refusing to run without an explicit corpus is the whole reproducibility
		// story. Nuclei will otherwise fetch and use whatever the public
		// template repository holds today, which makes two runs a week apart
		// incomparable and makes the corpus an unrecorded dependency.
		return scanner.Invocation{}, errors.New(
			"no template directory is configured at engines.nuclei.templates. AppSec Framework " +
				"will not let Nuclei fetch templates for itself: a scan against a corpus that " +
				"changed overnight is not reproducible, and an unrecorded corpus is an " +
				"unrecorded dependency")
	}
	info, err := os.Stat(templates)
	if err != nil || !info.IsDir() {
		return scanner.Invocation{}, fmt.Errorf(
			"the configured template directory %s is not a readable directory", templates)
	}
	absTemplates, err := filepath.Abs(templates)
	if err != nil {
		return scanner.Invocation{}, fmt.Errorf("the template directory path is not usable: %w", err)
	}

	// What the corpus actually holds decides whether this run can find anything
	// at all, so it is established before the process starts rather than
	// inferred afterwards from an empty result.
	corpus, err := inspectCorpus(absTemplates)
	if err != nil {
		return scanner.Invocation{}, fmt.Errorf("the template directory %s could not be read: %w",
			absTemplates, err)
	}
	if corpus.total == 0 {
		return scanner.Invocation{}, fmt.Errorf(
			"the configured template directory %s contains no templates. Running Nuclei against an "+
				"empty corpus would produce a scan that finds nothing because it looked for "+
				"nothing", absTemplates)
	}
	allowUnsigned := s.Extra["allowUnsignedTemplates"] == "true"
	if corpus.signed == 0 && !allowUnsigned {
		// This is the trap this check exists for. Nuclei exits successfully
		// after excluding every unsigned template, so without this the run
		// would report "completed, no findings" having executed no security
		// logic whatsoever — a green result earned by doing nothing.
		return scanner.Invocation{}, fmt.Errorf(
			"none of the %d templates in %s carries a Nuclei signature, and unsigned templates are "+
				"excluded from execution, so this run would check nothing and report no findings. "+
				"Either point engines.nuclei.templates at a signed corpus, or set "+
				"engines.nuclei.allowUnsignedTemplates: true to state that you trust this "+
				"directory — templates are executable security logic, so that is a decision to "+
				"make deliberately", corpus.total, absTemplates)
	}

	args := []string{
		// One target. Nuclei is not asked to discover anything.
		"-target", t.BaseURL,
		// Explicit corpus. Nothing is fetched.
		"-templates", absTemplates,

		// Structured output. Human terminal text is never scraped.
		"-jsonl",
		"-silent",
		"-no-color",

		// No out-of-band interaction. Interactsh sends target-triggered
		// callbacks to a third-party service by default, which is both an
		// unannounced network egress and a disclosure of what is being tested.
		"-no-interactsh",

		// No update check. It is a network call AppSec did not ask for, and a
		// corpus that updates itself mid-assessment is not reproducible.
		"-disable-update-check",

		// Bounds inside the engine, in addition to the supervisor's.
		"-timeout", strconv.Itoa(perRequestTimeoutSeconds),
		"-retries", "1",
		"-rate-limit", strconv.Itoa(rateLimit(s)),

		// Results are also written to the workspace, so a partial run leaves
		// something readable even if stdout was cut.
		"-output", w.OutputPath,
	}

	// Deliberately never passed, each for a specific reason:
	//
	//   -code                      would let a template execute local code
	//   -headless                  would start a browser this tool cannot supervise
	//   -allow-local-file-access   would let a template read the filesystem
	//   -follow-redirects          would let a target redirect the scan off-origin
	//   -dashboard / -cloud-upload would send results to a third party
	//   -update-templates          would mutate the corpus mid-assessment
	//   -proxy                     would route traffic somewhere unaudited
	//   -interactsh-server         would re-enable out-of-band callbacks
	//
	// All of them default to off. They are listed here because "we did not pass
	// it" is only a control if somebody can see that it was a decision.

	if !allowUnsigned {
		// Refuse templates that are unsigned or whose signature does not
		// verify. Templates are executable security logic, so this is a
		// supply-chain control, not a formality. Defaults to false, so it must
		// be passed. It is omitted only when the operator has explicitly said
		// they trust this directory, and the provenance then records that.
		args = append(args, "-disable-unsigned-templates")
	}

	if sev := severities(s); len(sev) > 0 {
		args = append(args, "-severity", strings.Join(sev, ","))
	}

	return scanner.Invocation{
		Spec: proc.Spec{Name: "nuclei", Path: a.Path, Args: args},
		// Nuclei needs no environment. It is given a target and a directory.
		EnvNames: nil,
		Provenance: scanner.Provenance{
			Engine:         "nuclei",
			Version:        a.Version,
			ExecutablePath: a.Path,
			RuleSource:     describeTemplates(absTemplates, corpus, allowUnsigned),
			// AppSec cannot establish that this binary is a genuine
			// ProjectDiscovery build, and does not claim to.
			Verified: false,
		},
	}, nil
}

// perRequestTimeoutSeconds bounds one Nuclei request.
const perRequestTimeoutSeconds = 10

// rateLimit returns the requests-per-second cap for a run.
func rateLimit(s scanner.Settings) int {
	if v, ok := s.Extra["rateLimit"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			return n
		}
	}
	return 50
}

// severities returns the validated severity filter.
//
// The values are checked against Nuclei's own vocabulary rather than passed
// through. An operator-supplied string reaching an argument vector is data, but
// data that Nuclei will reject is a failed scan, and a failed scan reads as
// coverage that did not happen.
func severities(s scanner.Settings) []string {
	valid := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true, "critical": true, "unknown": true,
	}
	var out []string
	for _, v := range s.Severity {
		v = strings.ToLower(strings.TrimSpace(v))
		if valid[v] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// describeTemplates records where the corpus came from and pins it if it can.
//
// A directory path alone does not identify a corpus: the same path holds
// different templates next week. If the directory is a git checkout its commit
// is recorded, which is what makes a result reproducible. What the run will
// actually execute is recorded too, because "1000 templates on disk" and "1000
// templates executed" are different claims whenever any of them is unsigned.
func describeTemplates(dir string, c corpus, allowUnsigned bool) string {
	desc := "operator-supplied directory " + dir
	if head, err := gitHead(dir); err == nil && head != "" {
		desc += " at commit " + head
	} else {
		desc += " (not a git checkout, so the corpus is not pinned and a later run may " +
			"use different templates)"
	}
	switch {
	case allowUnsigned:
		desc += fmt.Sprintf("; %d templates, signature checking waived by "+
			"engines.nuclei.allowUnsignedTemplates, so they are trusted on the operator's word "+
			"alone", c.total)
	case c.unsigned > 0:
		desc += fmt.Sprintf("; %d of %d templates are signed and the remaining %d are excluded "+
			"from execution, so the corpus that ran is smaller than the directory",
			c.signed, c.total, c.unsigned)
	default:
		desc += fmt.Sprintf("; %d signed templates", c.signed)
	}
	return desc
}

// gitHead reads a checkout's HEAD commit without running git.
//
// Reading the file avoids executing a program inside a directory the operator
// pointed at, which is the sort of small convenience that turns into an
// execution primitive.
func gitHead(dir string) (string, error) {
	head, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD"))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(head))
	if ref, ok := strings.CutPrefix(line, "ref: "); ok {
		b, err := os.ReadFile(filepath.Join(dir, ".git", filepath.FromSlash(ref)))
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(string(b))
	}
	if len(line) < 7 {
		return "", errors.New("no commit")
	}
	return line[:7], nil
}

// corpus is what a template directory holds.
type corpus struct {
	total    int
	signed   int
	unsigned int
}

// maxTemplates bounds the walk so a directory that is not a template corpus —
// a home directory, a checkout of something else — cannot stall a run.
const maxTemplates = 100000

// maxTemplateBytes bounds one file read. A Nuclei template is a few kilobytes;
// anything far larger is not one, and reading it would only cost memory.
const maxTemplateBytes = 1 << 20

// inspectCorpus counts templates and how many carry a Nuclei signature.
//
// Nuclei signs a template by appending a "# digest:" line, so signedness is
// readable without running anything. This is a count, not a verification: only
// Nuclei itself checks that a digest matches, and this code deliberately does
// not reimplement that. What it establishes is the difference between a corpus
// Nuclei will execute and one it will silently skip in full.
func inspectCorpus(dir string) (corpus, error) {
	var c corpus
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// An unreadable subdirectory is not a reason to abandon the corpus.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		c.total++
		if isSigned(path) {
			c.signed++
		} else {
			c.unsigned++
		}
		if c.total >= maxTemplates {
			return filepath.SkipAll
		}
		return nil
	})
	return c, err
}

// isSigned reports whether a template file carries a Nuclei digest line.
func isSigned(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxTemplateBytes {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "# digest:") {
			return true
		}
	}
	return false
}

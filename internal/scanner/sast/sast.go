// Package sast runs Semgrep or opengrep as an external engine.
//
// One integration covers both, and that is an evidence-based choice rather than
// symmetry for its own sake. opengrep is a fork of Semgrep's open-source engine:
// both are LGPL-2.1, both take `--config` and both emit the same `--json`
// document, so supporting the second costs a name in a list. Supporting it is
// worth doing because the two differ in ways an operator may care about:
// Semgrep's metrics default to AUTO, which sends telemetry when rules are pulled
// from its registry, and its registry rules are licensed for internal use only —
// which is why this project has a CI check forbidding references to them.
//
// The most important thing this package does not do is bundle rules. A rule
// corpus is somebody else's licensed work and somebody else's security opinion.
// The operator supplies it, and its location is recorded so a result can be
// reproduced.
package sast

import (
	"context"
	"encoding/json"
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

// candidates are the executables looked for, in order.
//
// opengrep first: it is the fork without the telemetry default and without the
// registry-licensing question, so an operator who has both installed gets the
// one with fewer surprises unless they say otherwise.
var candidates = []string{"opengrep", "semgrep"}

// Engine is the static-analysis integration.
type Engine struct{}

// New returns the static-analysis engine.
func New() scanner.Engine { return Engine{} }

// Meta identifies the engine.
func (Engine) Meta() scanner.Meta {
	return scanner.Meta{
		ID:    "sast",
		Title: "Semgrep/opengrep",
		Capabilities: []scanner.Capability{
			"source analysis (bring your own rules; registry rules are not redistributable)",
		},
		Unlocks: "source-level observations from rules you supply, for classes runtime testing " +
			"cannot reach",
		InstallHint: "Install opengrep (https://github.com/opengrep/opengrep) or Semgrep " +
			"(https://semgrep.dev) and point engines.sast.executable at it. AppSec Framework " +
			"never downloads or installs an engine, and ships no rules.",
	}
}

// RequiredProfile is the profile a source scan needs.
//
// Verification rather than discovery, but not because it is dangerous to the
// target: it sends no traffic at all. It sits here because it reads an
// application's source, which is a different kind of access from reading a
// specification, and because a profile is the place an operator states what
// this run is allowed to touch.
func (Engine) RequiredProfile(scanner.Settings) model.Profile { return model.ProfileVerification }

// Detect resolves the executable and asks it for its version.
func (Engine) Detect(ctx context.Context, s scanner.Settings) scanner.Availability {
	path, err := resolve(s.Executable)
	if err != nil {
		return scanner.Availability{Problem: err.Error()}
	}
	res, runErr := scanner.ProbeVersion(ctx, proc.Spec{
		Name: "sast --version", Path: path, Args: []string{"--version"},
		Env: []string{}, Timeout: scanner.DefaultVersionTimeout,
		MaxStdout: 64 << 10, MaxStderr: 64 << 10,
	})
	version := parseVersion(string(res.Stdout) + " " + res.Stderr)
	if version == "" {
		problem := "the executable did not report a recognisable version"
		if runErr != nil {
			problem = fmt.Sprintf("the version probe failed: %v", runErr)
		}
		return scanner.Availability{Problem: problem, Path: path}
	}
	warn := []string{
		"the executable at " + path + " is whatever is installed; AppSec Framework records its " +
			"path and self-reported version but cannot establish its provenance",
	}
	if strings.Contains(strings.ToLower(filepath.Base(path)), "semgrep") {
		warn = append(warn, "Semgrep's metrics default to AUTO, which sends telemetry when rules "+
			"are pulled from its registry. AppSec Framework passes --metrics=off and requires "+
			"local rules, but the setting is the engine's and can be changed elsewhere")
	}
	return scanner.Availability{Present: true, Path: path, Version: version, Warnings: warn}
}

func resolve(configured string) (string, error) {
	if configured != "" {
		info, err := os.Stat(configured)
		if err != nil {
			return "", fmt.Errorf("the configured executable %s cannot be read: %w", configured, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("the configured executable %s is a directory", configured)
		}
		return filepath.Abs(configured)
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("neither opengrep nor semgrep was found on PATH and none is configured " +
		"at engines.sast.executable")
}

func parseVersion(out string) string {
	for _, field := range strings.Fields(proc.Sanitize(out, 4096)) {
		trimmed := strings.TrimPrefix(field, "v")
		if trimmed == "" || !strings.Contains(trimmed, ".") {
			continue
		}
		if _, err := strconv.Atoi(strings.SplitN(trimmed, ".", 2)[0]); err == nil {
			return field
		}
	}
	return ""
}

// Invocation builds the argument vector.
func (Engine) Invocation(
	t scanner.Target, s scanner.Settings, w scanner.Workspace, a scanner.Availability,
) (scanner.Invocation, error) {
	if t.SourceRoot == "" {
		return scanner.Invocation{}, errors.New(
			"no source root is configured; a static analyser needs an application checkout to read")
	}
	root, err := filepath.Abs(t.SourceRoot)
	if err != nil {
		return scanner.Invocation{}, fmt.Errorf("the source root is not usable: %w", err)
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return scanner.Invocation{}, fmt.Errorf("the source root %s is not a readable directory", root)
	}

	rules := strings.TrimSpace(s.RuleSource)
	if rules == "" {
		return scanner.Invocation{}, errors.New(
			"no rule source is configured at engines.sast.rules. AppSec Framework ships no rules " +
				"and will not pull them from a registry: registry rules carry their own licence, " +
				"fetching them is an unannounced network call, and a corpus that changes between " +
				"runs makes results incomparable")
	}
	// A rule source must be a local path. A registry shorthand such as
	// `p/default` (appsec:refuses-registry) would fetch rules over the network
	// and, for Semgrep, turn metrics on.
	if !isLocalPath(rules) {
		return scanner.Invocation{}, fmt.Errorf(
			"the rule source %q is not a local path. AppSec Framework only accepts local rules: a "+
				"registry identifier would fetch over the network and, for Semgrep, enable "+
				"telemetry", rules)
	}
	absRules, err := filepath.Abs(rules)
	if err != nil {
		return scanner.Invocation{}, fmt.Errorf("the rule source path is not usable: %w", err)
	}
	if _, err := os.Stat(absRules); err != nil {
		return scanner.Invocation{}, fmt.Errorf("the rule source %s cannot be read", absRules)
	}

	args := []string{
		"--config", absRules,
		// Structured output, never scraped terminal text.
		"--json",
		"--output", w.OutputPath,
		// No telemetry. Semgrep's default is AUTO, which sends when rules come
		// from its registry; this is off regardless.
		"--metrics=off",
		// Never prompt, never open a browser, never require an account.
		"--disable-version-check",
		"--quiet",
		"--no-git-ignore",
		// Bounds inside the engine, on top of the supervisor's.
		"--timeout", strconv.Itoa(perRuleTimeoutSeconds),
		"--max-target-bytes", strconv.Itoa(maxTargetBytes),
		root,
	}

	return scanner.Invocation{
		Spec: proc.Spec{Name: "sast", Path: a.Path, Args: args},
		// A Python-based analyser needs a temporary directory and, for
		// Semgrep, a home for its cache. Nothing else, and never a credential.
		EnvNames: []string{"HOME", "TMPDIR", "PATH"},
		Provenance: scanner.Provenance{
			Engine:         "sast",
			Version:        a.Version,
			ExecutablePath: a.Path,
			RuleSource:     describeRules(absRules),
			Verified:       false,
		},
	}, nil
}

const (
	perRuleTimeoutSeconds = 30
	maxTargetBytes        = 2000000
)

// isLocalPath reports whether a rule source is a filesystem path rather than a
// registry identifier or URL.
func isLocalPath(v string) bool {
	if strings.Contains(v, "://") {
		return false
	}
	// Semgrep registry shorthands look like `p/default`, `r/go`, or `auto`. appsec:refuses-registry
	if v == "auto" {
		return false
	}
	if filepath.IsAbs(v) || strings.HasPrefix(v, ".") {
		return true
	}
	// A bare `p/xxx` or `r/xxx` is a registry reference; a real relative
	// directory almost always has more structure or exists on disk.
	if _, err := os.Stat(v); err == nil {
		return true
	}
	return false
}

// describeRules records where the rules came from and pins them if it can.
func describeRules(path string) string {
	desc := "operator-supplied rules at " + path
	if head, err := gitHead(path); err == nil && head != "" {
		return desc + " at commit " + head
	}
	return desc + " (not a git checkout, so the rule set is not pinned and a later run may use " +
		"different rules)"
}

// gitHead reads a checkout's HEAD without running git.
func gitHead(path string) (string, error) {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
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

// output is the subset of the Semgrep/opengrep JSON document this reads.
type output struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata struct {
				CWE        any    `json:"cwe"`
				OWASP      any    `json:"owasp"`
				Confidence string `json:"confidence"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"errors"`
	Paths struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

// Normalize reads the JSON document.
func (Engine) Normalize(
	stdout []byte, w scanner.Workspace, p scanner.Provenance, _ scanner.Settings,
) (scanner.Normalized, error) {
	raw, err := os.ReadFile(w.OutputPath)
	if err != nil {
		if len(stdout) == 0 {
			return scanner.Normalized{}, errors.New(
				"no results document was written and nothing was produced on stdout")
		}
		raw = stdout
	}

	var doc output
	if err := json.Unmarshal(raw, &doc); err != nil {
		return scanner.Normalized{}, fmt.Errorf("the results document is not readable JSON: %w", err)
	}

	var out scanner.Normalized
	for _, r := range doc.Results {
		if r.CheckID == "" {
			continue
		}
		location := r.Path
		if r.Start.Line > 0 {
			location = fmt.Sprintf("%s:%d", r.Path, r.Start.Line)
		}
		out.Observations = append(out.Observations, scanner.Observation{
			RuleID:   r.CheckID,
			RuleName: r.CheckID,
			Location: location,
			// The engine's own severity, verbatim. Semgrep emits ERROR,
			// WARNING and INFO, which is a third scale again and is not
			// translated.
			SourceSeverity:   r.Extra.Severity,
			SourceConfidence: r.Extra.Metadata.Confidence,
			References:       refs(r.Extra.Metadata.CWE),
			Detail: fmt.Sprintf("%s reported %q at %s. %s",
				p.Engine, r.CheckID, location, strings.TrimSpace(r.Extra.Message)),
			// The matched source lines are the application's own code. They are
			// deliberately not imported: a report that quotes source copies an
			// application into an artefact attached to tickets, and secrets live
			// in source.
		})
	}

	for _, e := range doc.Errors {
		if strings.EqualFold(e.Level, "error") {
			out.Partial = true
		}
		out.Limitations = append(out.Limitations,
			"the analyser reported a problem while scanning: "+e.Message)
	}

	if !out.Partial {
		out.Covered = Engine{}.Meta().Capabilities
	}
	out.Limitations = append(out.Limitations,
		"static analysis reports what the supplied rules match in source: "+p.RuleSource+
			". It is not evidence that anything is reachable or exploitable at runtime, and a "+
			"class no supplied rule covers was not assessed",
		fmt.Sprintf("%d file(s) were scanned; files the analyser skipped are not assessed",
			len(doc.Paths.Scanned)))
	sort.Strings(out.Limitations)
	return out, nil
}

// refs extracts CWE identifiers, which the metadata types loosely.
func refs(v any) []string {
	var raw []string
	switch t := v.(type) {
	case string:
		if t != "" {
			raw = []string{t}
		}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				raw = append(raw, s)
			}
		}
	}
	var out []string
	for _, r := range raw {
		// Semgrep writes "CWE-89: Improper Neutralization..."; keep the id.
		if id, _, found := strings.Cut(r, ":"); found {
			r = id
		}
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, strings.ToUpper(r))
		}
	}
	sort.Strings(out)
	return out
}

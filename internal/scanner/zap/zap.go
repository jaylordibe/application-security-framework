// Package zap runs ZAP as an external engine.
//
// ZAP is integrated second, on the boundary Nuclei proved, because it is the
// harder process to supervise: a JVM, helper processes, and in some modes a
// browser. That is exactly why the process-group cleanup was tested with a
// deliberately forking fake engine before this package existed.
//
// The integration is deliberately the smallest reproducible one: `zap.sh -cmd`,
// which runs to completion and exits, writing a JSON report. It is not the
// daemon-plus-API mode. A long-lived daemon means a port, a lifecycle and an
// API key to manage, and a whole class of "did it really stop" questions that
// `-cmd` does not raise.
package zap

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

// binaryName is what is looked up on PATH when no explicit path is configured.
const binaryName = "zap.sh"

// Mode is how much ZAP is allowed to do.
type Mode string

const (
	// ModePassive spiders the target and reports what passive rules observe.
	// It sends ordinary requests and does not attempt attacks.
	ModePassive Mode = "passive"
	// ModeActive additionally runs ZAP's active scanner, which sends attack
	// payloads. It is an attack, and it is gated accordingly.
	ModeActive Mode = "active"
)

// Engine is the ZAP integration.
type Engine struct{}

// New returns the ZAP engine.
func New() scanner.Engine { return Engine{} }

// Meta identifies the engine.
func (Engine) Meta() scanner.Meta {
	return scanner.Meta{
		ID:    "zap",
		Title: "ZAP",
		Capabilities: []scanner.Capability{
			"CWE-79 cross-site scripting",
			"CWE-89 SQL injection",
		},
		Unlocks: "runtime web scanning: injection and cross-site scripting classes AppSec " +
			"Framework does not test natively",
		InstallHint: "Install ZAP from https://www.zaproxy.org/download/ and point " +
			"engines.zap.executable at zap.sh. AppSec Framework never downloads or installs an engine.",
	}
}

// mode returns the configured mode, defaulting to passive.
//
// Passive is the default because the alternative sends attack traffic, and a
// default that attacks is a default that surprises somebody.
func mode(s scanner.Settings) Mode {
	if strings.EqualFold(s.Extra["mode"], string(ModeActive)) {
		return ModeActive
	}
	return ModePassive
}

// RequiredProfile gates ZAP by what it is actually configured to do.
//
// This is the distinction §21 of the milestone turns on: a passive scan is
// ordinary traffic and belongs at verification, while the active scanner sends
// payloads intended to change behaviour and belongs at intrusive. Letting an
// active scan run under a reconnaissance profile because the same executable
// covers both would be exactly the silent escalation the profile model exists
// to prevent.
func (Engine) RequiredProfile(s scanner.Settings) model.Profile {
	if mode(s) == ModeActive {
		return model.ProfileIntrusive
	}
	return model.ProfileVerification
}

// Detect resolves the executable and asks it for its version.
func (Engine) Detect(ctx context.Context, s scanner.Settings) scanner.Availability {
	path, err := resolve(s.Executable)
	if err != nil {
		return scanner.Availability{Problem: err.Error()}
	}
	res, runErr := scanner.ProbeVersion(ctx, proc.Spec{
		Name: "zap -version",
		Path: path,
		Args: []string{"-cmd", "-version"},
		// ZAP is a JVM launcher and needs a home directory to write its
		// configuration into. It is given one explicitly at run time; the
		// version probe needs nothing.
		Env:       []string{},
		Timeout:   scanner.DefaultVersionTimeout,
		MaxStdout: 64 << 10,
		MaxStderr: 64 << 10,
	})
	version := parseVersion(string(res.Stdout) + " " + res.Stderr)
	if version == "" {
		problem := "the executable did not report a recognisable version"
		if runErr != nil {
			problem = fmt.Sprintf("the version probe failed: %v", runErr)
		}
		return scanner.Availability{Problem: problem, Path: path}
	}
	return scanner.Availability{
		Present: true, Path: path, Version: version,
		Warnings: []string{
			"the ZAP executable is whatever is installed at " + path + "; AppSec Framework " +
				"records its path and self-reported version but cannot establish its provenance",
		},
	}
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
	path, err := exec.LookPath(binaryName)
	if err != nil {
		return "", errors.New("no " + binaryName + " was found on PATH and none is configured " +
			"at engines.zap.executable")
	}
	return path, nil
}

// parseVersion pulls a version out of ZAP's banner.
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
	if t.BaseURL == "" {
		return scanner.Invocation{}, errors.New("no target URL was given")
	}
	// ZAP writes its own configuration and add-on state into a home directory.
	// It is given one inside the run's workspace, which is removed afterwards,
	// so a scan cannot accumulate state in the operator's home directory or
	// pick any up from a previous run.
	home := filepath.Join(w.Dir, "zap-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return scanner.Invocation{}, fmt.Errorf("cannot create a private ZAP home: %w", err)
	}

	args := []string{
		// Run to completion and exit. Not a daemon.
		"-cmd",
		// A private, empty home inside the workspace.
		"-dir", home,
		// Never contact the marketplace or update add-ons mid-assessment.
		"-silent",
		"-nostdout",
		// One target, and the report path.
		"-quickurl", t.BaseURL,
		"-quickout", w.OutputPath,
	}
	if mode(s) == ModePassive {
		// Spider and passive-scan only. Without this, -quickurl runs the active
		// scanner, which sends attack payloads.
		args = append(args, "-quickprogress")
	}

	return scanner.Invocation{
		Spec: proc.Spec{Name: "zap", Path: a.Path, Args: args},
		// ZAP is a JVM launcher: it needs to find a Java runtime and a writable
		// temporary directory. These are named explicitly, and everything else
		// — including this tool's identity credentials — is absent.
		EnvNames: []string{"JAVA_HOME", "PATH", "TMPDIR"},
		Provenance: scanner.Provenance{
			Engine:         "zap",
			Version:        a.Version,
			ExecutablePath: a.Path,
			RuleSource: fmt.Sprintf("ZAP's built-in rules in %s mode; AppSec Framework supplies "+
				"no rules and does not pin ZAP's add-ons, so results depend on the installed "+
				"version and its add-on state", mode(s)),
			Verified: false,
		},
	}, nil
}

// report is the subset of ZAP's JSON report this integration reads.
type report struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID   string `json:"pluginid"`
			AlertRef   string `json:"alertRef"`
			Name       string `json:"name"`
			Alert      string `json:"alert"`
			RiskCode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			RiskDesc   string `json:"riskdesc"`
			Desc       string `json:"desc"`
			CWEID      string `json:"cweid"`
			WASCID     string `json:"wascid"`
			Instances  []struct {
				URI      string `json:"uri"`
				Method   string `json:"method"`
				Param    string `json:"param"`
				Evidence string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// riskName maps ZAP's numeric risk code to its own label.
//
// This is not a translation into AppSec's scale — it is ZAP's own vocabulary,
// which the report happens to encode as a number. "3" and "High" are the same
// statement by ZAP; neither is a statement by AppSec Framework.
func riskName(code string) string {
	switch strings.TrimSpace(code) {
	case "3":
		return "High"
	case "2":
		return "Medium"
	case "1":
		return "Low"
	case "0":
		return "Informational"
	}
	return strings.TrimSpace(code)
}

// confidenceName maps ZAP's numeric confidence to its own label.
func confidenceName(code string) string {
	switch strings.TrimSpace(code) {
	case "4":
		return "Confirmed"
	case "3":
		return "High"
	case "2":
		return "Medium"
	case "1":
		return "Low"
	case "0":
		return "False Positive"
	}
	return strings.TrimSpace(code)
}

// Normalize reads ZAP's JSON report.
func (Engine) Normalize(
	stdout []byte, w scanner.Workspace, p scanner.Provenance, s scanner.Settings,
) (scanner.Normalized, error) {
	raw, err := os.ReadFile(w.OutputPath)
	if err != nil {
		// ZAP writes its report to a file, so stdout is a fallback rather than
		// the primary channel.
		if len(stdout) == 0 {
			return scanner.Normalized{}, fmt.Errorf("no ZAP report was written to %s and nothing "+
				"was produced on stdout", filepath.Base(w.OutputPath))
		}
		raw = stdout
	}

	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return scanner.Normalized{}, fmt.Errorf("the ZAP report is not readable JSON: %w", err)
	}

	var out scanner.Normalized
	for _, site := range rep.Site {
		for _, a := range site.Alerts {
			id := firstNonEmpty(a.AlertRef, a.PluginID)
			if id == "" {
				continue
			}
			name := firstNonEmpty(a.Name, a.Alert)
			// One observation per instance: a parameter is what makes an alert
			// actionable, and collapsing instances would lose it.
			if len(a.Instances) == 0 {
				out.Observations = append(out.Observations, scanner.Observation{
					RuleID: id, RuleName: name, Location: site.Name,
					SourceSeverity:   riskName(a.RiskCode),
					SourceConfidence: confidenceName(a.Confidence),
					References:       refs(a.CWEID, a.WASCID),
					Detail:           detail(name, a.Desc),
				})
				continue
			}
			for _, inst := range a.Instances {
				out.Observations = append(out.Observations, scanner.Observation{
					RuleID: id, RuleName: name,
					Location:  firstNonEmpty(inst.URI, site.Name),
					Parameter: inst.Param,
					// ZAP's own risk and confidence, verbatim. ZAP's four risks
					// and five confidences do not map onto AppSec's scales and
					// are not converted (ADR-0005).
					SourceSeverity:   riskName(a.RiskCode),
					SourceConfidence: confidenceName(a.Confidence),
					References:       refs(a.CWEID, a.WASCID),
					Detail:           detail(name, a.Desc),
					// Evidence is the matched fragment of a target response. It
					// is target-controlled, so the caller sanitizes and redacts
					// it before anything is persisted.
					Evidence: inst.Evidence,
				})
			}
		}
	}

	// A passive run claims nothing. ZAP's passive rules observe responses; they
	// do not send the payloads that would establish whether an injection is
	// exploitable. Claiming the class because the executable ran is precisely
	// the inference the coverage account exists to prevent.
	if mode(s) == ModeActive {
		out.Covered = Engine{}.Meta().Capabilities
	}
	out.Limitations = []string{
		"ZAP's spider reaches what it can find from the target URL. AppSec Framework cannot " +
			"constrain where a ZAP rule sends a request, so its traffic is bounded by ZAP's own " +
			"configuration rather than by this tool's authorization boundary",
		"ZAP results depend on the installed version and its add-on state, which AppSec " +
			"Framework does not pin; two runs against different installations are not comparable",
		"ZAP runs unauthenticated. AppSec Framework does not pass identity credentials to a " +
			"third-party engine, so anything reachable only when signed in was not scanned",
	}
	if mode(s) == ModePassive {
		out.Limitations = append(out.Limitations, PassiveOnlyLimitation)
	}
	sort.Strings(out.Limitations)
	return out, nil
}

// PassiveOnlyLimitation names what a passive run did not do.
//
// It is a separate exported statement because "ZAP ran" and "injection was
// assessed" are different claims, and a passive run only supports the first.
const PassiveOnlyLimitation = "ZAP ran in passive mode, so its active scanner did not run and " +
	"injection and cross-site scripting were NOT assessed by it. Set engines.zap.mode to active, " +
	"under the intrusive profile, to test those"

func detail(name, desc string) string {
	d := "ZAP reported " + name
	if desc = strings.TrimSpace(desc); desc != "" {
		d += ". " + desc
	}
	return d
}

func refs(cwe, wasc string) []string {
	var out []string
	if c := strings.TrimSpace(cwe); c != "" && c != "-1" && c != "0" {
		out = append(out, "CWE-"+c)
	}
	if c := strings.TrimSpace(wasc); c != "" && c != "-1" && c != "0" {
		out = append(out, "WASC-"+c)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

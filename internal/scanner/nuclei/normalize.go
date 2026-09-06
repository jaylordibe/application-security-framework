package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// maxLineBytes bounds one JSONL record. A single Nuclei result embeds the
// matched request and response, so one line can be large; it cannot be
// unbounded.
const maxLineBytes = 4 << 20

// result is the subset of Nuclei's ResultEvent this integration reads.
//
// It is a subset on purpose. Nuclei emits `request`, `response`,
// `template-encoded` and `curl-command`, and every one of those is a place a
// credential ends up: the curl command carries the Authorization header AppSec
// itself may have sent, and the request and response are raw HTTP. None of them
// is decoded here, so none can be persisted by accident later.
type result struct {
	TemplateID   string   `json:"template-id"`
	TemplatePath string   `json:"template-path"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	Matched      string   `json:"matched-at"`
	MatcherName  string   `json:"matcher-name"`
	Extracted    []string `json:"extracted-results"`
	Info         struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Tags           any    `json:"tags"`
		Reference      any    `json:"reference"`
		Classification *struct {
			CVEID any `json:"cve-id"`
			CWEID any `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Error string `json:"error"`
}

// Normalize turns Nuclei's JSONL into observations.
//
// Nuclei writes one JSON object per line and prints nothing at all when it
// finds nothing, so an empty document is a successful scan with no results —
// not a parse failure. That distinction matters: treating "no output" as an
// error would make a clean scan look like a broken engine, and treating a
// broken engine as a clean scan would be worse.
func (Engine) Normalize(
	stdout []byte, w scanner.Workspace, p scanner.Provenance, s scanner.Settings,
) (scanner.Normalized, error) {
	raw := stdout
	// Nuclei was asked to write results to the workspace as well. If stdout was
	// empty but the file has content, the file is authoritative: it survives a
	// run whose stdout was interfered with.
	if len(bytes.TrimSpace(raw)) == 0 {
		if b, err := os.ReadFile(w.OutputPath); err == nil && len(bytes.TrimSpace(b)) > 0 {
			raw = b
		}
	}

	var out scanner.Normalized
	var malformed, engineErrors int

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r result
		if err := json.Unmarshal(line, &r); err != nil {
			malformed++
			continue
		}
		if r.Error != "" {
			engineErrors++
			continue
		}
		if r.TemplateID == "" {
			// Nothing to identify, triage or deduplicate on.
			malformed++
			continue
		}
		out.Observations = append(out.Observations, toObservation(r))
	}
	if err := sc.Err(); err != nil {
		// A line above the buffer limit means the document is not fully
		// readable. Whatever parsed is retained and the result is partial: a
		// silently shorter list of findings is the failure mode to avoid.
		out.Partial = true
		out.Limitations = append(out.Limitations,
			"a Nuclei result line exceeded the read limit, so the output was not fully parsed")
	}

	if malformed > 0 {
		out.Partial = true
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"%d Nuclei result line(s) could not be read and were discarded", malformed))
	}
	if engineErrors > 0 {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"Nuclei reported %d template execution error(s); those templates did not run to "+
				"completion and their subject matter is not assessed", engineErrors))
	}

	// Coverage is claimed only by a run that completed and actually executed a
	// corpus. A partial parse claims nothing: the caller enforces that too, and
	// it is stated twice because "the process launched" becoming "the class was
	// assessed" is the single easiest way this feature could overstate itself.
	if !out.Partial {
		out.Covered = Engine{}.Meta().Capabilities
	}
	// Signature checking is stated as it was configured for this run. Claiming
	// it unconditionally would put a control in the report that the operator
	// had turned off.
	signatures := "unsigned templates are refused"
	if s.Extra["allowUnsignedTemplates"] == "true" {
		signatures = "signature checking was waived for this run by " +
			"engines.nuclei.allowUnsignedTemplates, so the templates ran on the operator's word"
	}
	out.Limitations = append(out.Limitations,
		"Nuclei covers only what the supplied templates cover: "+p.RuleSource+
			". Weakness classes absent from that corpus were not assessed by it",
		"AppSec Framework cannot constrain what an individual Nuclei template does. Redirects "+
			"are not followed, out-of-band interaction is disabled and "+signatures+
			", but a template in the supplied corpus can still address a host of its own "+
			"choosing, and that is outside this tool's authorization boundary")
	sort.Strings(out.Limitations)
	return out, nil
}

// toObservation maps one Nuclei result, preserving its own vocabulary.
func toObservation(r result) scanner.Observation {
	o := scanner.Observation{
		RuleID:   r.TemplateID,
		RuleName: r.Info.Name,
		Location: firstNonEmpty(r.Matched, r.Host),
		// Nuclei's severity, verbatim. It is not translated into AppSec's scale:
		// the two mean different things, and converting would invent an
		// assessment nobody made.
		SourceSeverity: strings.ToLower(strings.TrimSpace(r.Info.Severity)),
		// Nuclei expresses no confidence at all, so this stays empty rather than
		// being filled with something plausible.
		SourceConfidence: "",
		References:       classifications(r),
		Detail:           detail(r),
	}
	// Extractor output is the closest thing to evidence Nuclei offers that is
	// not a raw request or response. It is still target-controlled, so it is
	// bounded here and sanitized and redacted by the caller.
	if len(r.Extracted) > 0 {
		o.Evidence = "extracted: " + strings.Join(clip(r.Extracted, 8), ", ")
	}
	return o
}

// detail renders an operator-facing sentence.
func detail(r result) string {
	name := firstNonEmpty(r.Info.Name, r.TemplateID)
	d := fmt.Sprintf("Nuclei template %q matched at %s", name, firstNonEmpty(r.Matched, r.Host))
	if r.MatcherName != "" {
		d += " (matcher " + r.MatcherName + ")"
	}
	if desc := strings.TrimSpace(r.Info.Description); desc != "" {
		d += ". " + desc
	}
	return d
}

// classifications extracts CWE and CVE identifiers.
//
// Nuclei types these fields loosely — a single string in some templates, a list
// in others — so both shapes are accepted rather than assuming one.
func classifications(r result) []string {
	if r.Info.Classification == nil {
		return nil
	}
	var out []string
	out = append(out, asStrings(r.Info.Classification.CWEID)...)
	out = append(out, asStrings(r.Info.Classification.CVEID)...)
	for i, v := range out {
		out[i] = strings.ToUpper(strings.TrimSpace(v))
	}
	sort.Strings(out)
	return clip(out, 32)
}

// asStrings normalizes a field that may be a string or a list of strings.
func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func clip(in []string, max int) []string {
	if len(in) > max {
		return in[:max]
	}
	return in
}

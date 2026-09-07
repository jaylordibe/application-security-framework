package nuclei

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// A real Nuclei JSONL record, of the shape v3 emits. Kept verbatim so that a
// change in the tool's output format shows up here rather than as silently
// missing findings.
const realRecord = `{"template":"http/cves/2021/CVE-2021-44228.yaml",` +
	`"template-url":"https://cloud.projectdiscovery.io/public/CVE-2021-44228",` +
	`"template-id":"CVE-2021-44228","template-path":"/corpus/http/cves/2021/CVE-2021-44228.yaml",` +
	`"info":{"name":"Apache Log4j2 Remote Code Injection","author":["pdteam"],` +
	`"tags":["cve","rce"],"description":"Apache Log4j2 JNDI features do not protect against ` +
	`attacker controlled LDAP.","severity":"critical",` +
	`"classification":{"cve-id":["cve-2021-44228"],"cwe-id":["cwe-77"],"cvss-score":10}},` +
	`"type":"http","host":"http://127.0.0.1:8080","matched-at":"http://127.0.0.1:8080/api",` +
	`"matcher-name":"jndi","extracted-results":["ldap://x"],` +
	`"request":"GET /api HTTP/1.1\nAuthorization: Bearer SECRET-TOKEN\n",` +
	`"response":"HTTP/1.1 200 OK\n",` +
	`"curl-command":"curl -H 'Authorization: Bearer SECRET-TOKEN' http://127.0.0.1:8080/api",` +
	`"timestamp":"2026-09-06T12:00:00Z","matcher-status":true}`

func normalize(t *testing.T, jsonl string) scanner.Normalized {
	t.Helper()
	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "results.json")}
	n, err := Engine{}.Normalize([]byte(jsonl), w,
		scanner.Provenance{Engine: "nuclei", RuleSource: "test corpus"}, scanner.Settings{})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return n
}

// The engine's own vocabulary must survive intact, and the fields that carry
// credentials must not be imported at all.
func TestNormalizePreservesProvenanceAndDropsSecretBearingFields(t *testing.T) {
	n := normalize(t, realRecord)

	if len(n.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(n.Observations))
	}
	o := n.Observations[0]

	if o.RuleID != "CVE-2021-44228" {
		t.Errorf("RuleID = %q", o.RuleID)
	}
	if o.RuleName != "Apache Log4j2 Remote Code Injection" {
		t.Errorf("RuleName = %q", o.RuleName)
	}
	if o.Location != "http://127.0.0.1:8080/api" {
		t.Errorf("Location = %q, want the matched-at value", o.Location)
	}
	// Nuclei's severity verbatim, not translated.
	if o.SourceSeverity != "critical" {
		t.Errorf("SourceSeverity = %q, want the engine's own value", o.SourceSeverity)
	}
	// Nuclei expresses no confidence; inventing one would be inventing precision.
	if o.SourceConfidence != "" {
		t.Errorf("SourceConfidence = %q, want empty: Nuclei does not express confidence",
			o.SourceConfidence)
	}
	refs := strings.Join(o.References, ",")
	for _, want := range []string{"CWE-77", "CVE-2021-44228"} {
		if !strings.Contains(refs, want) {
			t.Errorf("references %v do not carry %s", o.References, want)
		}
	}

	// The request, response and curl command are never decoded, so a bearer
	// token echoed by the target cannot reach a report through them.
	whole, _ := json.Marshal(o)
	if strings.Contains(string(whole), "SECRET-TOKEN") {
		t.Fatalf("a credential from Nuclei's raw request/curl output was imported: %s", whole)
	}
}

// A clean scan produces no output at all. That must read as "found nothing",
// not as a broken engine.
func TestEmptyOutputIsACleanScanNotAFailure(t *testing.T) {
	n := normalize(t, "")
	if len(n.Observations) != 0 {
		t.Errorf("observations = %d, want 0", len(n.Observations))
	}
	if n.Partial {
		t.Error("an empty result was reported as partial")
	}
	if len(n.Covered) == 0 {
		t.Error("a completed scan with no findings claimed no coverage")
	}
}

// Unreadable lines make the result partial rather than silently shorter.
func TestMalformedLinesMakeTheResultPartial(t *testing.T) {
	n := normalize(t, realRecord+"\n{not json\n"+realRecord)
	if len(n.Observations) != 2 {
		t.Errorf("observations = %d, want the two readable records", len(n.Observations))
	}
	if !n.Partial {
		t.Fatal("a document with unreadable lines was reported as complete")
	}
	if len(n.Covered) != 0 {
		t.Fatal("a partially parsed run claimed coverage")
	}
	if !mentions(n.Limitations, "could not be read") {
		t.Errorf("the discarded lines were not reported: %v", n.Limitations)
	}
}

// A template that errored did not run, and its subject matter is unassessed.
func TestTemplateErrorsAreReportedNotCounted(t *testing.T) {
	n := normalize(t, `{"template-id":"x","error":"context deadline exceeded"}`)
	if len(n.Observations) != 0 {
		t.Error("an errored template produced an observation")
	}
	if !mentions(n.Limitations, "did not run to completion") {
		t.Errorf("template errors were not reported: %v", n.Limitations)
	}
}

// Nuclei types classification fields as either a string or a list.
func TestClassificationAcceptsBothShapes(t *testing.T) {
	n := normalize(t, `{"template-id":"t","matched-at":"http://x/",`+
		`"info":{"name":"n","severity":"high","classification":{"cve-id":"CVE-2020-1","cwe-id":"CWE-79"}}}`)
	if len(n.Observations) != 1 {
		t.Fatalf("observations = %d", len(n.Observations))
	}
	refs := strings.Join(n.Observations[0].References, ",")
	if !strings.Contains(refs, "CVE-2020-1") || !strings.Contains(refs, "CWE-79") {
		t.Errorf("scalar classification fields were dropped: %v", n.Observations[0].References)
	}
}

// Coverage is never claimed without a corpus caveat, because a corpus that
// covers nothing relevant is not an assessment of anything.
func TestCoverageIsAlwaysQualifiedByTheCorpus(t *testing.T) {
	n := normalize(t, realRecord)
	if !mentions(n.Limitations, "only what the supplied templates cover") {
		t.Errorf("coverage was claimed without naming its limit: %v", n.Limitations)
	}
	if !mentions(n.Limitations, "cannot constrain what an individual Nuclei template does") {
		t.Errorf("the scope limitation is not stated: %v", n.Limitations)
	}
}

// The argument vector is where every hardening decision actually takes effect.
func TestInvocationIsHardened(t *testing.T) {
	dir := signedCorpus(t)
	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "r.json")}
	inv, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: dir},
		w, scanner.Availability{Present: true, Path: "/usr/local/bin/nuclei", Version: "v3.11.1"})
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	args := strings.Join(inv.Spec.Args, " ")

	// Flags that default to unsafe and must be turned off explicitly.
	for _, required := range []string{
		"-disable-unsigned-templates", // templates are executable logic
		"-no-interactsh",              // no out-of-band callbacks to a third party
		"-disable-update-check",       // no unannounced network call, no corpus drift
		"-jsonl",                      // structured output, never scraped terminal text
	} {
		if !strings.Contains(args, required) {
			t.Errorf("the invocation omits %s: %s", required, args)
		}
	}

	// Flags that would be unsafe and are never passed.
	for _, forbidden := range []string{
		"-code", "-headless", "-allow-local-file-access", "-lfa",
		"-follow-redirects", "-fr", "-dashboard", "-cloud-upload",
		"-update-templates", "-proxy", "-interactsh-server",
	} {
		for _, a := range inv.Spec.Args {
			if a == forbidden {
				t.Errorf("the invocation passes %s, which it must never do", forbidden)
			}
		}
	}

	// The engine needs, and gets, no environment.
	if len(inv.EnvNames) != 0 {
		t.Errorf("Nuclei asked for environment variables: %v", inv.EnvNames)
	}
	// Provenance is honest about what cannot be established.
	if inv.Provenance.Verified {
		t.Error("a user-installed binary was reported as verified")
	}
	if !strings.Contains(inv.Provenance.RuleSource, dir) {
		t.Errorf("the template source was not recorded: %q", inv.Provenance.RuleSource)
	}
}

// Without an explicit corpus, Nuclei fetches templates for itself. That makes a
// scan unreproducible and the corpus an unrecorded dependency, so it is refused.
func TestInvocationRefusesToRunWithoutAnExplicitCorpus(t *testing.T) {
	_, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://x/", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true},
		scanner.Workspace{}, scanner.Availability{Present: true, Path: "/bin/nuclei"})
	if err == nil {
		t.Fatal("Nuclei was invoked with no template directory, so it would fetch its own")
	}
	if !strings.Contains(err.Error(), "not reproducible") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// A git checkout pins the corpus; anything else cannot be pinned and says so.
func TestTemplateProvenanceRecordsAPinWhenThereIsOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := inspectCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := describeTemplates(dir, c, false); !strings.Contains(got, "not pinned") {
		t.Errorf("an unpinned corpus was not flagged: %q", got)
	}

	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"),
		[]byte("abcdef1234567890\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := describeTemplates(dir, c, false)
	if !strings.Contains(got, "abcdef1") {
		t.Errorf("a git-pinned corpus did not record its commit: %q", got)
	}
}

// Nuclei sends real probe traffic, so it is not reconnaissance.
func TestRequiredProfileIsVerification(t *testing.T) {
	if got := (Engine{}).RequiredProfile(scanner.Settings{}); got != model.ProfileVerification {
		t.Errorf("required profile = %s, want verification", got)
	}
}

// An absent binary is a clear diagnosis, not a crash.
func TestDetectReportsAnAbsentBinary(t *testing.T) {
	a := Engine{}.Detect(context.Background(),
		scanner.Settings{Executable: filepath.Join(t.TempDir(), "nope")})
	if a.Present {
		t.Fatal("a non-existent executable was reported as present")
	}
	if !strings.Contains(a.Problem, "cannot be read") {
		t.Errorf("problem = %q", a.Problem)
	}
}

func TestParseVersion(t *testing.T) {
	tests := map[string]string{
		"v3.11.1":                             "v3.11.1",
		"Nuclei Engine Version: v3.11.1":      "v3.11.1",
		"[INF] Nuclei Engine Version: v3.4.2": "v3.4.2",
		"3.11.1":                              "3.11.1",
		"no version here":                     "",
	}
	for in, want := range tests {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func mentions(all []string, substr string) bool {
	for _, s := range all {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// signedCorpus writes a template directory Nuclei would actually execute.
//
// Nuclei marks a signed template with a trailing digest line. A corpus without
// one is skipped in full, which is the case the gate below exists to catch.
func signedCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := "id: x\ninfo:\n  name: x\n  severity: info\n" +
		"# digest: 4a0a00473045022100abcdef:1234567890abcdef\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The failure this catches is the worst kind: Nuclei excludes every unsigned
// template, exits successfully, prints nothing, and the run reads as a clean
// scan. Nothing was checked, and the report would not say so.
func TestAnEntirelyUnsignedCorpusIsRefusedRatherThanSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"),
		[]byte("id: mine\ninfo:\n  name: mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: dir},
		scanner.Workspace{}, scanner.Availability{Present: true, Path: "/usr/local/bin/nuclei"})
	if err == nil {
		t.Fatal("a corpus in which every template would be skipped was accepted, so the run " +
			"would have reported no findings after checking nothing")
	}
	if !strings.Contains(err.Error(), "report no findings") {
		t.Errorf("the refusal does not name the consequence: %v", err)
	}
	if !strings.Contains(err.Error(), "allowUnsignedTemplates") {
		t.Errorf("the refusal does not say how to proceed deliberately: %v", err)
	}
}

// An operator who writes their own templates must be able to run them — by
// saying so, and with the provenance recording that nothing verified them.
func TestUnsignedTemplatesRunOnlyWhenExplicitlyTrusted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"),
		[]byte("id: mine\ninfo:\n  name: mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	inv, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: dir,
			Extra: map[string]string{"allowUnsignedTemplates": "true"}},
		scanner.Workspace{}, scanner.Availability{Present: true, Path: "/usr/local/bin/nuclei"})
	if err != nil {
		t.Fatalf("an explicitly trusted corpus was refused: %v", err)
	}
	for _, a := range inv.Spec.Args {
		if a == "-disable-unsigned-templates" {
			t.Fatal("signature checking stayed on, so the trusted templates would not run")
		}
	}
	if !strings.Contains(inv.Provenance.RuleSource, "operator's word") {
		t.Errorf("the provenance does not record that nothing verified these templates: %q",
			inv.Provenance.RuleSource)
	}
}

// A mixed corpus runs, but the report must not imply the whole directory did.
func TestAPartlySignedCorpusRecordsWhatWillNotRun(t *testing.T) {
	dir := signedCorpus(t)
	if err := os.WriteFile(filepath.Join(dir, "mine.yaml"),
		[]byte("id: mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	inv, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: dir},
		scanner.Workspace{}, scanner.Availability{Present: true, Path: "/usr/local/bin/nuclei"})
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	if !strings.Contains(inv.Provenance.RuleSource, "excluded from execution") {
		t.Errorf("the corpus that ran was reported as the whole directory: %q",
			inv.Provenance.RuleSource)
	}
}

// An empty directory is a scan that looks for nothing.
func TestAnEmptyCorpusIsRefused(t *testing.T) {
	_, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: t.TempDir()},
		scanner.Workspace{}, scanner.Availability{Present: true, Path: "/usr/local/bin/nuclei"})
	if err == nil {
		t.Fatal("an empty template directory was accepted")
	}
	if !strings.Contains(err.Error(), "looked for nothing") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// A report must not credit a control the operator turned off.
func TestTheSignatureClaimReflectsHowTheRunWasConfigured(t *testing.T) {
	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "r.json")}
	p := scanner.Provenance{Engine: "nuclei", RuleSource: "test corpus"}

	enforced, err := Engine{}.Normalize([]byte(realRecord), w, p, scanner.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if !mentions(enforced.Limitations, "unsigned templates are refused") {
		t.Errorf("a run that enforced signatures did not say so: %v", enforced.Limitations)
	}

	waived, err := Engine{}.Normalize([]byte(realRecord), w, p,
		scanner.Settings{Extra: map[string]string{"allowUnsignedTemplates": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if mentions(waived.Limitations, "unsigned templates are refused") {
		t.Errorf("a run with signature checking waived claimed the control anyway: %v",
			waived.Limitations)
	}
	if !mentions(waived.Limitations, "ran on the operator's word") {
		t.Errorf("the waiver is not disclosed: %v", waived.Limitations)
	}
}

// Found by running the real Nuclei v3.11.1 against the reference Laravel
// application during the product validation gate.
//
// The stock "missing-cookie-samesite-strict" template extracts the whole
// Set-Cookie header, so extracted-results contained a live `api_session` value.
// That field was being imported as evidence on the assumption that the caller's
// redactor would clean it — but the redactor only removes credentials this
// assessment registered, never a secret belonging to the target.
func TestNucleiExtractorOutputIsNotImported(t *testing.T) {
	const sessionCookie = "api_session=eyJpdiI6IkpxWjlOQWxDLVNFQ1JFVCJ9"
	record := `{"template-id":"missing-cookie-samesite-strict",` +
		`"info":{"name":"Missing Cookie SameSite Strict","severity":"info"},` +
		`"matched-at":"http://127.0.0.1:8000","matcher-name":"cookie-check",` +
		`"extracted-results":["XSRF-TOKEN=abc; path=/; samesite=lax ` + sessionCookie + `"],` +
		`"matcher-status":true}`

	n := normalize(t, record)
	if len(n.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(n.Observations))
	}

	whole, err := json.Marshal(n.Observations[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(whole), "api_session") || strings.Contains(string(whole), "eyJpdiI6") {
		t.Fatalf("a target session cookie was imported from extracted-results: %s", whole)
	}

	// The matcher name is kept: it is written by the template author, says which
	// branch fired, and is what a triager actually needs.
	if got := n.Observations[0].Evidence; got != "matcher: cookie-check" {
		t.Errorf("Evidence = %q, want the matcher name", got)
	}
}

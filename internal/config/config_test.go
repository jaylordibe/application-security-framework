package config

import (
	"strings"
	"testing"
)

func parse(t *testing.T, yaml string) (Config, error) {
	t.Helper()
	return Parse(strings.NewReader(yaml), "test.yaml")
}

const minimal = `
apiVersion: assay/v1alpha1
target:
  baseURL: http://localhost:3000
`

func TestMinimalConfigLoadsWithDefaults(t *testing.T) {
	cfg, err := parse(t, minimal)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Assessment.Profile != "verification" {
		t.Errorf("default profile = %q, want verification", cfg.Assessment.Profile)
	}
	if !cfg.ShouldExcludeAuthEndpoints() {
		t.Error("authentication endpoints must be excluded by default")
	}
	if cfg.Output.Dir != ".assay" {
		t.Errorf("default output dir = %q", cfg.Output.Dir)
	}
}

// A typo must be a loud error, not a silently ignored setting.
func TestUnknownFieldsAreRejected(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profil: discovery\n")
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if !strings.Contains(err.Error(), "profil") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// The intrusive profile can change or destroy data, so selecting it is not by
// itself authorization to use it.
func TestIntrusiveProfileRequiresExplicitAuthorization(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profile: intrusive\n")
	if err == nil {
		t.Fatal("intrusive profile accepted without authorization")
	}
	if !strings.Contains(err.Error(), "authorizeIntrusive") {
		t.Errorf("error does not explain what is required: %v", err)
	}

	cfg, err := parse(t, minimal+"\nassessment:\n  profile: intrusive\n  authorizeIntrusive: true\n")
	if err != nil {
		t.Fatalf("authorized intrusive profile rejected: %v", err)
	}
	if cfg.Profile() != "intrusive" {
		t.Errorf("profile = %q", cfg.Profile())
	}
}

func TestInvalidProfileIsRejected(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profile: aggressive\n")
	if err == nil || !strings.Contains(err.Error(), "discovery, verification, intrusive") {
		t.Fatalf("error = %v, want the valid profiles listed", err)
	}
}

func TestTargetValidation(t *testing.T) {
	cases := map[string]string{
		"missing":            "apiVersion: assay/v1alpha1\ntarget:\n  baseURL: \"\"\n",
		"unsupported scheme": "apiVersion: assay/v1alpha1\ntarget:\n  baseURL: file:///etc/passwd\n",
		"no host":            "apiVersion: assay/v1alpha1\ntarget:\n  baseURL: http://\n",
		"embedded creds":     "apiVersion: assay/v1alpha1\ntarget:\n  baseURL: http://u:p@x.test\n",
	}
	for name, doc := range cases {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: accepted an invalid target", name)
		}
	}
}

func TestUnsupportedAPIVersionIsRejected(t *testing.T) {
	_, err := parse(t, "apiVersion: assay/v99\ntarget:\n  baseURL: http://x.test\n")
	if err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("error = %v, want an apiVersion rejection", err)
	}
}

func TestPacingBoundsAreEnforced(t *testing.T) {
	cases := []string{
		"\nassessment:\n  concurrency: 0\n",
		"\nassessment:\n  concurrency: 999\n",
		"\nassessment:\n  requestsPerSecond: 0\n",
		"\nassessment:\n  timeoutSeconds: 0\n",
		"\nassessment:\n  timeoutSeconds: 100000\n",
	}
	for _, c := range cases {
		if _, err := parse(t, minimal+c); err == nil {
			t.Errorf("accepted out-of-range pacing: %s", c)
		}
	}
}

func TestMutuallyExclusiveDiscoverySources(t *testing.T) {
	_, err := parse(t, minimal+"\ndiscovery:\n  openAPIFile: ./a.json\n  openAPIURL: http://x.test/s.json\n")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want a mutual-exclusion error", err)
	}
}

func TestErrorCodePointerMustBeAJSONPointer(t *testing.T) {
	if _, err := parse(t, minimal+"\noutcome:\n  errorCodePointer: errorCode\n"); err == nil {
		t.Fatal("accepted a pointer without a leading slash")
	}
	if _, err := parse(t, minimal+"\noutcome:\n  errorCodePointer: /errorCode\n"); err != nil {
		t.Fatalf("rejected a valid pointer: %v", err)
	}
}

// The target's own origin is always in scope; nothing else is.
func TestScopePolicyAlwaysIncludesTheTarget(t *testing.T) {
	cfg, err := parse(t, "apiVersion: assay/v1alpha1\ntarget:\n  baseURL: http://localhost:3000\n"+
		"scope:\n  allowPrivateAddresses: true\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pol, err := cfg.ScopePolicy()
	if err != nil {
		t.Fatalf("ScopePolicy: %v", err)
	}
	if !pol.CheckURL("http://localhost:3000/api/x").Allowed {
		t.Error("the target's own origin is not in scope")
	}
	if pol.CheckURL("http://localhost:9200/").Allowed {
		t.Error("a different port on the target host is in scope")
	}
	if pol.CheckURL("http://evil.test/").Allowed {
		t.Error("an unrelated host is in scope")
	}
}

// Alias expansion is a classic exponential-blowup denial of service.
func TestOversizedInputIsRefused(t *testing.T) {
	huge := strings.Repeat("#", MaxConfigBytes+10)
	if _, err := Parse(strings.NewReader(huge), "big.yaml"); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

func TestMalformedYAMLProducesAReadableError(t *testing.T) {
	_, err := parse(t, "target:\n  baseURL: [unclosed\n")
	if err == nil {
		t.Fatal("malformed YAML accepted")
	}
	if !strings.Contains(err.Error(), "test.yaml") {
		t.Errorf("error does not name the file: %v", err)
	}
}

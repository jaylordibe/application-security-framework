package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole point of the Secret type is that there is no accidental route from
// a credential to output. Each of these is a route Go offers by default.
func TestSecretNeverRendersItsValue(t *testing.T) {
	const value = "APPSEC_M1_SECRET_MUST_NEVER_PERSIST_7f91"
	s := NewSecret(value)

	type carrier struct {
		Name   string
		Token  Secret
		Nested struct{ Inner Secret }
	}
	c := carrier{Name: "admin", Token: s}
	c.Nested.Inner = s

	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Passed as an interface value, which is how a Secret would actually reach a
	// logging call, an error wrapper or a diagnostic print.
	var asAny any = s

	renderings := map[string]string{
		"String":     s.String(),
		"%v":         fmt.Sprintf("%v", asAny),
		"%s":         fmt.Sprintf("%s", asAny),
		"%q":         fmt.Sprintf("%q", asAny),
		"%#v":        fmt.Sprintf("%#v", asAny),
		"%+v struct": fmt.Sprintf("%+v", c),
		"%#v struct": fmt.Sprintf("%#v", c),
		"json":       string(encoded),
		"error":      fmt.Errorf("credential %v was rejected", asAny).Error(),
	}
	for name, got := range renderings {
		if strings.Contains(got, value) {
			t.Errorf("%s leaked the credential: %s", name, got)
		}
	}

	// Expose is the single deliberate route, and it must still work.
	if s.Expose() != value {
		t.Error("Expose did not return the credential")
	}
}

// A Secret must not be constructible by decoding untrusted input into a struct
// that happens to contain one.
func TestSecretRefusesToUnmarshal(t *testing.T) {
	var s Secret
	if err := json.Unmarshal([]byte(`"attacker-supplied"`), &s); err == nil {
		t.Fatal("a Secret was populated from JSON")
	}
	if !s.Empty() {
		t.Error("a refused unmarshal still set a value")
	}
}

func TestCredentialSourceResolve(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte("  file-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, MaxCredentialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("APPSEC_TEST_TOKEN", "env-credential")
	t.Setenv("APPSEC_TEST_BLANK", "   ")

	tests := []struct {
		name    string
		src     CredentialSource
		want    string
		wantErr string
	}{
		{name: "env", src: CredentialSource{Env: "APPSEC_TEST_TOKEN"}, want: "env-credential"},
		{name: "env missing", src: CredentialSource{Env: "APPSEC_TEST_ABSENT"}, wantErr: "is not set"},
		{name: "env blank", src: CredentialSource{Env: "APPSEC_TEST_BLANK"}, wantErr: "set but empty"},
		{name: "file trims whitespace", src: CredentialSource{File: good}, want: "file-credential"},
		{name: "file missing", src: CredentialSource{File: filepath.Join(dir, "nope")}, wantErr: "cannot read credential file"},
		{name: "file empty", src: CredentialSource{File: empty}, wantErr: "is empty"},
		{name: "file too large", src: CredentialSource{File: big}, wantErr: "exceeds"},
		{name: "nothing configured", src: CredentialSource{}, wantErr: "no credential source"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.Resolve()
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Expose() != tc.want {
				t.Errorf("resolved a different credential than expected")
			}
		})
	}
}

// A resolution failure is printed, logged and stored. It must name the location
// and never the value.
func TestResolveErrorsNeverContainTheCredential(t *testing.T) {
	dir := t.TempDir()
	huge := filepath.Join(dir, "huge")
	secret := strings.Repeat("SECRETVALUE", (MaxCredentialBytes/11)+2)
	if err := os.WriteFile(huge, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CredentialSource{File: huge}.Resolve()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("the error leaked file contents: %v", err)
	}
}

func bearer(id, env string) Identity {
	return Identity{
		ID:   id,
		Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: env}},
	}
}

func TestIdentityValidation(t *testing.T) {
	tests := []struct {
		name    string
		id      Identity
		wantErr string
	}{
		{name: "valid bearer", id: bearer("admin", "APPSEC_ADMIN_TOKEN")},
		{
			name: "valid api key",
			id: Identity{ID: "svc", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "X-API-Key",
				Credential: CredentialSource{Env: "APPSEC_SVC"},
			}},
		},
		{name: "missing id", id: bearer("", "APPSEC_X"), wantErr: "id is required"},
		{name: "reserved id", id: bearer("anonymous", "APPSEC_X"), wantErr: "reserved"},
		{name: "uppercase id", id: bearer("Admin", "APPSEC_X"), wantErr: "lowercase"},
		{name: "id with slash", id: bearer("a/b", "APPSEC_X"), wantErr: "lowercase"},
		{
			name:    "unknown scheme",
			id:      Identity{ID: "x", Auth: Authentication{Scheme: "oauth2", Credential: CredentialSource{Env: "E"}}},
			wantErr: "not one of bearer, apiKey",
		},
		{
			name:    "api key without header",
			id:      Identity{ID: "x", Auth: Authentication{Scheme: SchemeAPIKey, Credential: CredentialSource{Env: "E"}}},
			wantErr: "header is required",
		},
		{
			name: "header with CRLF is refused",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "X-Key\r\nInjected: 1",
				Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "not a valid HTTP header name",
		},
		{
			name: "header with colon is refused",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "X-Key: value",
				Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "not a valid HTTP header name",
		},
		{
			name: "header with space is refused",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "X Key",
				Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "not a valid HTTP header name",
		},
		{
			name: "Host may not carry a credential",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "Host", Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "may not carry a credential",
		},
		{
			name: "User-Agent may not carry a credential",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "User-Agent", Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "may not carry a credential",
		},
		{
			name: "value prefix with CRLF is refused",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeAPIKey, Header: "X-Key", ValuePrefix: "a\r\nX: b",
				Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "control characters",
		},
		{
			name: "bearer rejects a header",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeBearer, Header: "X-Key", Credential: CredentialSource{Env: "E"},
			}},
			wantErr: "applies only to the apiKey scheme",
		},
		{
			name:    "no credential source",
			id:      Identity{ID: "x", Auth: Authentication{Scheme: SchemeBearer}},
			wantErr: "one of env or file is required",
		},
		{
			name: "both credential sources",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeBearer, Credential: CredentialSource{Env: "E", File: "/f"},
			}},
			wantErr: "exactly one of env or file",
		},
		{
			name: "invalid env name",
			id: Identity{ID: "x", Auth: Authentication{
				Scheme: SchemeBearer, Credential: CredentialSource{Env: "not a var"},
			}},
			wantErr: "not a valid environment variable name",
		},
		{
			name: "liveness path must be absolute",
			id: func() Identity {
				i := bearer("x", "E")
				i.Live = Liveness{Path: "api/me"}
				return i
			}(),
			wantErr: "must begin with /",
		},
		{
			name: "liveness must be a safe method",
			id: func() Identity {
				i := bearer("x", "E")
				i.Live = Liveness{Path: "/api/me", Method: "DELETE"}
				return i
			}(),
			wantErr: "must be a safe method",
		},
		{
			name: "liveness status out of range",
			id: func() Identity {
				i := bearer("x", "E")
				i.Live = Liveness{Path: "/api/me", ExpectStatus: []int{99}}
				return i
			}(),
			wantErr: "is not an HTTP status",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			problems := tc.id.Validate("identities[0]")
			joined := strings.Join(problems, "\n")
			if tc.wantErr == "" {
				if len(problems) != 0 {
					t.Fatalf("expected no problems, got:\n%s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.wantErr) {
				t.Fatalf("problems %q do not mention %q", joined, tc.wantErr)
			}
		})
	}
}

// Identity ids key the coverage ledger. Two rows with the same key would make
// the ledger ambiguous about which principal a result belongs to.
func TestDuplicateIdentityIDsAreRejected(t *testing.T) {
	problems := ValidateAll([]Identity{
		bearer("admin", "APPSEC_A"),
		bearer("admin", "APPSEC_B"),
	})
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "duplicates") {
		t.Fatalf("duplicate ids were accepted: %q", joined)
	}
}

func TestValidateAllAcceptsDistinctIdentities(t *testing.T) {
	problems := ValidateAll([]Identity{
		bearer("admin", "APPSEC_A"),
		bearer("service", "APPSEC_B"),
	})
	if len(problems) != 0 {
		t.Fatalf("valid identities rejected: %v", problems)
	}
}

func TestLivenessAccepts(t *testing.T) {
	tests := []struct {
		name   string
		live   Liveness
		status int
		want   bool
	}{
		{name: "default accepts 200", live: Liveness{Path: "/me"}, status: 200, want: true},
		{name: "default accepts 204", live: Liveness{Path: "/me"}, status: 204, want: true},
		{name: "default rejects 401", live: Liveness{Path: "/me"}, status: 401, want: false},
		{name: "default rejects 302", live: Liveness{Path: "/me"}, status: 302, want: false},
		{name: "explicit list", live: Liveness{Path: "/me", ExpectStatus: []int{204}}, status: 204, want: true},
		{name: "explicit list excludes 200", live: Liveness{Path: "/me", ExpectStatus: []int{204}}, status: 200, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.live.Accepts(tc.status); got != tc.want {
				t.Errorf("Accepts(%d) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

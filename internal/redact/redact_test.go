package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestRegisteredSecretIsRemovedEverywhere(t *testing.T) {
	r := New()
	r.Register("s3cr3t-value-abcdef", "[TOKEN]")
	if got := r.String("prefix s3cr3t-value-abcdef suffix"); strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret survived redaction: %q", got)
	}
	if got := string(r.Bytes([]byte(`{"token":"s3cr3t-value-abcdef"}`))); strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret survived body redaction: %q", got)
	}
}

// A secret that travels base64- or percent-encoded must still be caught.
func TestEncodedFormsAreRedacted(t *testing.T) {
	r := New()
	r.Register("hunter2-hunter2-hunter2", "[TOKEN]")
	if got := r.String("aHVudGVyMi1odW50ZXIyLWh1bnRlcjI="); strings.Contains(got, "aHVudGVy") {
		t.Errorf("base64 form survived: %q", got)
	}
}

func TestShortValuesAreNotRegistered(t *testing.T) {
	r := New()
	r.Register("ok", "[X]")
	if got := r.String("this is ok to keep"); !strings.Contains(got, "ok") {
		t.Fatalf("a two-character secret redacted ordinary text: %q", got)
	}
}

func TestSensitiveHeadersAreReplacedEntirely(t *testing.T) {
	r := New()
	in := map[string][]string{
		"Authorization": {"Bearer abcdefghijklmnop"},
		"Cookie":        {"session=abcdefghijklmnop"},
		"Accept":        {"application/json"},
	}
	out := r.Header(in)
	if out["Authorization"][0] != Placeholder {
		t.Error("Authorization not redacted")
	}
	if out["Cookie"][0] != Placeholder {
		t.Error("Cookie not redacted")
	}
	if out["Accept"][0] != "application/json" {
		t.Error("a harmless header was altered")
	}
	// The input must not be mutated.
	if in["Authorization"][0] == Placeholder {
		t.Error("input header map was mutated")
	}
}

// A credential the target issues mid-run must be redacted from later captures.
func TestRuntimeCredentialsAreLearned(t *testing.T) {
	r := New()
	r.Header(map[string][]string{"Set-Cookie": {"sid=abcdef0123456789xyz; Path=/; HttpOnly"}})
	if got := r.String("later body mentioning abcdef0123456789xyz"); strings.Contains(got, "abcdef0123456789xyz") {
		t.Fatalf("runtime-issued cookie value was not learned: %q", got)
	}
}

func TestBearerTokenValueIsLearnedWithoutScheme(t *testing.T) {
	r := New()
	r.Header(map[string][]string{"Authorization": {"Bearer tok-abcdef0123456789"}})
	if got := r.String("body with tok-abcdef0123456789"); strings.Contains(got, "tok-abcdef") {
		t.Fatalf("bearer token value not learned: %q", got)
	}
}

func TestHighSignalPatternsRedactedWithoutRegistration(t *testing.T) {
	r := New()
	cases := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
		"sk_live_abcdefghijklmnop",
		"ghp_abcdefghijklmnopqrstuvwxyz12",
		"AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, c := range cases {
		if got := r.String("value: " + c); strings.Contains(got, c) {
			t.Errorf("unregistered secret %q survived: %q", c, got)
		}
	}
}

func TestURLRedactsCredentialsAndSensitiveParams(t *testing.T) {
	r := New()
	got := r.URL("https://user:pw@api.example.com/x?api_key=abcdef0123456789&page=2")
	if strings.Contains(got, "abcdef0123456789") || strings.Contains(got, "pw@") {
		t.Fatalf("url leaked a secret: %q", got)
	}
	if !strings.Contains(got, "page=2") {
		t.Errorf("harmless parameter lost: %q", got)
	}
}

// Go's *url.Error renders the full URL including its query string, so error
// text is a real leak channel.
func TestErrorStringsHaveQueryStringsStripped(t *testing.T) {
	r := New()
	err := errors.New(`Get "https://api.example.com/x?api_key=abcdef0123456789": dial tcp: refused`)
	got := r.Error(err)
	if strings.Contains(got, "abcdef0123456789") {
		t.Fatalf("error text leaked a query secret: %q", got)
	}
	if !strings.Contains(got, "dial tcp") {
		t.Errorf("diagnostic detail was lost: %q", got)
	}
}

// A bare hash of a low-entropy value is brute-forceable by anyone holding the
// report, so short values must not be fingerprinted at all.
func TestShortValuesAreNotFingerprinted(t *testing.T) {
	r := New()
	for _, v := range []string{"1234", "000000", "admin"} {
		got := r.Fingerprint(v)
		if !strings.HasPrefix(got, "short:") {
			t.Errorf("Fingerprint(%q) = %q, want a length bucket only", v, got)
		}
		if strings.Contains(got, v) {
			t.Errorf("Fingerprint(%q) leaked the value: %q", v, got)
		}
	}
}

func TestFingerprintIsStableWithinRunAndDiffersAcrossRuns(t *testing.T) {
	a := New()
	value := "a-sufficiently-long-secret-value"
	first, second := a.Fingerprint(value), a.Fingerprint(value)
	if first != second {
		t.Errorf("fingerprint is not stable within a run: %q vs %q", first, second)
	}
	b := New()
	if a.Fingerprint(value) == b.Fingerprint(value) {
		t.Error("fingerprint is identical across runs; secrets would be correlatable between reports")
	}
}

func TestFingerprintDoesNotContainTheValue(t *testing.T) {
	r := New()
	value := "correct-horse-battery-staple"
	if strings.Contains(r.Fingerprint(value), value) {
		t.Fatal("fingerprint contains the secret")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	r := New()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				r.Register("secret-value-number-abcdef", "[T]")
				_ = r.String("body with secret-value-number-abcdef")
				_ = r.Header(map[string][]string{"Authorization": {"Bearer abcdefghijklmnop"}})
				_ = r.Fingerprint("a-sufficiently-long-secret-value")
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// A long authentication scheme puts the credential past the point a fixed prefix
// heuristic would look, so the token must still be learned.
func TestLongAuthSchemesAreLearned(t *testing.T) {
	cases := map[string]string{
		"Authorization": "SharedAccessSignature sr=x&sig=abcdef0123456789abcdef",
		"X-Auth-Token":  "AWS4-HMAC-SHA256 Credential=abcdef0123456789/x, Signature=fedcba9876543210",
	}
	for header, value := range cases {
		r := New()
		r.Header(map[string][]string{header: {value}})
		secret := strings.Fields(value)[1]
		if got := r.String("later body with " + secret); strings.Contains(got, secret) {
			t.Errorf("%s: credential %q was not learned: %q", header, secret, got)
		}
	}
}

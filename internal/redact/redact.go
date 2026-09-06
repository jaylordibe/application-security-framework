// Package redact removes secrets from data before it is stored.
//
// Redaction happens at capture time, not at render time, so that a secret never
// reaches disk in the first place (threat model T-06). This package is a
// zero-dependency leaf: it operates on bytes, strings and header maps, and
// imports nothing but the standard library.
//
// Redaction is a mitigation, not a guarantee. It uses a deny-list of header
// names, operator-registered values, values learned at runtime, and a small set
// of high-signal token patterns. It will not catch every bespoke secret format,
// and AppSec Framework's documentation says so rather than implying safety.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Placeholder replaces a redacted value.
const Placeholder = "[REDACTED]"

// minFingerprintLength is the shortest value that will be fingerprinted.
//
// A fingerprint of a low-entropy value is offline-guessable: anyone holding the
// report can hash candidate PINs, six-digit codes or numeric identifiers and
// confirm a match. Below this length we emit only a type and a length bucket.
const minFingerprintLength = 16

// sensitiveHeaders are redacted wherever they appear, matched
// case-insensitively.
var sensitiveHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"api-key",
	"x-auth-token",
	"x-access-token",
	"x-csrf-token",
	"x-xsrf-token",
	"x-session-token",
	"x-amz-security-token",
	"authentication",
	"www-authenticate",
	"proxy-authenticate",
}

// sensitiveQueryParams are redacted from URLs.
var sensitiveQueryParams = []string{
	"access_token", "api_key", "apikey", "auth", "code", "id_token",
	"key", "password", "refresh_token", "secret", "session", "sig",
	"signature", "token",
}

// tokenPatterns match high-signal secret shapes that should be redacted even
// when the operator never registered them.
var tokenPatterns = []*regexp.Regexp{
	// JWT: three base64url segments.
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`),
	// Common vendor key prefixes.
	regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}`),
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	// PEM private key blocks.
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

// Redactor removes registered and pattern-matched secrets from data.
//
// A Redactor is safe for concurrent use. Values learned during a run are added
// to the deny-list so that a credential the target issues mid-run — a session
// cookie, a refresh token — is redacted from every later capture.
type Redactor struct {
	mu sync.RWMutex
	// secrets maps a secret value to the label reported in its place.
	secrets map[string]string
	// extraHeaders holds header names registered at run start because the
	// operator declared that they carry a credential. They are lowercased.
	//
	// This exists so that a bespoke API-key header is redacted by name as well
	// as by value. Redacting by value alone would leave the header readable if a
	// target echoed only a prefix of the credential, and blanket-redacting every
	// unrecognised header would destroy the evidence the report exists to carry.
	// Registering exactly the headers the operator said are credentials is the
	// precise middle.
	extraHeaders map[string]struct{}
	// fingerprintKey is generated per run and never written to a report, so a
	// fingerprint cannot be correlated across runs or brute-forced offline
	// without access to the run directory.
	fingerprintKey []byte
}

// New returns a Redactor with a freshly generated per-run fingerprint key.
func New() *Redactor {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failure is not recoverable and must not silently
		// degrade to a keyless hash, which would be offline-guessable.
		panic("redact: cannot generate fingerprint key: " + err.Error())
	}
	return &Redactor{
		secrets:        make(map[string]string),
		extraHeaders:   make(map[string]struct{}),
		fingerprintKey: key,
	}
}

// RegisterSensitiveHeader marks a header name as carrying a credential, so its
// value is replaced entirely wherever it appears rather than only where it
// matches a known secret.
func (r *Redactor) RegisterSensitiveHeader(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.extraHeaders == nil {
		r.extraHeaders = make(map[string]struct{})
	}
	r.extraHeaders[name] = struct{}{}
}

// sensitiveHeader reports whether a header must have its value replaced, taking
// both the built-in deny-list and run-registered names into account.
func (r *Redactor) sensitiveHeader(name string) bool {
	if isSensitiveHeader(name) {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.extraHeaders[lower]
	return ok
}

// FingerprintKey returns the per-run key. It is stored alongside a run so that
// fingerprints remain correlatable within that run, and it must never be written
// into a report.
func (r *Redactor) FingerprintKey() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]byte, len(r.fingerprintKey))
	copy(out, r.fingerprintKey)
	return out
}

// Register adds a secret value to the deny-list. Short values are ignored: a
// one- or two-character "secret" would redact ordinary text everywhere and make
// evidence useless.
func (r *Redactor) Register(value, label string) {
	if len(value) < 4 {
		return
	}
	if label == "" {
		label = Placeholder
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets[value] = label
	// Also register encoded forms, so a secret that travels base64- or
	// percent-encoded is still caught.
	if enc := base64.StdEncoding.EncodeToString([]byte(value)); len(enc) >= 4 {
		r.secrets[enc] = label
	}
	if enc := url.QueryEscape(value); enc != value && len(enc) >= 4 {
		r.secrets[enc] = label
	}
}

// registered returns a snapshot of the deny-list ordered longest-first, so that
// a longer secret containing a shorter one is replaced first.
func (r *Redactor) registered() [][2]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([][2]string, 0, len(r.secrets))
	for v, label := range r.secrets {
		out = append(out, [2]string{v, label})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i][0]) != len(out[j][0]) {
			return len(out[i][0]) > len(out[j][0])
		}
		return out[i][0] < out[j][0]
	})
	return out
}

// String redacts registered secrets and pattern-matched tokens from s.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	for _, kv := range r.registered() {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	for _, re := range tokenPatterns {
		s = re.ReplaceAllString(s, Placeholder)
	}
	return s
}

// Bytes redacts a body. Bodies are treated as text for redaction purposes;
// binary content is unaffected in practice because the patterns do not match it.
func (r *Redactor) Bytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	return []byte(r.String(string(b)))
}

// Header redacts a header map, replacing sensitive header values entirely and
// redacting secrets from the rest. The returned map is a copy; the input is not
// modified.
//
// Values of sensitive headers are also registered, so the same value is redacted
// if it later appears in a body or a URL.
func (r *Redactor) Header(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		if r.sensitiveHeader(name) {
			for _, v := range values {
				r.learn(name, v)
			}
			out[name] = []string{Placeholder}
			continue
		}
		cp := make([]string, 0, len(values))
		for _, v := range values {
			cp = append(cp, r.String(v))
		}
		out[name] = cp
	}
	return out
}

// learn registers a credential observed at runtime so that later captures redact
// it too. Cookie headers carry name=value pairs; the value is the secret.
func (r *Redactor) learn(name, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	lower := strings.ToLower(name)
	if lower == "cookie" || lower == "set-cookie" {
		for _, part := range strings.Split(value, ";") {
			if eq := strings.IndexByte(part, '='); eq > 0 {
				r.Register(strings.TrimSpace(part[eq+1:]), Placeholder)
			}
		}
		return
	}
	// Register the whole value, and every substantial whitespace-delimited field
	// within it. Guessing which prefix is a scheme fails for long schemes such as
	// "SharedAccessSignature" or "AWS4-HMAC-SHA256"; registering each field is
	// both simpler and more complete.
	r.Register(value, Placeholder)
	fields := strings.Fields(value)
	for i, f := range fields {
		if len(f) >= 16 {
			r.Register(f, Placeholder)
		}
		// The remainder after a leading scheme token is often the credential.
		if i == 0 && len(fields) > 1 {
			rest := strings.TrimSpace(strings.TrimPrefix(value, f))
			if len(rest) >= 8 {
				r.Register(rest, Placeholder)
			}
		}
	}
}

// URL redacts a URL for display: userinfo is removed and sensitive query
// parameter values are replaced.
//
// This matters because Go's *url.Error renders the full URL, query string
// included, so any transport failure would otherwise write "?api_key=..." into
// an evidence record.
func (r *Redactor) URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable input is still run through value redaction rather than
		// returned verbatim.
		return r.String(raw)
	}
	if u.User != nil {
		u.User = url.User(Placeholder)
	}
	if q := u.Query(); len(q) > 0 {
		changed := false
		for key := range q {
			if isSensitiveQueryParam(key) {
				q.Set(key, Placeholder)
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	return r.String(u.String())
}

// Error renders an error as a redacted string, with any query string stripped
// from URLs it mentions. Never store an error's raw text in evidence.
func (r *Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(stripQueryStrings(err.Error()))
}

// urlInText matches URLs appearing inside free text such as error strings.
var urlInText = regexp.MustCompile(`https?://[^\s"']+`)

// stripQueryStrings removes the query portion of any URL found in text.
func stripQueryStrings(s string) string {
	return urlInText.ReplaceAllStringFunc(s, func(m string) string {
		if i := strings.IndexByte(m, '?'); i >= 0 {
			return m[:i] + "?" + Placeholder
		}
		return m
	})
}

// Fingerprint returns a stable, non-reversible label for a value, so that the
// same secret can be correlated across evidence within one run without the value
// being recorded.
//
// It is an HMAC under the per-run key, truncated to 64 bits. Values shorter than
// minFingerprintLength are not fingerprinted at all, because a bare hash of a
// low-entropy value can be brute-forced by anyone holding the report.
func (r *Redactor) Fingerprint(value string) string {
	if len(value) < minFingerprintLength {
		return "short:" + lengthBucket(len(value))
	}
	r.mu.RLock()
	key := r.fingerprintKey
	r.mu.RUnlock()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return "fp:" + hex.EncodeToString(mac.Sum(nil)[:8])
}

// lengthBucket coarsens a length so that it does not narrow a guessing space.
func lengthBucket(n int) string {
	switch {
	case n == 0:
		return "0"
	case n < 8:
		return "1-7"
	case n < 16:
		return "8-15"
	default:
		return "16+"
	}
}

// isSensitiveHeader reports whether a header's value must be replaced entirely.
func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, h := range sensitiveHeaders {
		if lower == h {
			return true
		}
	}
	return false
}

// isSensitiveQueryParam reports whether a query parameter's value must be
// replaced.
func isSensitiveQueryParam(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, p := range sensitiveQueryParams {
		if lower == p {
			return true
		}
	}
	return false
}

// SensitiveHeaderNames returns the header deny-list, for documentation and
// tests.
func SensitiveHeaderNames() []string {
	out := make([]string, len(sensitiveHeaders))
	copy(out, sensitiveHeaders)
	return out
}

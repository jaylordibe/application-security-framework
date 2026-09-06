package discovery

import "strings"

// PathLiterals extracts path-like string literals from JavaScript.
//
// The extraction is deliberately dumb, and every part of that is a decision.
//
// It does not parse JavaScript. A real parser would be a large dependency
// carrying a large attack surface, and it would still not tell us which strings
// are routes: a bundler has already inlined, renamed and concatenated
// everything, so "which fetch() calls exist" is not recoverable from the bundle
// anyway. What is recoverable is that the literal exists in code the target
// served, and that is exactly what a candidate claims.
//
// It uses no regular expression. This input is a target-controlled file of up to
// several megabytes, and the usual URL-matching regex — alternation plus
// unbounded repetition — is a catastrophic-backtracking denial of service handed
// to whoever we are auditing. Everything below is a single left-to-right pass
// with no lookahead beyond one byte.
//
// It extracts only literals that look like absolute paths. Requiring a leading
// "/" and at least one more character discards the overwhelming majority of a
// bundle's strings — CSS class names, error messages, property names — while
// keeping the shape that a route actually has. It is not an attempt to find
// every route; it is an attempt to find some, without inventing any.
func PathLiterals(body []byte, limits Limits) (paths []string, truncated bool) {
	s := string(body)
	seen := map[string]struct{}{}
	n := len(s)
	i := 0

	for i < n {
		c := s[i]
		if c != '"' && c != '\'' && c != '`' {
			i++
			continue
		}
		quote := c
		i++
		start := i
		// Scan to the closing quote, honouring escapes. A literal that runs past
		// the budget is abandoned rather than truncated into a fake path.
		for i < n {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == quote || s[i] == '\n' {
				break
			}
			if i-start > limits.MaxPathLength {
				break
			}
			i++
		}
		if i >= n {
			break
		}
		if s[i] != quote {
			// Unterminated or over-long: skip it and continue from here rather
			// than rescanning, so the pass stays linear.
			i++
			continue
		}
		literal := s[start:i]
		i++

		p := normalizeLiteralPath(literal, limits)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		if len(seen) >= limits.MaxCandidatesPerSource {
			return sortedUnique(seen), true
		}
		seen[p] = struct{}{}
	}
	return sortedUnique(seen), false
}

// normalizeLiteralPath decides whether a string literal is a usable path
// candidate, and returns its structural form.
func normalizeLiteralPath(v string, limits Limits) string {
	if len(v) < 2 || len(v) > limits.MaxPathLength {
		return ""
	}
	if v[0] != '/' {
		// Only absolute paths. A relative literal ("users") is indistinguishable
		// from a property name, and resolving it against a base we are guessing
		// would fabricate a path the application never contained.
		return ""
	}
	if strings.HasPrefix(v, "//") {
		// "//cdn.example.com/x" is a protocol-relative URL to another origin,
		// not a path on this one.
		return ""
	}
	// Drop query and fragment before anything is retained. A discovered URL is
	// one of the likeliest places to find a session token, a signed parameter or
	// a password-reset nonce, and this type exists to carry structure rather
	// than to harvest them.
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	if v == "" || v == "/" {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		// Control characters, whitespace and quote characters do not appear in a
		// path that was actually requested; a literal containing them is prose,
		// a template fragment, or an attempt to inject into whatever renders it.
		if c < 0x21 || c == 0x7f || c == '"' || c == '\'' || c == '<' || c == '>' || c == '\\' {
			return ""
		}
	}
	// A bundler emits many "/" strings that are file paths, not routes. Those
	// with a source-file extension are dropped: they describe the build, not the
	// application's surface.
	if hasBuildExtension(v) {
		return ""
	}
	return v
}

// buildExtensions are file suffixes that indicate a build artefact rather than
// an application route.
var buildExtensions = []string{
	".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".map", ".css", ".scss",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".wasm",
}

func hasBuildExtension(p string) bool {
	lower := strings.ToLower(p)
	for _, ext := range buildExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

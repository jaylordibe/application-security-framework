// Command appsec-adapter-laravel reports normalized security facts about a
// Laravel application.
//
// It reads source and never executes it. That is a deliberate and consequential
// choice, because the higher-fidelity option is worse than it looks: `php
// artisan route:list` requires vendor/autoload.php and then boots the whole
// framework, registering and booting every service provider the repository
// defines. On a repository AppSec did not write, that is arbitrary code
// execution wearing the costume of a read-only query. Worse, a fresh checkout
// has no vendor/ at all, so using artisan first requires `composer install`,
// whose post-autoload-dump hook in this project's own reference application
// runs `@php artisan package:discover` — the install itself boots the app.
//
// So this adapter is the static tier. Its facts are graded `inferred`, never
// `declared`, and everything it cannot resolve is reported as a limitation
// rather than guessed at.
package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/adapters/internal/source"
	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

// Laravel's security semantics, which exist here and nowhere in the core.
//
// A Laravel route is protected when an authentication middleware applies to it,
// either directly or through an enclosing group. Absence of that middleware is
// *not* proof of a public route: middleware can also be attached in a
// controller constructor, in a route-service provider, or globally in
// bootstrap/app.php, none of which this tier reads. That asymmetry is the most
// important thing this file knows, and it is why `public` is only ever reported
// for routes reached through a group this adapter actually saw.

// authMiddleware are the middleware names that mean "a caller must be
// authenticated". `auth` covers `auth:api`, `auth:sanctum` and friends.
var authMiddleware = []string{"auth", "auth.basic", "authenticate", "jwt.auth", "auth.session"}

// authorizationMiddleware are the names that mean "a control beyond
// authentication applies". `can:` is Laravel's gate/policy middleware.
var authorizationMiddleware = []string{"can", "authorize", "permission", "role", "role_or_permission"}

var (
	// A route registration: Route::get('path', ...) or ->get('path', ...).
	routeRe = regexp.MustCompile(`(?:Route::|->)(get|post|put|patch|delete|options|any|match)\s*\(`)
	// A middleware clause: middleware('x') or middleware(['x', 'y']).
	middlewareRe = regexp.MustCompile(`middleware\s*\(\s*(\[[^\]]*\]|'[^']*'|"[^"]*")`)
	// A prefix clause: prefix('x').
	prefixRe = regexp.MustCompile(`prefix\s*\(\s*['"]([^'"]*)['"]`)
	// A controller reference: [FooController::class, 'method'].
	controllerRe = regexp.MustCompile(`\[\s*([A-Za-z_][A-Za-z0-9_]*)::class\s*,\s*['"]([^'"]+)['"]\s*\]`)
	// A quoted string literal.
	stringRe = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
	// Gate::authorize(...) or $this->authorize(...) inside a controller body.
	authorizeCallRe = regexp.MustCompile(`(?:Gate::authorize|Gate::allows|Gate::denies|\$this->authorize|\$this->authorizeResource)\s*\(\s*([^),]*)`)
	// A PHP method declaration.
	phpMethodRe = regexp.MustCompile(`function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	// A dynamic value where a literal was expected.
	dynamicRe = regexp.MustCompile(`\bconfig\s*\(|\benv\s*\(|\$[A-Za-z_]`)
)

// scope is one enclosing Route::group.
type scope struct {
	depth      int
	middleware []string
	prefix     string
}

// routeDecl is a route found in the source.
type routeDecl struct {
	method     string
	path       string
	middleware []string
	controller string
	action     string
	file       string
	line       int
	// dynamicPath is true when the path or its constraints came from something
	// this tier cannot evaluate.
	dynamicPath bool
}

// apiPrefixRe finds a custom API prefix in bootstrap/app.php.
var apiPrefixRe = regexp.MustCompile(`apiPrefix\s*:\s*['"]([^'"]*)['"]`)

// routeFilePrefix returns the URL prefix Laravel applies to a route file.
//
// This is routing convention, not a security fact, and getting it wrong makes
// every fact useless: an operation identified as /users/{id} never matches the
// specification's /api/users/{id}, so the adapter would silently corroborate
// nothing. Laravel's withRouting(api: ...) applies an "api" prefix by default,
// configurable via apiPrefix; routes/web.php gets none.
func routeFilePrefix(tree source.Tree, path string) (prefix string, known bool) {
	switch {
	case path == "routes/api.php":
		for _, f := range tree.Files {
			if f.Path != "bootstrap/app.php" {
				continue
			}
			for _, line := range f.Lines {
				if m := apiPrefixRe.FindStringSubmatch(line); m != nil {
					return m[1], true
				}
			}
		}
		return "api", true
	case path == "routes/web.php", path == "routes/console.php":
		return "", true
	default:
		// Some other route file. Laravel does not mount it by convention, so
		// the prefix depends on how the application registered it.
		return "", false
	}
}

// extract turns a Laravel source tree into normalized facts.
func extract(tree source.Tree) ([]adapter.Fact, []string) {
	limits := map[string]struct{}{}
	note := func(s string) { limits[s] = struct{}{} }
	for _, l := range tree.Limitations {
		note(l)
	}

	var routes []routeDecl
	controllers := map[string]map[string][]string{} // class -> method -> authorization controls

	for _, f := range tree.Files {
		switch {
		case f.Path == "routes/console.php":
			// Console routes are commands, not HTTP operations.
		case strings.HasPrefix(f.Path, "routes/"):
			prefix, known := routeFilePrefix(tree, f.Path)
			if !known {
				note(f.Path + " is not a route file Laravel mounts by convention, so the URL " +
					"prefix it is registered under is unknown and its routes were not reported")
				continue
			}
			rs, ls := parseRoutes(f, prefix)
			routes = append(routes, rs...)
			for _, l := range ls {
				note(l)
			}
		case strings.Contains(f.Path, "Http/Controllers/"):
			class, methods := parseController(f)
			if class != "" {
				controllers[class] = methods
			}
		}
	}

	if len(routes) == 0 {
		note("no route declarations were found under routes/; this adapter reads route files " +
			"statically and does not see routes registered from a service provider or a package")
	}
	note("middleware attached in a controller constructor, a route-service provider or the " +
		"application bootstrap is not visible to static extraction, so a route with no " +
		"authentication middleware in its route file is reported as public only when this " +
		"adapter saw the group it belongs to")
	note("a Laravel policy or gate decides access at runtime and its basis — ownership, role, " +
		"or something else — is not determinable without executing it, so no ownership fact " +
		"is reported")

	var facts []adapter.Fact
	for _, r := range routes {
		if r.dynamicPath {
			// The path is computed, so this route cannot be named. Emitting a
			// fact anyway would attach it to whatever operation the guessed
			// path happens to collide with, which is worse than silence — so
			// the route becomes a stated limitation instead.
			note(fmt.Sprintf("%s:%d registers a route whose path is computed at runtime; the "+
				"operation could not be identified and no fact was reported for it",
				r.file, r.line))
			continue
		}
		opPath := r.path
		ev := adapter.Evidence{File: r.file, Line: r.line}

		// Authentication.
		authValue := adapter.AuthenticationPublic
		detail := "no authentication middleware applies to this route in its route file"
		if m, ok := firstMatching(r.middleware, authMiddleware); ok {
			authValue = adapter.AuthenticationRequired
			detail = "the route is inside a middleware group applying " + m
		}
		facts = append(facts, adapter.Fact{
			Kind:      adapter.KindAuthentication,
			Operation: adapter.OperationRef{Method: r.method, Path: opPath},
			Value:     authValue,
			Evidence:  adapter.Evidence{File: ev.File, Line: ev.Line, Detail: detail},
		})

		// Authorization: middleware first, then the controller body.
		control, where, found := "", "", false
		if m, ok := firstMatching(r.middleware, authorizationMiddleware); ok {
			control, where, found = m, "middleware "+m, true
		} else if methods, ok := controllers[r.controller]; ok {
			if ctrls, has := methods[r.action]; has && len(ctrls) > 0 {
				control = ctrls[0]
				where = "an authorization call in " + r.controller + "::" + r.action
				found = true
			}
		}
		value := adapter.AuthorizationAbsent
		adetail := "no authorization middleware applies and no authorization call was found in " +
			"the controller action"
		if found {
			value = adapter.AuthorizationPresent
			adetail = "authorization is applied by " + where
		}
		if r.controller != "" {
			if _, known := controllers[r.controller]; !known && !found {
				// The handler was not among the files read, so absence of an
				// authorization call is ignorance rather than evidence.
				value = adapter.ValueUnknown
				adetail = "the controller " + r.controller + " was not found in the inspected " +
					"source, so its authorization behaviour is unknown"
			}
		}
		facts = append(facts, adapter.Fact{
			Kind:      adapter.KindAuthorization,
			Operation: adapter.OperationRef{Method: r.method, Path: opPath},
			Value:     value,
			Control:   control,
			Evidence:  adapter.Evidence{File: ev.File, Line: ev.Line, Detail: adetail},
		})
	}

	out := make([]string, 0, len(limits))
	for l := range limits {
		out = append(out, l)
	}
	sort.Strings(out)
	return facts, out
}

// parseRoutes reads one route file.
//
// It works on *statements* rather than lines. A Laravel route chain routinely
// spans several lines —
//
//	Route::delete('/{orderId}', [OrderController::class, 'destroy'])
//	    ->middleware('can:delete,order');
//
// — so a line-oriented parser sees the registration and never sees the
// middleware that authorizes it. That failure mode is silent and it is the
// dangerous direction: it reports an authorized route as having no
// authorization control.
//
// Brace depth is tracked across statements, with strings and comments masked
// first, so a brace inside a route path cannot unbalance the group stack.
func parseRoutes(f source.File, filePrefix string) ([]routeDecl, []string) {
	var routes []routeDecl
	var limits []string
	// The file's own mount prefix is the outermost scope, so every route in it
	// inherits it exactly as a group prefix would be inherited.
	stack := []scope{{depth: -1, prefix: filePrefix}}
	depth := 0
	inBlockComment := false

	var stmtRaw strings.Builder
	var stmtCode strings.Builder
	stmtLine := 0

	flush := func() {
		raw, code := stmtRaw.String(), stmtCode.String()
		stmtRaw.Reset()
		stmtCode.Reset()
		if strings.TrimSpace(code) == "" {
			depth += braceDelta(code)
			return
		}

		pendingMiddleware := middlewareNames(raw)
		pendingPrefix := ""
		if m := prefixRe.FindStringSubmatch(raw); m != nil {
			pendingPrefix = m[1]
		}
		isGroup := strings.Contains(code, "group")

		if match := routeRe.FindStringSubmatchIndex(code); match != nil && !isGroup {
			verb := code[match[2]:match[3]]
			path, dynamic := routePath(raw)
			for _, method := range httpMethods(verb) {
				r := routeDecl{
					method:      method,
					path:        joinPath(currentPrefix(stack), path),
					middleware:  append(currentMiddleware(stack), pendingMiddleware...),
					file:        f.Path,
					line:        stmtLine,
					dynamicPath: dynamic,
				}
				if c := controllerRe.FindStringSubmatch(raw); c != nil {
					r.controller, r.action = c[1], c[2]
				}
				routes = append(routes, r)
			}
			if verb == "any" || verb == "match" {
				limits = append(limits, "a Route::"+verb+" registration in "+f.Path+
					" covers several HTTP methods; only GET was reported, to avoid inventing "+
					"operations the application may not serve")
			}
		}

		delta := braceDelta(code)
		if isGroup && delta > 0 {
			stack = append(stack, scope{
				depth:      depth,
				middleware: append(currentMiddleware(stack), pendingMiddleware...),
				prefix:     joinPath(currentPrefix(stack), pendingPrefix),
			})
		}
		depth += delta
		for len(stack) > 1 && depth <= stack[len(stack)-1].depth {
			stack = stack[:len(stack)-1]
		}
	}

	for i, raw := range f.Lines {
		code, stillInComment := maskLine(raw, inBlockComment)
		inBlockComment = stillInComment
		if stmtRaw.Len() == 0 {
			stmtLine = i + 1
		}
		stmtRaw.WriteString(raw)
		stmtRaw.WriteString(" ")
		stmtCode.WriteString(code)
		stmtCode.WriteString(" ")

		// A statement ends at a semicolon, or at a brace that opens or closes a
		// block. Anything else is a continuation of the same chain.
		if strings.ContainsAny(code, ";{}") {
			flush()
		}
	}
	flush()

	if f.Truncated {
		limits = append(limits, f.Path+" was read only in part, so routes after the cut are missing")
	}
	return routes, limits
}

// parseController finds authorization calls per method.
func parseController(f source.File) (string, map[string][]string) {
	class := strings.TrimSuffix(pathBase(f.Path), ".php")
	methods := map[string][]string{}
	current := ""
	for _, raw := range f.Lines {
		if m := phpMethodRe.FindStringSubmatch(raw); m != nil {
			current = m[1]
			continue
		}
		if current == "" {
			continue
		}
		if m := authorizeCallRe.FindStringSubmatch(raw); m != nil {
			control := strings.TrimSpace(m[1])
			control = strings.Trim(control, `'"`)
			if control == "" {
				control = "authorize"
			}
			methods[current] = append(methods[current], control)
		}
	}
	return class, methods
}

// maskLine blanks string literals and comments so structural characters can be
// counted without a brace or semicolon inside a string ending a statement.
func maskLine(line string, inBlockComment bool) (string, bool) {
	var code strings.Builder
	var quote byte
	escaped := false

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inBlockComment:
			if c == '*' && i+1 < len(line) && line[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		case quote != 0:
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
				code.WriteByte(' ')
			}
			continue
		case c == '\'' || c == '"':
			quote = c
			continue
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return code.String(), false
		case c == '#':
			return code.String(), false
		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			inBlockComment = true
			i++
			continue
		}
		code.WriteByte(c)
	}
	return code.String(), inBlockComment
}

// braceDelta counts net brace nesting on a masked line.
func braceDelta(code string) int {
	return strings.Count(code, "{") - strings.Count(code, "}")
}

// routePath returns the route's path literal and whether it was computed.
func routePath(raw string) (string, bool) {
	idx := routeRe.FindStringIndex(raw)
	if idx == nil {
		return "", true
	}
	rest := raw[idx[1]:]
	loc := stringRe.FindStringIndex(rest)
	if loc == nil {
		// The first argument is not a string at all.
		return "", true
	}
	// Anything between the opening parenthesis and the first string literal
	// means the literal is an argument to something else — config('x'),
	// env('y'), a variable, a concatenation. The literal is then not the path,
	// and taking it would name an operation the application never serves.
	if before := strings.TrimSpace(rest[:loc[0]]); before != "" {
		return "", true
	}
	m := stringRe.FindStringSubmatch(rest)
	p := m[1]
	if p == "" {
		p = m[2]
	}
	// A concatenated or interpolated path is likewise not knowable statically.
	after := rest[loc[1]:]
	if trimmed := strings.TrimSpace(after); strings.HasPrefix(trimmed, ".") ||
		dynamicRe.MatchString(p) {
		return "", true
	}
	return p, false
}

// middlewareNames extracts middleware names from a line.
func middlewareNames(raw string) []string {
	m := middlewareRe.FindStringSubmatch(raw)
	if m == nil {
		return nil
	}
	var out []string
	for _, lit := range stringRe.FindAllStringSubmatch(m[1], -1) {
		v := lit[1]
		if v == "" {
			v = lit[2]
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// firstMatching returns the first middleware whose name matches a known family.
//
// Laravel middleware carries parameters after a colon — `auth:api`,
// `can:update,post` — so the family is the part before it.
func firstMatching(applied, families []string) (string, bool) {
	for _, a := range applied {
		name := a
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		for _, f := range families {
			if strings.EqualFold(name, f) {
				return a, true
			}
		}
	}
	return "", false
}

func currentMiddleware(stack []scope) []string {
	if len(stack) == 0 {
		return nil
	}
	top := stack[len(stack)-1].middleware
	out := make([]string, len(top))
	copy(out, top)
	return out
}

func currentPrefix(stack []scope) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1].prefix
}

// joinPath composes a group prefix with a route path.
func joinPath(prefix, path string) string {
	prefix = strings.Trim(prefix, "/")
	path = strings.Trim(path, "/")
	switch {
	case prefix == "" && path == "":
		return "/"
	case prefix == "":
		return "/" + path
	case path == "":
		return "/" + prefix
	}
	return "/" + prefix + "/" + path
}

// httpMethods expands a Laravel verb into HTTP methods.
func httpMethods(verb string) []string {
	switch strings.ToLower(verb) {
	case "any", "match":
		// Conservative: only the safe method is claimed. Claiming every method
		// would invent operations the application may not serve.
		return []string{"GET"}
	default:
		return []string{strings.ToUpper(verb)}
	}
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Command appsec-adapter-nestjs reports normalized security facts about a
// NestJS application.
//
// Like the Laravel adapter, it reads source and never executes it, and for a
// sharper reason: in NestJS, importing a module *is* executing it. Decorators
// run at import time, and this project's own reference application calls
// startTelemetry() at the top of main.ts, which patches http, pg and ioredis
// before bootstrap() is ever called. A "probe" that imports the application to
// read its metadata would therefore open database and network machinery on a
// repository nobody vouched for. On a fresh checkout it could not even do that,
// because node_modules is absent and installing it runs lifecycle scripts.
//
// So this is the static tier, graded `inferred`.
package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/adapters/internal/source"
	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

// NestJS security semantics, which exist here and nowhere in the core.
//
// The important asymmetry with Laravel: NestJS applications commonly register a
// global authentication guard, which makes authentication the default and turns
// @Public() into the opt-out. So the same syntactic absence means opposite
// things in the two frameworks — a route with no auth decorator is protected
// here and unprotected there. That reasoning is exactly what must never reach
// the core, and it is why the contract carries conclusions rather than
// framework constructs.

var (
	// A global guard registration: { provide: APP_GUARD, useClass: JwtAuthGuard }
	globalGuardRe = regexp.MustCompile(`provide\s*:\s*APP_GUARD\s*,\s*useClass\s*:\s*([A-Za-z_][A-Za-z0-9_]*)`)
	// app.setGlobalPrefix('api')
	globalPrefixRe = regexp.MustCompile(`setGlobalPrefix\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]*)`)
	// @Controller('device-tokens') or @Controller()
	controllerRe = regexp.MustCompile(`@Controller\s*\(\s*(?:['"` + "`" + `]([^'"` + "`" + `]*)['"` + "`" + `])?`)
	// @Get(':id'), @Post(), @Patch('x/:y')
	methodRe = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*(?:['"` + "`" + `]([^'"` + "`" + `]*)['"` + "`" + `])?`)
	// @UseGuards(A, B)
	useGuardsRe = regexp.MustCompile(`@UseGuards\s*\(([^)]*)\)`)
	// A bare decorator name.
	decoratorRe = regexp.MustCompile(`@([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	// A template literal or expression where a literal path was expected.
	dynamicPathRe = regexp.MustCompile(`@(?:Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*[^'"` + "`" + `)]`)
)

// authGuardNames are guard class names that mean authentication.
//
// Matching is by substring on a lowercased name because guard naming is a
// convention rather than a contract: JwtAuthGuard, AuthGuard, SessionAuthGuard.
// A guard this adapter does not recognise yields "unknown", never "public".
var authGuardNames = []string{"authguard", "jwtguard", "jwtauth", "sessionguard", "bearerguard"}

// authorizationDecorators mark a control beyond authentication.
var authorizationDecorators = []string{
	"RequirePermission", "RequirePermissions", "Permissions", "Roles", "RequireRoles",
	"CheckPolicies", "CheckAbility", "CanAccess", "Ability",
}

// publicDecorators opt an operation out of a global authentication guard.
var publicDecorators = []string{"Public", "SkipAuth", "AllowAnonymous", "NoAuth"}

// authOnlyDecorators mark authentication without a further authorization check.
var authOnlyDecorators = []string{"AuthenticatedOnly"}

// routeDecl is a route found in a controller.
type routeDecl struct {
	method     string
	path       string
	file       string
	line       int
	decorators []string
	guards     []string
	dynamic    bool
}

// extract turns a NestJS source tree into normalized facts.
func extract(tree source.Tree) ([]adapter.Fact, []string) {
	limits := map[string]struct{}{}
	note := func(s string) { limits[s] = struct{}{} }
	for _, l := range tree.Limitations {
		note(l)
	}

	globalPrefix := ""
	globalAuth, globalGuard := false, ""
	for _, f := range tree.Files {
		for _, line := range f.Lines {
			if m := globalPrefixRe.FindStringSubmatch(line); m != nil && globalPrefix == "" {
				globalPrefix = m[1]
			}
			if m := globalGuardRe.FindStringSubmatch(line); m != nil {
				if looksLikeAuthGuard(m[1]) {
					globalAuth, globalGuard = true, m[1]
				}
			}
		}
	}
	if globalAuth {
		note("authentication is applied globally by " + globalGuard + ", so operations are " +
			"protected unless they opt out; an operation this adapter reports as public is one " +
			"carrying an explicit opt-out decorator")
	} else {
		note("no global authentication guard was found, so an operation is reported as protected " +
			"only when a recognised guard is applied to it or its controller directly")
	}
	note("a NestJS guard decides access at runtime and its basis — ownership, role, or " +
		"something else — is not determinable without executing it, so no ownership fact is " +
		"reported")

	var routes []routeDecl
	for _, f := range tree.Files {
		if !strings.HasSuffix(f.Path, ".controller.ts") {
			continue
		}
		rs, ls := parseController(f, globalPrefix)
		routes = append(routes, rs...)
		for _, l := range ls {
			note(l)
		}
	}
	if len(routes) == 0 {
		note("no controller routes were found; this adapter reads *.controller.ts files and does " +
			"not see routes registered dynamically")
	}

	var facts []adapter.Fact
	for _, r := range routes {
		if r.dynamic {
			// A computed path names no operation this adapter can report
			// against. See the Laravel adapter for the same reasoning.
			note(fmt.Sprintf("%s:%d declares a route whose path is computed; the operation could "+
				"not be identified and no fact was reported for it", r.file, r.line))
			continue
		}
		ev := adapter.Evidence{File: r.file, Line: r.line}

		value, detail := authenticationFor(r, globalAuth, globalGuard)
		facts = append(facts, adapter.Fact{
			Kind:      adapter.KindAuthentication,
			Operation: adapter.OperationRef{Method: r.method, Path: r.path},
			Value:     value,
			Evidence:  adapter.Evidence{File: ev.File, Line: ev.Line, Detail: detail},
		})

		control, found := firstDecorator(r.decorators, authorizationDecorators)
		aValue, aDetail := adapter.AuthorizationAbsent, "no recognised authorization decorator applies"
		if found {
			aValue = adapter.AuthorizationPresent
			aDetail = "authorization is applied by @" + control
		} else if unknown, has := unrecognisedGuard(r.guards); has {
			// A guard whose semantics this adapter does not know may well be an
			// authorization control. Reporting "absent" would be inventing the
			// absence of a control that is right there in the source.
			aValue = adapter.ValueUnknown
			aDetail = "the guard " + unknown + " is applied but its semantics are not recognised, " +
				"so whether it enforces authorization is unknown"
		}
		facts = append(facts, adapter.Fact{
			Kind:      adapter.KindAuthorization,
			Operation: adapter.OperationRef{Method: r.method, Path: r.path},
			Value:     aValue,
			Control:   control,
			Evidence:  adapter.Evidence{File: ev.File, Line: ev.Line, Detail: aDetail},
		})
	}

	out := make([]string, 0, len(limits))
	for l := range limits {
		out = append(out, l)
	}
	sort.Strings(out)
	return facts, out
}

// authenticationFor decides an operation's authentication expectation.
func authenticationFor(r routeDecl, globalAuth bool, globalGuard string) (adapter.Value, string) {
	if name, ok := firstDecorator(r.decorators, publicDecorators); ok {
		return adapter.AuthenticationPublic, "@" + name + " opts this operation out of authentication"
	}
	if g, ok := firstAuthGuard(r.guards); ok {
		return adapter.AuthenticationRequired, "the guard " + g + " is applied to this operation " +
			"or its controller"
	}
	if name, ok := firstDecorator(r.decorators, authOnlyDecorators); ok {
		return adapter.AuthenticationRequired, "@" + name + " requires an authenticated caller"
	}
	if _, ok := firstDecorator(r.decorators, authorizationDecorators); ok && globalAuth {
		return adapter.AuthenticationRequired, "an authorization decorator applies and " +
			globalGuard + " authenticates globally"
	}
	if globalAuth {
		return adapter.AuthenticationRequired,
			globalGuard + " authenticates every operation that does not opt out, and this one does not"
	}
	// No global guard and nothing local. Silence is not evidence of a public
	// route: authentication may be applied by middleware this tier does not read.
	return adapter.ValueUnknown, "no global authentication guard was found and none is applied " +
		"here, so whether this operation requires authentication could not be determined"
}

// parseController reads one controller file.
//
// Decorators are collected as a *group* and processed when the group closes,
// because NestJS puts the route decorator anywhere within it. In the reference
// application the order is @Get(':id') then @RequirePermission(...), so a parser
// that consumed the group when it met the route decorator would drop every
// authorization decorator in the codebase — and would then report the
// application as having no authorization at all, which is the most dangerous
// wrong answer this adapter could give.
func parseController(f source.File, globalPrefix string) ([]routeDecl, []string) {
	var routes []routeDecl
	var limits []string

	base := ""
	var classDecorators, classGuards []string
	var group []string

	// flush processes an accumulated decorator group.
	flush := func(atLine int, isClassLevel bool) {
		if len(group) == 0 {
			return
		}
		defer func() { group = nil }()

		var decorators, guards []string
		var routeLines []string
		for _, line := range group {
			if methodRe.MatchString(line) {
				routeLines = append(routeLines, line)
			}
			if m := useGuardsRe.FindStringSubmatch(line); m != nil {
				for _, g := range strings.Split(m[1], ",") {
					if g = strings.TrimSpace(g); g != "" {
						guards = append(guards, g)
					}
				}
				continue
			}
			if m := decoratorRe.FindStringSubmatch(line); m != nil {
				decorators = append(decorators, m[1])
			}
		}

		if isClassLevel {
			classDecorators = append(classDecorators, decorators...)
			classGuards = append(classGuards, guards...)
			return
		}

		for _, line := range routeLines {
			m := methodRe.FindStringSubmatch(line)
			verb := strings.ToUpper(m[1])
			methods := []string{verb}
			if verb == "ALL" {
				// Conservative: claiming every method would invent operations
				// the application may not serve.
				methods = []string{"GET"}
				limits = append(limits, "an @All() route in "+f.Path+" was reported for GET only")
			}
			for _, hm := range methods {
				routes = append(routes, routeDecl{
					method:     hm,
					path:       nestPath(globalPrefix, base, m[2]),
					file:       f.Path,
					line:       atLine,
					decorators: append(append([]string{}, classDecorators...), decorators...),
					guards:     append(append([]string{}, classGuards...), guards...),
					dynamic:    dynamicPathRe.MatchString(line),
				})
			}
		}
	}

	for i, raw := range f.Lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "*") ||
			strings.HasPrefix(line, "/*") {
			continue
		}

		if strings.HasPrefix(line, "@") {
			group = append(group, line)
			if m := controllerRe.FindStringSubmatch(line); m != nil {
				base = m[1]
			}
			continue
		}

		// A non-decorator line closes the group. Whether it was class-level
		// metadata or a route's is decided by what the line declares.
		isClass := strings.HasPrefix(line, "export class") || strings.HasPrefix(line, "class ") ||
			strings.HasPrefix(line, "export abstract class")
		flush(i, isClass)
	}
	flush(len(f.Lines), false)

	if f.Truncated {
		limits = append(limits, f.Path+" was read only in part, so routes after the cut are missing")
	}
	return routes, limits
}

// nestPath composes the global prefix, controller base and method sub-path, and
// converts NestJS parameter syntax to the template form the contract uses.
//
// This conversion is not cosmetic. An operation reported as /users/:id never
// matches a specification's /users/{id}, so the adapter would silently
// corroborate nothing while appearing to work.
func nestPath(globalPrefix, base, sub string) string {
	parts := make([]string, 0, 3)
	for _, p := range []string{globalPrefix, base, sub} {
		if p = strings.Trim(p, "/"); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "/"
	}
	joined := "/" + strings.Join(parts, "/")

	segments := strings.Split(strings.Trim(joined, "/"), "/")
	for i, seg := range segments {
		switch {
		case strings.HasPrefix(seg, ":"):
			name := strings.TrimSuffix(strings.TrimPrefix(seg, ":"), "?")
			segments[i] = "{" + name + "}"
		case strings.HasPrefix(seg, "*"):
			segments[i] = "{wildcard}"
		}
	}
	return "/" + strings.Join(segments, "/")
}

// looksLikeAuthGuard reports whether a guard class name reads as authentication.
func looksLikeAuthGuard(name string) bool {
	l := strings.ToLower(name)
	for _, n := range authGuardNames {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

// firstAuthGuard returns the first applied guard that reads as authentication.
func firstAuthGuard(guards []string) (string, bool) {
	for _, g := range guards {
		if looksLikeAuthGuard(g) {
			return g, true
		}
	}
	return "", false
}

// unrecognisedGuard returns a guard whose semantics are not known.
func unrecognisedGuard(guards []string) (string, bool) {
	for _, g := range guards {
		if !looksLikeAuthGuard(g) {
			return g, true
		}
	}
	return "", false
}

// firstDecorator returns the first applied decorator from a known family.
func firstDecorator(applied, family []string) (string, bool) {
	for _, a := range applied {
		for _, f := range family {
			if strings.EqualFold(a, f) {
				return a, true
			}
		}
	}
	return "", false
}

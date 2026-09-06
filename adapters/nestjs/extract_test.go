package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/adapters/internal/source"
	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

func run(t *testing.T, root string) adapter.Document {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := source.Main{
		Name: "nestjs", Version: version, Method: adapter.MethodStaticLexical,
		Extensions: []string{".ts"},
		Wanted: func(rel string) bool {
			return strings.HasSuffix(rel, ".controller.ts") ||
				strings.HasSuffix(rel, ".module.ts") || strings.HasSuffix(rel, "main.ts")
		},
		Detect: detect, Extract: extract,
	}.Run([]string{"--source-root", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("adapter exited %d: %s", code, stderr.String())
	}
	res, err := adapter.Parse(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("the adapter produced output the core rejects: %v", err)
	}
	if res.Dropped != 0 {
		t.Fatalf("the core dropped %d of this adapter's facts: %v", res.Dropped, res.DropReasons)
	}
	return res.Document
}

func factFor(doc adapter.Document, kind adapter.Kind, method, path string) (adapter.Fact, bool) {
	for _, f := range doc.Facts {
		if f.Kind == kind && f.Operation.Method == method && f.Operation.Path == path {
			return f, true
		}
	}
	return adapter.Fact{}, false
}

// The golden fixture. The interesting rows are the ones where NestJS means the
// opposite of Laravel: with a global guard registered, an operation with no
// decorator at all is protected, and it is @Public() that makes one public.
func TestNestJSGoldenFixture(t *testing.T) {
	doc := run(t, "testdata/app")

	tests := []struct {
		name    string
		kind    adapter.Kind
		method  string
		path    string
		want    adapter.Value
		control string
		why     string
	}{
		{
			name: "@Public opts out of the global guard", kind: adapter.KindAuthentication,
			method: "POST", path: "/api/auth/sign-in", want: adapter.AuthenticationPublic,
		},
		{
			name: "no decorator means protected under a global guard",
			kind: adapter.KindAuthentication, method: "POST", path: "/api/auth/sign-out",
			want: adapter.AuthenticationRequired,
			why:  "this is the inverse of Laravel, where silence means unprotected",
		},
		{
			name: "the global prefix and controller base compose",
			kind: adapter.KindAuthentication, method: "GET", path: "/api/orders/{orderId}",
			want: adapter.AuthenticationRequired,
		},
		{
			name: "@AuthenticatedOnly requires authentication", kind: adapter.KindAuthentication,
			method: "GET", path: "/api/orders", want: adapter.AuthenticationRequired,
		},
		{
			name: "an authorization decorator after the route decorator is found",
			kind: adapter.KindAuthorization, method: "GET", path: "/api/orders/{orderId}",
			want: adapter.AuthorizationPresent, control: "RequirePermission",
			why: "NestJS puts the route decorator first, so a parser that consumed the group " +
				"on seeing it would miss every authorization decorator in the codebase",
		},
		{
			name: "@AuthenticatedOnly is authentication, not authorization",
			kind: adapter.KindAuthorization, method: "GET", path: "/api/orders",
			want: adapter.AuthorizationAbsent,
		},
		{
			name: "an unrecognised guard means unknown, not absent",
			kind: adapter.KindAuthorization, method: "DELETE", path: "/api/orders/{orderId}",
			want: adapter.ValueUnknown,
			why: "a guard we cannot classify may well authorize; claiming absent would invent " +
				"the absence of a control that is visibly there",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := factFor(doc, tc.kind, tc.method, tc.path)
			if !ok {
				t.Fatalf("no %s fact for %s %s (%s)", tc.kind, tc.method, tc.path, tc.why)
			}
			if f.Value != tc.want {
				t.Fatalf("value = %s, want %s (%s); evidence: %s",
					f.Value, tc.want, tc.why, f.Evidence.Detail)
			}
			if tc.control != "" && f.Control != tc.control {
				t.Errorf("control = %q, want %q", f.Control, tc.control)
			}
			if f.Evidence.Detail == "" {
				t.Error("a fact must explain itself")
			}
		})
	}
}

// NestJS parameter syntax must become the template form the contract uses, or
// every fact is attached to an operation the specification does not contain.
func TestNestJSNormalizesParameterSyntax(t *testing.T) {
	doc := run(t, "testdata/app")
	for _, f := range doc.Facts {
		if strings.Contains(f.Operation.Path, ":") {
			t.Errorf("NestJS parameter syntax leaked into an operation path: %q", f.Operation.Path)
		}
		if strings.Contains(f.Operation.Path, "//") {
			t.Errorf("path composition produced a doubled separator: %q", f.Operation.Path)
		}
	}
	if _, ok := factFor(doc, adapter.KindAuthentication, "GET", "/api/orders/{orderId}"); !ok {
		t.Error("the parameterised route was not normalized to template form")
	}
}

func TestNestJSDoesNotInventADynamicRoute(t *testing.T) {
	doc := run(t, "testdata/app")
	for _, f := range doc.Facts {
		if strings.Contains(f.Operation.Path, "ROUTE_PATH") {
			t.Errorf("a computed route path was reported as an operation: %+v", f.Operation)
		}
	}
	if !mentions(doc.Limitations, "path is computed") {
		t.Errorf("the unreadable route was not reported as a limitation: %v", doc.Limitations)
	}
}

func TestNestJSReportsItsBlindSpots(t *testing.T) {
	doc := run(t, "testdata/app")
	for _, want := range []string{
		"applied globally by JwtAuthGuard", // what silence means here
		"guard decides access at runtime",  // why no ownership fact
	} {
		if !mentions(doc.Limitations, want) {
			t.Errorf("limitations do not mention %q: %v", want, doc.Limitations)
		}
	}
	for _, f := range doc.Facts {
		if f.Kind == adapter.KindOwnership && f.Value != adapter.ValueUnknown {
			t.Errorf("an ownership fact was claimed from static analysis: %+v", f)
		}
	}
}

// Without a global guard, silence means nothing at all — not "public".
// Reporting public here would mark every operation in the application as
// unprotected and invite a finding on each one.
func TestNestJSWithoutAGlobalGuardReportsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/orders.controller.ts", `
import { Controller, Get } from '@nestjs/common';
@Controller('orders')
export class OrdersController {
  @Get()
  async findAll(): Promise<void> {}
}
`)
	doc := run(t, dir)
	f, ok := factFor(doc, adapter.KindAuthentication, "GET", "/orders")
	if !ok {
		t.Fatalf("no authentication fact was reported: %+v", doc.Facts)
	}
	if f.Value != adapter.ValueUnknown {
		t.Fatalf("value = %s, want unknown; with no global guard and no local decorator, "+
			"whether this operation is protected is simply not knowable from source", f.Value)
	}
	if !mentions(doc.Limitations, "no global authentication guard was found") {
		t.Errorf("the adapter did not explain its uncertainty: %v", doc.Limitations)
	}
}

func TestNestJSDetectsANonNestTree(t *testing.T) {
	doc := run(t, t.TempDir())
	if len(doc.Facts) != 0 {
		t.Fatalf("facts were reported for a non-NestJS tree: %+v", doc.Facts)
	}
	if !mentions(doc.Limitations, "does not look like a NestJS application") {
		t.Errorf("the adapter did not say why it reported nothing: %v", doc.Limitations)
	}
}

func TestNestJSExtractionIsDeterministic(t *testing.T) {
	first, err := json.Marshal(run(t, "testdata/app"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := json.Marshal(run(t, "testdata/app"))
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("two runs over the same source produced different documents")
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

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	if err := osMkdirAll(root, rel); err != nil {
		t.Fatal(err)
	}
	if err := osWriteFile(root, rel, content); err != nil {
		t.Fatal(err)
	}
}

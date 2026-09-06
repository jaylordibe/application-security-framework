package main

import (
	"strings"

	"github.com/jaylordibe/application-security-framework/adapters/internal/source"
	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

// version is this adapter's own version, independent of the contract version.
const version = "0.1.0"

func main() {
	source.Exit(source.Main{
		Name:       "nestjs",
		Version:    version,
		Method:     adapter.MethodStaticLexical,
		Extensions: []string{".ts"},
		Wanted: func(rel string) bool {
			// Controllers carry the routes; the module and entrypoint carry the
			// global guard and prefix that decide what a route's silence means.
			return strings.HasSuffix(rel, ".controller.ts") ||
				strings.HasSuffix(rel, ".module.ts") ||
				strings.HasSuffix(rel, "main.ts")
		},
		Detect:  detect,
		Extract: extract,
	})
}

// detect reports whether this looks like a NestJS application.
func detect(tree source.Tree) (bool, string) {
	for _, f := range tree.Files {
		if strings.HasSuffix(f.Path, ".controller.ts") || strings.HasSuffix(f.Path, ".module.ts") {
			return true, ""
		}
	}
	return false, "no NestJS controllers or modules were found, so this does not look like a " +
		"NestJS application; no facts are reported and none should be inferred from their absence"
}

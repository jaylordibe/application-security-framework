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
		Name:       "laravel",
		Version:    version,
		Method:     adapter.MethodStaticLexical,
		Extensions: []string{".php"},
		Wanted: func(rel string) bool {
			// Only route files and controllers carry the facts this adapter
			// reports. Reading the whole application would be slower and would
			// widen the set of files a hostile repository can aim at us.
			return strings.HasPrefix(rel, "routes/") ||
				strings.Contains(rel, "Http/Controllers/") ||
				rel == "bootstrap/app.php"
		},
		Detect:  detect,
		Extract: extract,
	})
}

// detect reports whether this looks like a Laravel application.
func detect(tree source.Tree) (bool, string) {
	for _, f := range tree.Files {
		if strings.HasPrefix(f.Path, "routes/") {
			return true, ""
		}
	}
	return false, "no routes/ directory was found, so this does not look like a Laravel " +
		"application; no facts are reported and none should be inferred from their absence"
}

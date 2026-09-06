package adapter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The core must not learn framework-specific security concepts.
//
// This is the property the whole adapter design exists to protect, and it is
// the one that erodes quietly: the first `if framework == "laravel"` always
// looks like a small pragmatic exception. So it is asserted mechanically rather
// than by review.
//
// Identifiers and string literals are checked; comments are not. Explaining in
// a comment why booting Laravel is dangerous is exactly the kind of reasoning
// that belongs in the core. Branching on it is not.
func TestCoreContainsNoFrameworkSpecificReasoning(t *testing.T) {
	// Terms that only make sense inside one framework's world.
	//
	// Each is specific enough to be unambiguous. A bare "nest" would match
	// RuneStart and a bare "gate" would match this project's own scope gate, and
	// a check that cries wolf is a check somebody deletes.
	forbidden := []string{
		"laravel", "artisan", "eloquent", "spatie", "scramble", "blade",
		"nestjs", "casl", "prisma", "typeorm",
	}
	// Directories that make up the core. Adapters are deliberately excluded:
	// framework knowledge is their entire job.
	roots := []string{"internal", "cmd"}

	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.Walk(filepath.Join("..", "..", root),
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
					return err
				}
				if strings.HasSuffix(path, "_test.go") {
					return nil
				}
				// The CLI embeds the example configuration as a string literal,
				// and that document legitimately names the adapters an operator
				// can configure. Naming an adapter in configuration
				// documentation is not reasoning about a framework; it is
				// telling somebody what to type. The exclusion is this one file
				// rather than a blanket rule so that real code in it is still
				// covered.
				if filepath.Base(path) == "init.go" &&
					strings.Contains(filepath.Dir(path), "cli") {
					return nil
				}
				// Parse without comments: only code is under scrutiny.
				file, perr := parser.ParseFile(fset, path, nil, 0)
				if perr != nil {
					t.Errorf("cannot parse %s: %v", path, perr)
					return nil
				}
				ast.Inspect(file, func(n ast.Node) bool {
					var text string
					switch v := n.(type) {
					case *ast.Ident:
						text = v.Name
					case *ast.BasicLit:
						if v.Kind == token.STRING {
							text = v.Value
						}
					default:
						return true
					}
					lower := strings.ToLower(text)
					for _, term := range forbidden {
						if !strings.Contains(lower, term) {
							continue
						}
						pos := fset.Position(n.Pos())
						// Bound the excerpt: a violation inside a long literal
						// would otherwise print the whole document.
						excerpt := text
						if len(excerpt) > 80 {
							excerpt = excerpt[:80] + "…"
						}
						t.Errorf("%s:%d: the core references the framework-specific term %q in "+
							"code (%q). Framework knowledge belongs in an adapter; the core "+
							"reasons only about normalized facts",
							strings.TrimPrefix(path, "../../"), pos.Line, term, excerpt)
					}
					return true
				})
				return nil
			})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// The contract itself must stay framework-neutral: a fact kind or value naming
// a framework construct would push that construct into every consumer.
func TestContractVocabularyIsFrameworkNeutral(t *testing.T) {
	var vocabulary []string
	for k := range validValues {
		vocabulary = append(vocabulary, string(k))
		for v := range validValues[k] {
			vocabulary = append(vocabulary, string(v))
		}
	}
	vocabulary = append(vocabulary,
		string(MethodFrameworkNative), string(MethodStaticAST), string(MethodStaticLexical))

	for _, term := range []string{
		"middleware", "guard", "gate", "policy", "decorator", "controller",
		"provider", "module", "facade", "ability", "permission",
	} {
		for _, word := range vocabulary {
			if strings.Contains(strings.ToLower(word), term) {
				t.Errorf("the contract vocabulary contains %q via %q; a framework construct in "+
					"the contract makes every consumer learn that framework", term, word)
			}
		}
	}
}

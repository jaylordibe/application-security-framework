package source

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

// Main is the shared entry point for the reference adapters.
//
// Every adapter has the same job around its extractor: parse --source-root,
// read a bounded tree, emit exactly one contract document on stdout, and put
// everything else on stderr. Sharing it means the wire behaviour cannot drift
// between adapters, and an adapter author reading one of them sees the whole
// contract in one place.
type Main struct {
	// Name is the adapter identifier, which must match what the core invoked.
	Name string
	// Version is the adapter's own version.
	Version string
	// Method is how it extracts. The core maps this onto provenance.
	Method adapter.ExtractionMethod
	// Extensions are the file extensions to read.
	Extensions []string
	// Wanted optionally narrows which relative paths are read.
	Wanted func(rel string) bool
	// Extract turns a tree into facts and self-reported limitations.
	Extract func(Tree) ([]adapter.Fact, []string)
	// Detect reports whether the tree looks like this framework, and why not.
	Detect func(Tree) (bool, string)
}

// Run executes the adapter and returns a process exit code.
//
// stdout carries the document and nothing else, ever. A stray print would make
// the document unparseable, which the core treats as an adapter failure — the
// right outcome, but a confusing one to debug, so diagnostics go to stderr.
func (m Main) Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("appsec-adapter-"+m.Name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("source-root", "", "path to the application source to inspect")
	version := fs.Bool("version", false, "print the adapter and contract version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "%s %s (contract %s, extraction %s)\n",
			m.Name, m.Version, adapter.ContractVersion, m.Method)
		return 0
	}
	if *root == "" {
		fmt.Fprintln(stderr, "--source-root is required")
		return 2
	}

	tree, err := Read(*root, m.Extensions, m.Wanted)
	if err != nil {
		fmt.Fprintf(stderr, "cannot inspect the source: %v\n", err)
		return 1
	}

	doc := adapter.Document{
		ContractVersion: adapter.ContractVersion,
		Adapter: adapter.AdapterInfo{
			Name: m.Name, Version: m.Version, ExtractionMethod: m.Method,
		},
		Target: adapter.TargetInfo{Framework: m.Name},
		Facts:  []adapter.Fact{},
	}

	if m.Detect != nil {
		if ok, why := m.Detect(tree); !ok {
			// Not this framework. An empty fact list plus a limitation is the
			// honest answer: reporting nothing without saying why would let the
			// core read "no controls found" from "wrong adapter".
			doc.Limitations = []string{why}
			return emit(stdout, stderr, doc)
		}
	}

	facts, limits := m.Extract(tree)
	adapter.SortFacts(facts)
	doc.Facts = facts
	doc.Limitations = limits
	return emit(stdout, stderr, doc)
}

// emit writes the document as a single JSON value.
func emit(stdout, stderr io.Writer, doc adapter.Document) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(stderr, "cannot write the adapter document: %v\n", err)
		return 1
	}
	return 0
}

// Exit runs an adapter against the process's arguments and exits.
func Exit(m Main) {
	os.Exit(m.Run(os.Args[1:], os.Stdout, os.Stderr))
}

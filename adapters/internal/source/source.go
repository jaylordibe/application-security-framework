// Package source reads an application's files for adapters.
//
// Everything here assumes the repository is hostile. An adapter runs against a
// checkout nobody vouched for, so the reading itself has to be bounded: a
// symlink can point at /etc, a directory can recurse into itself, one file can
// be a gigabyte, and a tree can hold a million of them.
//
// Nothing in this package executes anything. It opens files and reads bytes.
// That is the whole security argument for the static extraction tier, and it is
// worth keeping literally true.
package source

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Budgets. Generous for real applications, bounded against hostile ones.
const (
	// MaxFileBytes bounds one source file.
	MaxFileBytes = 4 << 20 // 4 MiB
	// MaxFiles bounds how many files one adapter run will read.
	MaxFiles = 20000
	// MaxDepth bounds directory recursion.
	MaxDepth = 32
	// MaxLineBytes bounds a single line, so a minified file cannot be read as
	// one enormous token.
	MaxLineBytes = 1 << 20
)

// skipDirs are never descended into.
//
// vendor and node_modules are excluded for safety as much as speed: they are
// third-party code the application did not write, and a fact extracted from a
// dependency would be attributed to the application.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "dist": true,
	"build": true, ".next": true, "coverage": true, "storage": true,
	".idea": true, ".vscode": true,
}

// File is one file's contents, already bounded and validated.
type File struct {
	// Path is relative to the inspected root, always slash-separated so that
	// evidence locations mean the same thing on every platform.
	Path string
	// Lines are the file's lines, without terminators.
	Lines []string
	// Truncated is true when the file exceeded the size budget.
	Truncated bool
}

// Tree is the bounded result of reading a source root.
type Tree struct {
	Root  string
	Files []File
	// Limitations records what could not be read, in the adapter's own voice.
	// It is how a file that was skipped stays distinguishable from a file that
	// contained nothing.
	Limitations []string
}

// Read walks root and reads every file matching one of the extensions.
//
// Symlinks are not followed. A checkout may legitimately contain them, but a
// symlink is also the simplest way to make a walker read outside the tree it
// was pointed at, and no adapter needs one to find an application's routes.
func Read(root string, extensions []string, wanted func(rel string) bool) (Tree, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Tree{}, fmt.Errorf("source root %q is not usable: %w", root, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Tree{}, fmt.Errorf("source root %q cannot be resolved: %w", root, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return Tree{}, fmt.Errorf("source root %q is not a readable directory", root)
	}

	exts := make(map[string]bool, len(extensions))
	for _, e := range extensions {
		exts[strings.ToLower(e)] = true
	}

	tree := Tree{Root: resolved}
	limits := map[string]struct{}{}
	note := func(f string, a ...any) { limits[fmt.Sprintf(f, a...)] = struct{}{} }

	walkErr := filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable entry is noted and stepped over. Aborting the whole
			// walk would let one bad permission hide an entire application.
			note("some paths could not be read and were skipped")
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(resolved, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if path == resolved {
				return nil
			}
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			if strings.Count(rel, "/") >= MaxDepth {
				note("directories deeper than %d levels were not inspected", MaxDepth)
				return fs.SkipDir
			}
			return nil
		}

		// Type()&ModeSymlink is set for symlinks because WalkDir uses Lstat.
		if d.Type()&fs.ModeSymlink != 0 {
			note("symbolic links were not followed")
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if !exts[strings.ToLower(filepath.Ext(rel))] {
			return nil
		}
		if wanted != nil && !wanted(rel) {
			return nil
		}
		if len(tree.Files) >= MaxFiles {
			note("more than %d files matched and the remainder were not inspected", MaxFiles)
			return fs.SkipAll
		}

		f, ferr := readFile(path, rel)
		if ferr != nil {
			note("%s could not be read", rel)
			return nil
		}
		if f.Truncated {
			note("%s exceeded %d bytes and was read only in part", rel, MaxFileBytes)
		}
		tree.Files = append(tree.Files, f)
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return Tree{}, fmt.Errorf("cannot inspect %q: %w", root, walkErr)
	}

	sort.Slice(tree.Files, func(i, j int) bool { return tree.Files[i].Path < tree.Files[j].Path })
	for l := range limits {
		tree.Limitations = append(tree.Limitations, l)
	}
	sort.Strings(tree.Limitations)
	return tree, nil
}

// readFile reads one bounded file into lines.
func readFile(path, rel string) (File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer func() { _ = fh.Close() }()

	info, err := fh.Stat()
	if err != nil {
		return File{}, err
	}
	// Re-check after opening: the entry we walked and the file we opened are not
	// guaranteed to be the same thing on a tree somebody else can modify.
	if !info.Mode().IsRegular() {
		return File{}, errors.New("not a regular file")
	}

	out := File{Path: rel}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)

	var read int
	for sc.Scan() {
		line := sc.Text()
		read += len(line) + 1
		if read > MaxFileBytes {
			out.Truncated = true
			break
		}
		if !utf8.ValidString(line) {
			line = strings.ToValidUTF8(line, "")
		}
		out.Lines = append(out.Lines, line)
	}
	if err := sc.Err(); err != nil {
		// A line above the buffer limit is a truncation, not a failure: the rest
		// of the file may still hold readable routes.
		out.Truncated = true
	}
	return out, nil
}

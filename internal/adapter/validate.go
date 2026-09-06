package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrRejected is returned when adapter output cannot be trusted.
//
// Every rejection is one error type on purpose. A caller must not be able to
// handle "malformed JSON" differently from "unknown version" by accident and
// end up using half a document.
type ErrRejected struct {
	Reason string
}

func (e *ErrRejected) Error() string { return "adapter output rejected: " + e.Reason }

func reject(format string, args ...any) error {
	return &ErrRejected{Reason: fmt.Sprintf(format, args...)}
}

// Result is a validated document plus everything the core noticed while
// validating it.
type Result struct {
	Document Document
	// Dropped counts facts discarded during validation. A document is not
	// rejected for one bad fact — that would let a single malicious entry
	// suppress an entire adapter's useful output — but the count is reported so
	// nobody reads the remainder as complete.
	Dropped int
	// DropReasons are the distinct reasons facts were dropped, sorted.
	DropReasons []string
}

// Parse reads and validates an adapter document from r.
//
// Order matters here. Size is bounded before parsing, the version is checked
// before the body is interpreted, and facts are validated individually before
// any of them can reach the oracle. A document that fails at any of those
// points yields no facts at all rather than a partial view that reads as a
// complete one.
func Parse(r io.Reader) (Result, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return Result{}, reject("could not be read: %v", err)
	}
	if len(raw) > MaxDocumentBytes {
		return Result{}, reject("exceeds the %d byte limit", MaxDocumentBytes)
	}
	if len(raw) == 0 {
		return Result{}, reject("is empty")
	}

	// Strict decoding: an unknown field is a contract mismatch, and silently
	// ignoring one is how two versions come to disagree about meaning while both
	// believing they agree.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	dec.UseNumber()

	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Result{}, reject("is not a valid contract document: %v", sanitize(err.Error(), 200))
	}
	// Refuse trailing content. A document followed by a second JSON value is
	// ambiguous about which one was meant.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Result{}, reject("contains more than one JSON document")
	}

	switch ClassifyVersion(doc.ContractVersion) {
	case VersionUnparseable:
		return Result{}, reject("contractVersion %q is not an adapter contract version",
			sanitize(doc.ContractVersion, 64))
	case VersionUnknown:
		return Result{}, reject("contractVersion %q is not supported by this build (this build "+
			"speaks %s); the document is refused rather than interpreted, because a later contract "+
			"may give an existing field a different meaning",
			sanitize(doc.ContractVersion, 64), strings.Join(SupportedContractVersions, ", "))
	}

	if err := validateAdapterInfo(doc.Adapter); err != nil {
		return Result{}, err
	}
	if len(doc.Facts) > MaxFacts {
		return Result{}, reject("reports %d facts, above the limit of %d", len(doc.Facts), MaxFacts)
	}
	if len(doc.Limitations) > MaxLimitations {
		return Result{}, reject("reports %d limitations, above the limit of %d",
			len(doc.Limitations), MaxLimitations)
	}

	doc.Target.Framework = sanitize(doc.Target.Framework, MaxStringBytes)
	doc.Target.FrameworkVersion = sanitize(doc.Target.FrameworkVersion, MaxStringBytes)

	limits := make([]string, 0, len(doc.Limitations))
	for _, l := range doc.Limitations {
		if s := sanitize(l, MaxStringBytes); s != "" {
			limits = append(limits, s)
		}
	}
	doc.Limitations = limits

	res := Result{}
	kept := make([]Fact, 0, len(doc.Facts))
	seen := make(map[string]Fact, len(doc.Facts))
	reasons := map[string]struct{}{}
	drop := func(reason string) {
		res.Dropped++
		reasons[reason] = struct{}{}
	}

	for _, f := range doc.Facts {
		clean, err := validateFact(f)
		if err != nil {
			drop(err.Error())
			continue
		}
		prev, dup := seen[clean.key()]
		if dup {
			if prev.Value == clean.Value {
				// An exact repeat is noise, not a problem.
				drop("duplicate fact")
				continue
			}
			// The adapter contradicted itself about one subject. Neither
			// assertion can be trusted, so both are withdrawn: keeping the first
			// would make the outcome depend on document order, and keeping the
			// last would let a malicious adapter overwrite by appending.
			delete(seen, clean.key())
			drop("the adapter asserted conflicting values for the same operation and fact kind, " +
				"so neither was used")
			continue
		}
		seen[clean.key()] = clean
	}

	for _, f := range seen {
		kept = append(kept, f)
	}
	SortFacts(kept)
	doc.Facts = kept
	res.Document = doc

	for r := range reasons {
		res.DropReasons = append(res.DropReasons, r)
	}
	sort.Strings(res.DropReasons)
	return res, nil
}

// validateAdapterInfo checks the adapter's self-description.
func validateAdapterInfo(a AdapterInfo) error {
	if a.Name == "" {
		return reject("does not name the adapter that produced it")
	}
	if !isSlug(a.Name) {
		return reject("adapter name %q is not a plain identifier", sanitize(a.Name, 64))
	}
	if !a.ExtractionMethod.Valid() {
		return reject("adapter %q reports extraction method %q, which this build does not know. "+
			"The method decides how far a fact is trusted, so an unrecognised one cannot be "+
			"graded and the document is refused",
			sanitize(a.Name, 64), sanitize(string(a.ExtractionMethod), 64))
	}
	return nil
}

// validateFact checks and normalizes one fact, returning why it was dropped.
func validateFact(f Fact) (Fact, error) {
	if !f.Kind.Valid() {
		return Fact{}, errors.New("unknown fact kind")
	}
	allowed, ok := validValues[f.Kind]
	if !ok || !allowed[f.Value] {
		return Fact{}, errors.New("value is not one this fact kind may assert")
	}

	method := strings.ToUpper(strings.TrimSpace(f.Operation.Method))
	if !isHTTPMethod(method) {
		return Fact{}, errors.New("operation method is not an HTTP method")
	}
	p, err := normalizePath(f.Operation.Path)
	if err != nil {
		return Fact{}, err
	}

	out := Fact{
		Kind:      f.Kind,
		Operation: OperationRef{Method: method, Path: p},
		Value:     f.Value,
		Control:   sanitize(f.Control, MaxStringBytes),
		Evidence: Evidence{
			Line:   f.Evidence.Line,
			Detail: sanitize(f.Evidence.Detail, MaxStringBytes),
		},
	}
	// A negative line is not a location. It is dropped rather than clamped so
	// that the schema an adapter author validates against and the parser that
	// enforces the contract cannot disagree about the same document.
	if f.Evidence.Line < 0 {
		return Fact{}, errors.New("evidence line is negative")
	}
	// A source location that escapes the inspected root is dropped rather than
	// clamped: it is either a bug or an attempt to make a report point somewhere
	// it should not, and neither deserves to be repaired into something
	// plausible.
	if f.Evidence.File != "" {
		file, ferr := normalizeEvidencePath(f.Evidence.File)
		if ferr != nil {
			return Fact{}, ferr
		}
		out.Evidence.File = file
	}
	return out, nil
}

// normalizePath validates and canonicalises an operation path template.
func normalizePath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("operation path is empty")
	}
	if len(raw) > MaxStringBytes {
		return "", errors.New("operation path is too long")
	}
	if strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("operation path contains a control character")
	}
	if !utf8.ValidString(raw) {
		return "", errors.New("operation path is not valid UTF-8")
	}
	// A path template addresses this application. Anything carrying a scheme,
	// an authority, a query or a fragment is describing something else, and a
	// fact about something else must not enter the oracle for this target.
	if u, err := url.Parse(raw); err != nil {
		return "", errors.New("operation path is not parseable")
	} else if u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("operation path carries a scheme, authority, query or fragment")
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if strings.Contains(raw, "..") {
		return "", errors.New("operation path contains a parent-directory reference")
	}
	if n := strings.Count(raw, "/"); n > MaxPathSegments {
		return "", errors.New("operation path has too many segments")
	}
	// Collapse duplicate separators without resolving anything, so that two
	// adapters spelling one route differently still agree.
	cleaned := path.Clean(raw)
	if cleaned != "/" && strings.HasSuffix(raw, "/") {
		cleaned += "/"
	}
	return cleaned, nil
}

// normalizeEvidencePath validates a source location.
func normalizeEvidencePath(raw string) (string, error) {
	if len(raw) > MaxStringBytes {
		return "", errors.New("evidence path is too long")
	}
	if strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("evidence path contains a control character")
	}
	if !utf8.ValidString(raw) {
		return "", errors.New("evidence path is not valid UTF-8")
	}
	if path.IsAbs(raw) || strings.HasPrefix(raw, `\`) {
		return "", errors.New("evidence path is absolute")
	}
	if len(raw) >= 2 && raw[1] == ':' {
		return "", errors.New("evidence path carries a drive letter")
	}
	cleaned := path.Clean(raw)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("evidence path escapes the inspected root")
	}
	return cleaned, nil
}

// sanitize bounds a string and strips control characters.
//
// Adapter strings reach terminals, JSON reports, SARIF and — the roadmap is
// explicit that this is coming — model prompts. Control characters can rewrite
// a terminal, and unbounded length is a flooding primitive, so both are removed
// at the boundary rather than at each of the places the string later appears.
func sanitize(s string, limit int) string {
	if s == "" {
		return ""
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > limit {
		// Truncate on a rune boundary so the result stays valid UTF-8.
		for limit > 0 && !utf8.RuneStart(s[limit]) {
			limit--
		}
		s = s[:limit] + "…"
	}
	return s
}

// isSlug reports whether a name is a plain lowercase identifier.
func isSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// isHTTPMethod reports whether a method is one this project exercises.
func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT":
		return true
	}
	return false
}

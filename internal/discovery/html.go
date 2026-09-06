package discovery

import "strings"

// maxScriptRefs bounds how many script references are taken from one document.
const maxScriptRefs = 64

// ScriptSources extracts the src attribute of every <script> element.
//
// This is deliberately the narrowest possible HTML extraction: script sources
// and nothing else. Anchors are not followed, forms are not read, iframes are
// not entered, and no element leads to another document. That restraint is the
// product boundary — extracting <a href> is the first line of a spider, and this
// project's thesis says explicitly that it will not build one.
//
// It is a scanner rather than a parser because a full HTML5 tree builder is a
// large dependency and a large attack surface for one attribute, and because
// tolerating malformed markup matters more here than modelling it: a target that
// serves broken HTML should yield fewer scripts, never an error.
func ScriptSources(body []byte) []string {
	s := string(body)
	var out []string
	i := 0
	n := len(s)

	for i < n && len(out) < maxScriptRefs {
		j := indexFoldASCII(s[i:], "<script")
		if j < 0 {
			break
		}
		i += j + len("<script")
		if i < n {
			// "<scriptfoo" is not a script tag; the name must end here.
			if c := s[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '>' && c != '/' {
				continue
			}
		}
		// The tag ends at the first '>' that is not inside an attribute value.
		end := tagEnd(s, i)
		if end < 0 {
			break
		}
		if src := attrValue(s[i:end], "src"); src != "" {
			out = append(out, src)
		}
		i = end + 1
	}
	return out
}

// tagEnd returns the index of the '>' closing a tag whose attributes start at i,
// honouring quoted attribute values so that src="a>b" does not end the tag.
func tagEnd(s string, i int) int {
	n := len(s)
	var quote byte
	for i < n {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
		i++
	}
	return -1
}

// attrValue reads one attribute out of a tag's attribute text.
func attrValue(tag, name string) string {
	i := 0
	n := len(tag)
	for i < n {
		for i < n && isHTMLSpace(tag[i]) {
			i++
		}
		start := i
		for i < n && !isHTMLSpace(tag[i]) && tag[i] != '=' && tag[i] != '/' {
			i++
		}
		attr := strings.ToLower(tag[start:i])
		for i < n && isHTMLSpace(tag[i]) {
			i++
		}
		if i >= n || tag[i] != '=' {
			if attr == "" {
				i++
			}
			continue
		}
		i++ // consume '='
		for i < n && isHTMLSpace(tag[i]) {
			i++
		}
		var value string
		if i < n && (tag[i] == '"' || tag[i] == '\'') {
			q := tag[i]
			i++
			vs := i
			for i < n && tag[i] != q {
				i++
			}
			value = tag[vs:i]
			if i < n {
				i++
			}
		} else {
			vs := i
			for i < n && !isHTMLSpace(tag[i]) {
				i++
			}
			value = tag[vs:i]
		}
		if attr == name {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// indexFoldASCII is a case-insensitive IndexByte-driven substring search for an
// already-lowercase ASCII needle. It is linear and allocation-free, where
// strings.ToLower on a multi-megabyte document would copy the whole thing.
func indexFoldASCII(haystack, lowerNeedle string) int {
	if lowerNeedle == "" {
		return 0
	}
	first := lowerNeedle[0]
	upperFirst := first - 'a' + 'A'
	for i := 0; i+len(lowerNeedle) <= len(haystack); i++ {
		c := haystack[i]
		if c != first && c != upperFirst {
			continue
		}
		if strings.EqualFold(haystack[i:i+len(lowerNeedle)], lowerNeedle) {
			return i
		}
	}
	return -1
}

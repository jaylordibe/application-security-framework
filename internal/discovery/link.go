package discovery

import "strings"

// Link is one parsed member of an RFC 8288 Link header field.
type Link struct {
	// URI is the reference exactly as written, still possibly relative.
	URI string
	// Rel is the lowercased relation type, empty when the parameter is absent.
	Rel string
}

// maxLinkHeaderBytes bounds one Link header field value.
//
// A target chooses this string. Without a bound, a header of a few hundred
// megabytes is a memory-exhaustion primitive that costs the target one response.
const maxLinkHeaderBytes = 64 << 10

// maxLinksPerHeader bounds how many members are taken from one field value.
const maxLinksPerHeader = 64

// ParseLinkHeader parses one Link header field value.
//
// It is a real parser rather than a comma split, because the grammar allows
// commas and semicolons inside quoted parameter values:
//
//	</a>; rel="next"; title="one, two", </b>; rel="prev"
//
// splitting that on "," yields three broken members and loses a link. The
// grammar is walked once, left to right, with no backtracking and no regular
// expression — a target-supplied header is exactly the input that turns a
// convenient regex into a denial of service.
//
// Malformed input is skipped rather than rejected: a header with one broken
// member and three good ones should yield three links. Nothing here can fail in
// a way that stops discovery.
func ParseLinkHeader(value string) []Link {
	if len(value) > maxLinkHeaderBytes {
		value = value[:maxLinkHeaderBytes]
	}

	var out []Link
	i := 0
	n := len(value)

	for i < n && len(out) < maxLinksPerHeader {
		// Each member starts with a URI-Reference in angle brackets.
		for i < n && (value[i] == ' ' || value[i] == '\t' || value[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		if value[i] != '<' {
			// Not a member start. Skip to the next comma that is not inside a
			// quoted string, so one malformed member cannot swallow the rest.
			i = skipToNextMember(value, i)
			continue
		}
		i++
		start := i
		// A URI-Reference contains none of "<", ">", whitespace, a quote or a
		// comma. Scanning greedily to the next ">" would let a malformed member
		// swallow the one after it: in
		//
		//	<not-a-link; rel=x, </good>; rel="next"
		//
		// the first ">" belongs to the second member, and a greedy scan yields
		// one bogus link instead of finding the good one. Stopping at the first
		// character that cannot be in a reference means the broken member is
		// abandoned and the valid one is still parsed.
		for i < n {
			c := value[i]
			if c == '>' {
				break
			}
			if c == '<' || c == ',' || c == '"' || c == ' ' || c == '\t' {
				break
			}
			i++
		}
		if i >= n {
			// Unterminated reference: there is no more usable input.
			break
		}
		if value[i] != '>' {
			// Not a reference after all. Abandon this member.
			i = skipToNextMember(value, i)
			continue
		}
		uri := strings.TrimSpace(value[start:i])
		i++ // consume '>'

		link := Link{URI: uri}

		// Parameters, until an unquoted comma ends the member.
		for i < n {
			for i < n && (value[i] == ' ' || value[i] == '\t') {
				i++
			}
			if i >= n || value[i] == ',' {
				break
			}
			if value[i] != ';' {
				// Junk between parameters. Abandon this member's parameters
				// rather than guessing what was meant.
				i = skipToNextMember(value, i)
				break
			}
			i++ // consume ';'

			name, val, next := parseLinkParam(value, i)
			i = next
			if strings.EqualFold(name, "rel") && link.Rel == "" {
				// RFC 8288: the first "rel" wins; later occurrences are ignored.
				link.Rel = strings.ToLower(strings.TrimSpace(val))
			}
		}

		if uri != "" {
			out = append(out, link)
		}
	}
	return out
}

// parseLinkParam reads one "name=value" parameter starting at i, returning the
// offset just past it. A quoted value may contain commas, semicolons and
// backslash escapes.
func parseLinkParam(s string, i int) (name, value string, next int) {
	n := len(s)
	for i < n && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	nameStart := i
	for i < n && s[i] != '=' && s[i] != ';' && s[i] != ',' {
		i++
	}
	name = strings.TrimSpace(s[nameStart:i])
	if i >= n || s[i] != '=' {
		// A valueless parameter, e.g. "; anchor". Nothing to read.
		return name, "", i
	}
	i++ // consume '='
	for i < n && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i < n && s[i] == '"' {
		i++
		var b strings.Builder
		for i < n {
			c := s[i]
			if c == '\\' && i+1 < n {
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			b.WriteByte(c)
			i++
		}
		return name, b.String(), i
	}
	valStart := i
	for i < n && s[i] != ';' && s[i] != ',' && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	return name, s[valStart:i], i
}

// skipToNextMember advances past the next comma that is not inside a quoted
// string.
func skipToNextMember(s string, i int) int {
	n := len(s)
	inQuotes := false
	for i < n {
		c := s[i]
		switch {
		case c == '\\' && inQuotes && i+1 < n:
			i++
		case c == '"':
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			return i + 1
		}
		i++
	}
	return n
}

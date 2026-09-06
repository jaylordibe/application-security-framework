package discovery

import "strings"

// maxRobotsLines bounds how much of a robots.txt is read.
const maxRobotsLines = 2000

// ParseRobots extracts path candidates from a robots.txt.
//
// robots.txt is crawler guidance, not an access-control policy, and this is the
// single most important thing to get right about it. "Disallow: /admin" is a
// request that search engines not index /admin. It is not a statement that
// /admin rejects anonymous users, and treating it as one would manufacture a
// security expectation out of a politeness convention — then report a finding
// when the application, entirely correctly, served the page.
//
// So this returns paths and nothing else. Both Allow and Disallow are read,
// because both name a path the operator knows exists, and neither says anything
// about who may reach it.
//
// Only enough of the format is implemented to find paths: user-agent grouping is
// irrelevant when the output is "these paths exist", and Sitemap directives are
// deliberately ignored, because following one is crawling.
func ParseRobots(body []byte, limit int) (paths []string, truncated bool) {
	seen := map[string]struct{}{}
	lines := 0

	for _, line := range strings.Split(string(body), "\n") {
		lines++
		if lines > maxRobotsLines {
			return sortedUnique(seen), true
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimSpace(line[:colon]))
		if directive != "allow" && directive != "disallow" {
			// Sitemap, User-agent, Crawl-delay and anything else. A Sitemap
			// directive is a list of pages to crawl, and fetching it is the
			// first step of being a crawler.
			continue
		}
		value := strings.TrimSpace(line[colon+1:])
		if value == "" {
			// "Disallow:" with no value means "allow everything". It names no
			// path.
			continue
		}
		p := cleanRobotsPattern(value)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; !dup {
			if len(seen) >= limit {
				return sortedUnique(seen), true
			}
			seen[p] = struct{}{}
		}
	}
	return sortedUnique(seen), false
}

// cleanRobotsPattern turns a robots path pattern into a plain path.
//
// robots.txt patterns may carry "*" wildcards and a "$" end-anchor, neither of
// which is a path. The literal prefix before the first wildcard is the most that
// can honestly be said to exist, and a pattern that is only a wildcard says
// nothing at all.
func cleanRobotsPattern(v string) string {
	if i := strings.IndexAny(v, "*$"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" || v == "/" {
		// "/" is the whole site, not a discovered path.
		return ""
	}
	if !strings.HasPrefix(v, "/") {
		return ""
	}
	// A trailing slash left by a truncated wildcard ("/admin/*" -> "/admin/")
	// still names a directory worth recording, but "//" and deeper noise do not.
	if strings.Contains(v, "//") {
		return ""
	}
	return v
}

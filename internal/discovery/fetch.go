package discovery

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
)

// get performs one discovery request against the target's own origin.
//
// Every discovery request funnels through here, and it enforces the two rules
// that matter before the scope-enforced client enforces its own: the URL must be
// on the target's origin, and the budget must permit it. The client would refuse
// an out-of-scope host anyway; this refuses an in-scope host that is not the
// target, which scope alone would allow.
func (c *collector) get(
	ctx context.Context, opts Options, b *budget, rawURL string,
) (*model.CapturedResponse, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("the URL could not be parsed")
	}
	o, err := originOfURL(u)
	if err != nil {
		return nil, "", err
	}
	if !o.Equal(c.origin) {
		return nil, "", fmt.Errorf("%s is not the target's own origin, so it was not contacted",
			o.String())
	}
	if !b.canRequest() {
		return nil, "", fmt.Errorf("%s", b.exhausted)
	}
	b.requests++

	ex, err := opts.Client.Do(ctx, httpx.Request{
		Method: "GET",
		URL:    rawURL,
		Header: map[string][]string{"Accept": {"*/*"}},
	})
	if err != nil {
		return nil, "", fmt.Errorf("%s", ex.Err)
	}
	if ex.Response == nil {
		return nil, "", fmt.Errorf("no response was received")
	}
	b.bytes += int64(len(ex.Response.Body))
	return ex.Response, rawURL, nil
}

// fetchRoot reads the target's own root document.
//
// It is fetched for exactly two reasons — the Link headers on the response, and
// the <script src> attributes in the body — and it is the only page discovery
// ever reads. There is no second page, because a second page is a crawl.
func (c *collector) fetchRoot(
	ctx context.Context, opts Options, b *budget,
) ([]byte, string) {
	c.linkAttempt = Attempt{Source: model.SourceLinkHeader}

	current := opts.Target
	// One redirect hop, taken deliberately rather than by the HTTP client.
	//
	// The client never follows redirects, and that policy stays: a redirect is
	// evidence, not permission. But a great many applications answer "/" with a
	// 302 to "/login", and refusing to look at the destination would mean
	// discovery reads no HTML at all on a large class of real targets. So one
	// hop is taken, re-checked against the target's origin exactly as the first
	// request was, and counted against the request budget. An off-origin
	// Location ends the walk and is recorded as a reference, never followed.
	for hop := 0; hop < 2; hop++ {
		resp, from, err := c.get(ctx, opts, b, current)
		if err != nil {
			c.linkAttempt.Problem = "the target's root document could not be read: " + err.Error()
			return nil, ""
		}
		c.linkAttempt.Ran = true

		before := len(c.items)
		src := model.Source{Kind: model.SourceLinkHeader, Ref: from, ObservedAt: c.now()}
		for _, raw := range resp.Header["Link"] {
			for _, l := range ParseLinkHeader(raw) {
				c.resolve(l.URI, from, src)
			}
		}
		c.linkAttempt.Found += len(c.items) - before

		if resp.Status >= 300 && resp.Status < 400 {
			loc := strings.TrimSpace(resp.HeaderValue("Location"))
			if loc == "" || hop == 1 {
				return nil, ""
			}
			next, ok := c.sameOriginAbsolute(loc, from)
			if !ok {
				// Recorded as a reference; the walk stops here.
				c.resolve(loc, from, model.Source{
					Kind: model.SourceHTML, Ref: from, ObservedAt: c.now(),
				})
				return nil, ""
			}
			current = next
			continue
		}

		if !looksLikeHTML(resp) {
			// A JSON API at "/" is normal and is not an error. There is simply
			// no markup to read scripts from.
			return nil, from
		}
		return resp.Body, from
	}
	return nil, ""
}

// sameOriginAbsolute resolves a reference and returns it only when it stays on
// the target's own origin.
func (c *collector) sameOriginAbsolute(ref, base string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", false
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	abs := b.ResolveReference(u)
	o, err := originOfURL(abs)
	if err != nil || !o.Equal(c.origin) {
		return "", false
	}
	// The query is dropped before the URL is used again, so a redirect cannot
	// carry a credential into a request discovery makes on its own initiative.
	abs.RawQuery = ""
	abs.Fragment = ""
	return abs.String(), true
}

// looksLikeHTML reports whether a response body is worth scanning for scripts.
func looksLikeHTML(resp *model.CapturedResponse) bool {
	ct := strings.ToLower(resp.HeaderValue("Content-Type"))
	if strings.Contains(ct, "html") {
		return true
	}
	if ct != "" {
		return false
	}
	// No content type: sniff conservatively rather than scan an arbitrary blob.
	head := resp.Body
	if len(head) > 1024 {
		head = head[:1024]
	}
	lower := strings.ToLower(string(head))
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html")
}

// robots reads the target's robots.txt.
//
// robots.txt is crawler guidance and is treated as nothing more: it names paths
// the operator knows about, and says nothing whatsoever about who may reach
// them. See ParseRobots.
func (c *collector) robots(ctx context.Context, opts Options, b *budget) Attempt {
	a := Attempt{Source: model.SourceRobotsTxt}
	target := strings.TrimRight(opts.Target, "/") + "/robots.txt"

	resp, from, err := c.get(ctx, opts, b, target)
	if err != nil {
		a.Problem = "robots.txt could not be read: " + err.Error()
		return a
	}
	a.Ran = true
	if resp.Status != 200 {
		// A 404 here means this probe established nothing. It does not mean the
		// application has no undocumented surface.
		a.Problem = fmt.Sprintf("robots.txt returned status %d, so it revealed no paths",
			resp.Status)
		return a
	}
	if ct := strings.ToLower(resp.HeaderValue("Content-Type")); ct != "" &&
		!strings.Contains(ct, "text/plain") && !strings.Contains(ct, "text/") {
		a.Problem = "robots.txt was served as " + ct + " rather than text, so it was not parsed"
		return a
	}

	paths, truncated := ParseRobots(resp.Body, c.limits.MaxCandidatesPerSource)
	a.Truncated = truncated
	src := model.Source{Kind: model.SourceRobotsTxt, Ref: from, ObservedAt: c.now()}
	for _, p := range paths {
		c.resolve(p, from, src)
		a.Found++
	}
	return a
}

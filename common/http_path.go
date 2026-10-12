package common

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	uuidRegex       = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	hexRegex        = regexp.MustCompile(`[a-fA-F0-9]{8,}`)
	alphaNumericMix = regexp.MustCompile(`[a-zA-Z].*\d|\d.*[a-zA-Z]`)
)

// NormalizeHTTPPath reduces a request path to a low-cardinality template: the
// query string is dropped and identifier-like segments are replaced with
// {uuid}, {id} or {hex}. It is the one definition used by both the HTTP
// metrics' path label and the span URL, so the two always group the same way.
func NormalizeHTTPPath(path string) string {
	if i := strings.Index(path, "?"); i != -1 {
		path = path[:i]
	}
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	hashes := false
	for i, p := range parts {
		if p == "" {
			continue
		}
		if uuidRegex.MatchString(p) {
			parts[i] = "{uuid}"
			continue
		}
		if _, err := strconv.Atoi(p); err == nil {
			parts[i] = "{id}"
			continue
		}
		if len(p) >= 8 && hexRegex.MatchString(p) {
			parts[i] = "{hex}"
			hashes = true
			continue
		}
		if len(p) >= 10 && alphaNumericMix.MatchString(p) {
			parts[i] = "{id}"
			continue
		}
	}
	// A content-addressed store fans its files out under directories named
	// after the first bytes of the hash: /packages/fa/e3/<hash>/<file> in a
	// PyPI mirror, /objects/ab/<hash> in git. Those directories are too short
	// for the rules above, so every pair of them made its own path, up to
	// 65,536 per host. Short hex segments right before a hash are part of it.
	if hashes {
		segments := strings.Split(path, "/")
		for i := range parts {
			if parts[i] != "{hex}" {
				continue
			}
			for j := i - 1; j >= 0 && isHashFanout(segments[j]); j-- {
				parts[j] = "{hex}"
			}
		}
	}
	return strings.Join(parts, "/")
}

// isHashFanout reports whether segment could be a fan-out directory of a
// content-addressed store: one to four hex digits.
func isHashFanout(segment string) bool {
	if len(segment) == 0 || len(segment) > 4 {
		return false
	}
	for _, c := range segment {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

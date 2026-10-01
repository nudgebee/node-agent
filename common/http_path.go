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
			continue
		}
		if len(p) >= 10 && alphaNumericMix.MatchString(p) {
			parts[i] = "{id}"
			continue
		}
	}
	return strings.Join(parts, "/")
}

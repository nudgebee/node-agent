package l7

import (
	"bytes"
	"encoding/base64"
	"log"
	"regexp"
	"strings"
)

func ParseHttp(payload []byte) (string, string) {
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}
	if !isHttpMethod(string(method)) {
		return "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}
	return string(method), string(uri)
}

func ParseHttpAndRest(payload []byte) (string, string, string, string) {
	data := string(payload)
	data = strings.ReplaceAll(data, "\\n\\n", "\n\n")
	split := strings.Split(data, "\n\n")
	rest := []byte(split[0])
	d := split[1]
	method, rest, ok := bytes.Cut(rest, space)
	if !ok {
		return "", "", "", ""
	}
	if !isHttpMethod(string(method)) {
		return "", "", "", ""
	}
	uri, rest, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}

	_, headers, ok := bytes.Cut(rest, []byte{'\n'})
	if !ok {
		uri = append(uri, []byte("...")...)
	}
	log.Printf("data %s", headers)
	return string(method), string(uri), string(headers), string(d)
}

func SanitizeString(input string) string {
	// Regular expression patterns to match various sensitive data formats
	sensitivePatterns := []*regexp.Regexp{
		// Authorization header (Bearer or Basic)
		// Example: Authorization: Basic c3FhXzdhODNiZTRjY2Y0M2E2NzFhMTI0ODViYmMyY2I4ZGU4MDk0MDQyMzE6
		// Reason: Matches common formats for authorization tokens.
		regexp.MustCompile(`(?i)Authorization: (Bearer|Basic)\s+[a-zA-Z0-9\-_\.=]+`),

		// API key
		// Example: ApiKey abcdef1234567890
		// Reason: Matches common formats for API keys.
		regexp.MustCompile(`(?i)ApiKey\s+[a-zA-Z0-9\-_\.=]+`),

		// JWT token
		// Example: JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
		// Reason: Matches common formats for JWT tokens.
		regexp.MustCompile(`(?i)JWT\s+[a-zA-Z0-9\-_\.=]+`),

		// OAuth token
		// Example: OAuth token1234567890
		// Reason: Matches common formats for OAuth tokens.
		regexp.MustCompile(`(?i)OAuth\s+[a-zA-Z0-9\-_\.=]+`),
	}

	// Replace sensitive data with placeholder '*'
	sanitized := input
	for _, pattern := range sensitivePatterns {
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			// Only replace the sensitive part, keeping the structure intact
			sanitized_string := strings.Repeat("*", len(match))
			log.Printf("Replacing %s with %s , using pattern %s", match, sanitized_string, pattern)
			return sanitized_string
		})
	}

	byteData := []byte(sanitized)

	// Encode byte slice to Base64
	base64String := base64.StdEncoding.EncodeToString(byteData)
	return base64String
}

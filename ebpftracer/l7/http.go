package l7

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
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

func ParseHTTPRequest(requestBytes []byte) (*http.Request, error) {
	// Create a reader from the byte array
	reader := bufio.NewReader(bytes.NewReader(requestBytes))

	// Parse HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("error parsing request: %v", err)
	}
	return req, nil
}

func ParseHostFromHttpRequest(input string) (string, error) {
	// Split the input string by newline characters
	lines := strings.Split(input, "\r\n")

	// Initialize host variable
	var host string

	// Iterate through each line
	for _, line := range lines {
		// Check if the line starts with "Host:"
		if strings.HasPrefix(line, "Host:") {
			// Split the line by colon and trim the leading/trailing whitespace
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host = strings.TrimSpace(parts[1])
			}
			break
		}
	}

	return host, nil
}

func ConvertHeadersToString(headers http.Header) string {
	var headerStrings []string

	for key, values := range headers {
		for _, value := range values {
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", key, value))
		}
	}

	return strings.Join(headerStrings, ", ")
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

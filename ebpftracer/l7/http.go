package l7

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
	// Convert bytes to string
	requestString := string(requestBytes)
	requestString = strings.ReplaceAll(requestString, "\x00", "")
	// Split the request into lines
	lines := strings.Split(requestString, "\r\n")
	// Find the index of the first empty line (indicating the end of the request line and headers)
	var emptyLineIndex int
	for i, line := range lines {
		if line == "" {
			emptyLineIndex = i
			break
		}
	}

	// Check if an empty line was found
	if emptyLineIndex == 0 || emptyLineIndex == len(lines)-1 {
		return nil, errors.New("malformed HTTP request: invalid request line or headers")
	}

	// Parse the request line
	requestLine := lines[0]
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return nil, errors.New("malformed HTTP request: invalid request line")
	}

	method := parts[0]
	uri := parts[1]
	httpVersion := parts[2]

	// Parse the URI to get the path and query
	parsedURL, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, errors.New("malformed HTTP request: invalid URI")
	}

	// Parse the Host header
	var host string
	for _, line := range lines[1:emptyLineIndex] {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return nil, errors.New("malformed HTTP request: invalid header line")
		}
		key := parts[0]
		value := parts[1]
		if strings.ToLower(key) == "host" {
			host = value
			break
		}
	}

	// If Host header not found, use the host from the parsed URL
	if host == "" {
		host = parsedURL.Host
	}

	// Construct the URL
	u := &url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     host,
		Path:     parsedURL.Path,
		RawQuery: parsedURL.RawQuery,
	}

	// Create a new request
	req := &http.Request{
		Method:     method,
		URL:        u,
		Proto:      httpVersion,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}

	// Parse headers (skipping first line)
	for _, line := range lines[1:emptyLineIndex] {
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return nil, errors.New("malformed HTTP request: invalid header line")
		}
		req.Header.Add(parts[0], parts[1])
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

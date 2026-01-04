package l7

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/flags"
)

var (
	sensitiveHeadersCache map[string]bool
	sensitiveHeadersMu    sync.RWMutex
	lastSensitiveHeader   string
)

func getSensitiveHeaders() map[string]bool {
	currentHeader := ""
	if flags.SensitiveHeader != nil {
		currentHeader = *flags.SensitiveHeader
	}

	sensitiveHeadersMu.RLock()
	if sensitiveHeadersCache != nil && lastSensitiveHeader == currentHeader {
		m := sensitiveHeadersCache
		sensitiveHeadersMu.RUnlock()
		return m
	}
	sensitiveHeadersMu.RUnlock()

	sensitiveHeadersMu.Lock()
	defer sensitiveHeadersMu.Unlock()

	// Double check
	if sensitiveHeadersCache != nil && lastSensitiveHeader == currentHeader {
		return sensitiveHeadersCache
	}

	m := make(map[string]bool)
	sensitiveKeysList := strings.Split(currentHeader, ",")
	for _, key := range sensitiveKeysList {
		m[strings.ToLower(strings.TrimSpace(key))] = true
	}
	sensitiveHeadersCache = m
	lastSensitiveHeader = currentHeader
	return m
}

// safeString converts bytes to string with UTF-8 validation
// If bytes contain invalid UTF-8, returns base64 encoded version as fallback
func safeString(data []byte) string {
	if !utf8.Valid(data) {
		// Return base64 encoded version for invalid UTF-8 data
		return "base64:" + base64.StdEncoding.EncodeToString(data)
	}
	return string(data)
}

// isValidHeaderKey checks if a string is a valid HTTP header key
func isValidHeaderKey(key string) bool {
	if len(key) == 0 {
		return false
	}

	// Check for non-printable characters or base64 prefix
	if strings.HasPrefix(key, "base64:") {
		return false
	}

	// HTTP header keys should only contain printable ASCII characters
	for _, r := range key {
		if r < 33 || r > 126 {
			return false
		}
		// Header keys shouldn't contain certain characters
		if r == ':' || r == ' ' || r == '\t' {
			return false
		}
	}

	return true
}

func ParseHttp(payload []byte) (string, string) {
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}
	if !isHttpMethod(safeString(method)) {
		return "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}
	return safeString(method), safeString(uri)
}

func ParseHTTPRequest(data []byte) (*http.Request, error) {
	method, rest, ok := bytes.Cut(data, space)
	if !ok {
		return nil, errors.New("invalid payload")
	}
	if !isHttpMethod(safeString(method)) {
		return nil, errors.New("invalid payload")
	}
	uri, rest, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}

	httpVersion, rest, _ := bytes.Cut(rest, []byte{'\n'})
	remaining := bytes.Split(rest, []byte{'\r', '\n', '\r', '\n'})
	headers := remaining[0]
	var body []byte
	if len(remaining) > 1 {
		body = remaining[1]
	}
	// Headers parsing continues regardless of URI space parsing
	parsedURL, err := url.ParseRequestURI(safeString(uri))

	if err != nil {
		return nil, errors.New("invalid uri")
	}

	// Parse headers (skipping first line)
	u := &url.URL{
		Scheme:   parsedURL.Scheme,
		Path:     parsedURL.Path,
		RawQuery: parsedURL.RawQuery,
	}
	var header = http.Header{}
	var host = ""
	headerLines := bytes.Split(headers, []byte("\n"))
	sensitiveHeaders := getSensitiveHeaders()
	for _, line := range headerLines {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Stop processing if we encounter binary data (invalid UTF-8)
		if !utf8.Valid(line) {
			break
		}

		part1, part2, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}

		// Skip if header key contains binary data or non-printable characters
		keyStr := strings.TrimSpace(safeString(part1))
		if !isValidHeaderKey(keyStr) {
			continue
		}

		if strings.HasPrefix(keyStr, "Host") {
			host = strings.TrimSpace(safeString(part2))
		}

		key := keyStr
		val := strings.TrimSpace(safeString(part2))
		if sensitiveHeaders[strings.ToLower(key)] {
			val = SanitizeString(val)
		}
		header.Add(key, val)
	}
	req := &http.Request{
		Method:     safeString(method),
		URL:        u,
		Proto:      string(httpVersion),
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       host,
		Header:     header,
	}
	if len(body) > 0 || body != nil {
		p := body
		req.Body = io.NopCloser(bytes.NewReader(p))
		defer req.Body.Close()
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

func ConvertHeadersToBase64String(headers http.Header) string {
	headerMap := make(map[string][]string)
	for key, values := range headers {
		headerMap[key] = values
	}
	jsonString, err := json.Marshal(headerMap)
	if err != nil {
		return ""
	}
	header64 := base64.StdEncoding.EncodeToString([]byte(jsonString))
	return string(header64)
}

func SanitizeString(value string) string {
	if !*flags.SanitizeHeaders {

		return value
	}
	return strings.Repeat("*", 5)
}

// ParseHTTPResponse parses HTTP response data and returns status code and headers
func ParseHTTPResponse(data []byte) (*http.Response, error) {
	// Skip debug logging for performance

	// Check if it starts with HTTP/
	if !bytes.HasPrefix(data, []byte("HTTP/")) {
		return nil, errors.New("invalid response format")
	}

	var space = []byte{' '}

	// Parse status line: HTTP/1.1 200 OK
	statusLine, rest, ok := bytes.Cut(data, []byte{'\r', '\n'})
	if !ok {
		statusLine, rest, ok = bytes.Cut(data, []byte{'\n'})
		if !ok {
			return nil, errors.New("invalid response: no status line")
		}
	}

	// Split status line: protocol, status code, reason phrase
	protocol, statusRest, ok := bytes.Cut(statusLine, space)
	if !ok {
		return nil, errors.New("invalid status line format")
	}

	statusCode, _, ok := bytes.Cut(statusRest, space)
	if !ok {
		// Some responses might not have a reason phrase
		statusCode = statusRest
	}

	// Validate HTTP version
	protocolStr := safeString(protocol)
	if !strings.HasPrefix(protocolStr, "HTTP/") {
		return nil, errors.New("invalid HTTP version")
	}

	// Parse status code
	statusCodeStr := safeString(statusCode)
	if len(statusCodeStr) != 3 {
		return nil, errors.New("invalid status code length")
	}

	// Split headers and body
	headerData, body, _ := bytes.Cut(rest, []byte{'\r', '\n', '\r', '\n'})
	if len(headerData) == len(rest) {
		// Try with just \n\n
		headerData, body, _ = bytes.Cut(rest, []byte{'\n', '\n'})
	}

	// Parse headers
	var header = http.Header{}
	sensitiveHeaders := getSensitiveHeaders()

	headerLines := bytes.Split(headerData, []byte("\r\n"))
	if len(headerLines) == 1 {
		// Try with just \n
		headerLines = bytes.Split(headerData, []byte("\n"))
	}

	for _, line := range headerLines {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Stop processing if we encounter binary data (invalid UTF-8)
		if !utf8.Valid(line) {
			break
		}

		key, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}

		keyStr := strings.TrimSpace(safeString(key))

		// Skip if header key contains binary data or non-printable characters
		if !isValidHeaderKey(keyStr) {
			continue
		}

		valueStr := strings.TrimSpace(safeString(value))

		if sensitiveHeaders[strings.ToLower(keyStr)] {
			valueStr = SanitizeString(valueStr)
		}
		header.Add(keyStr, valueStr)
	}

	// Create response object
	resp := &http.Response{
		Status:     safeString(statusLine),
		StatusCode: parseStatusCode(statusCodeStr),
		Proto:      protocolStr,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
	}

	if len(body) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	return resp, nil
}

// parseStatusCode converts status code string to int, returns 0 if invalid
func parseStatusCode(code string) int {
	if len(code) != 3 {
		return 0
	}

	// Manual parsing to avoid strconv dependency in critical path
	if code[0] < '1' || code[0] > '5' {
		return 0
	}
	if code[1] < '0' || code[1] > '9' {
		return 0
	}
	if code[2] < '0' || code[2] > '9' {
		return 0
	}

	return int(code[0]-'0')*100 + int(code[1]-'0')*10 + int(code[2]-'0')
}

// ParseHttp can handle both requests and responses
func ParseHttpResponse(payload []byte) (string, string) {
	if !bytes.HasPrefix(payload, []byte("HTTP/")) {
		return "", ""
	}

	// Parse HTTP response: HTTP/1.1 200 OK
	var space = []byte{' '}
	protocol, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}

	statusCode, statusText, ok := bytes.Cut(rest, space)
	if !ok {
		statusCode = rest
		statusText = []byte("Unknown")
	}

	// Extract just the status text before any line breaks
	if newlineIdx := bytes.IndexAny(statusText, "\r\n"); newlineIdx >= 0 {
		statusText = statusText[:newlineIdx]
	}

	return safeString(protocol), safeString(statusCode) + " " + safeString(statusText)
}

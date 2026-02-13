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
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/flags"
)

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
		RawPath:  parsedURL.RawPath,
		RawQuery: parsedURL.RawQuery,
	}
	var header = http.Header{}
	var host = ""
	headerLines := bytes.Split(headers, []byte("\n"))
	sensitiveHeaders := make(map[string]bool)
	sensitiveKeysList := strings.Split(*flags.SensitiveHeader, ",")
	for _, key := range sensitiveKeysList {
		sensitiveHeaders[strings.ToLower(strings.TrimSpace(key))] = true
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


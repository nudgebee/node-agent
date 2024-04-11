package l7

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/coroot/coroot-node-agent/flags"
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

func ParseHTTPRequest(data []byte) (*http.Request, error) {
	method, rest, ok := bytes.Cut(data, space)
	if !ok {
		log.Printf("invalid metheod")
		return nil, errors.New("invalid payload")
	}
	if !isHttpMethod(string(method)) {
		log.Printf("invalid method")
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
	if !ok {
		return nil, errors.New("invalid headers")
	}
	parsedURL, err := url.ParseRequestURI(string(uri))

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

	for _, line := range headerLines {
		part1, part2, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		if strings.HasPrefix(string(part1), "Host") {
			host = strings.TrimSpace(string(part2))
		}
		key := strings.TrimSpace(string(part1))
		val := strings.TrimSpace(string(part2))
		header.Add(key, val)
	}
	req := &http.Request{
		Method:     string(method),
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

func ConvertHeadersToString(headers http.Header) string {
	var headerStrings []string

	for key, values := range headers {
		for _, value := range values {
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", key, SanitizeString(value)))
		}
	}

	return strings.Join(headerStrings, ", ")
}

func SanitizeString(input string) string {
	if !*flags.SanitizeHeaders {
		return input
	}
	patternList := strings.Split(*flags.SensitiveHeaderPattern, ",")
	// Compile regex patterns
	var sensitivePatterns []*regexp.Regexp
	for _, pattern := range patternList {
		// Trim leading and trailing whitespace from the pattern
		pattern = strings.TrimSpace(pattern)
		if len(pattern) > 0 {
			// Compile each pattern and append to the list
			sensitivePatterns = append(sensitivePatterns, regexp.MustCompile(pattern))
		}
	}

	// Replace sensitive data with placeholder '*'
	sanitized := input
	for _, pattern := range sensitivePatterns {
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			// Only replace the sensitive part, keeping the structure intact
			sanitized_string := strings.Repeat("*", min(len(match), 5))
			log.Printf("Replacing %s with %s , using pattern %s", match, sanitized_string, pattern)
			return sanitized_string
		})
	}

	byteData := []byte(sanitized)

	// Encode byte slice to Base64
	base64String := base64.StdEncoding.EncodeToString(byteData)
	return base64String
}

package l7

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
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

	httpVersion, rest, ok := bytes.Cut(rest, []byte{'\n'})
	if !ok {
		// Handle the case where there's no newline after httpVersion,
		// meaning there are no headers or body.
		rest = []byte{} // Ensure rest is empty
	}

	var headers []byte
	var body []byte
	headerLinesBytes := [][]byte{}
	bodyStartIndex := -1

	// Iterate through 'rest' line by line to find the empty line separating headers and body
	tempRest := rest
	for i := 0; ; i++ {
		line, after, found := bytes.Cut(tempRest, []byte{'\n'})
		if !found {
			// No more newlines, the rest is part of the last header line or body
			if bodyStartIndex != -1 { // If we are already capturing body
				body = append(body, tempRest...)
			} else { // Still in headers
				headerLinesBytes = append(headerLinesBytes, tempRest)
			}
			break
		}

		// Check if the line is empty (carriage return followed by newline, or just newline)
		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) == 0 {
			bodyStartIndex = i + 1 // Mark the start of the body
			body = after           // The rest is body
			break
		}

		if bodyStartIndex == -1 { // Still processing headers
			headerLinesBytes = append(headerLinesBytes, line)
		}
		tempRest = after
	}

	if len(headerLinesBytes) > 0 {
		headers = bytes.Join(headerLinesBytes, []byte{'\n'})
	} else {
		headers = []byte{}
	}

	// The original code had `if !ok` check for headers which is not directly applicable here
	// as we are manually parsing. We'll rely on subsequent parsing steps to validate.
	// For instance, url.ParseRequestURI will fail if uri is bad.

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
	// We already have headerLinesBytes, but it contains the full lines including \r if present.
	// For header parsing, we need to split by \n and then process each line.
	// The 'headers' variable now contains all header lines joined by '\n'.
	headerLines := bytes.Split(headers, []byte("\n"))
	sensitiveHeaders := make(map[string]bool)
	sensitiveKeysList := strings.Split(*flags.SensitiveHeader, ",")
	for _, key := range sensitiveKeysList {
		sensitiveHeaders[strings.ToLower(strings.TrimSpace(key))] = true
	}
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
		if sensitiveHeaders[strings.ToLower(key)] {
			val = SanitizeString(val)
		}
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

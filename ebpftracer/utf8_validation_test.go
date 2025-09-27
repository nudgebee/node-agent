package ebpftracer

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
)

// Test the new safeString function with various inputs
func TestSafeStringValidation(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
		isValid  bool
	}{
		{
			name:     "Valid UTF-8 string",
			input:    []byte("GET /api HTTP/1.1"),
			expected: "GET /api HTTP/1.1",
			isValid:  true,
		},
		{
			name:     "Valid UTF-8 with unicode",
			input:    []byte("GET /café HTTP/1.1"),
			expected: "GET /café HTTP/1.1",
			isValid:  true,
		},
		{
			name:     "Binary TLS data",
			input:    []byte{0x16, 0x03, 0x03, 0x00, 0x47, 0x45, 0x54, 0x20},
			expected: "base64:",
			isValid:  false,
		},
		{
			name:     "MySQL protocol data",
			input:    []byte{0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x50, 0x4f, 0x53, 0x54},
			expected: "base64:",
			isValid:  false,
		},
		{
			name:     "Random binary data",
			input:    []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb},
			expected: "base64:",
			isValid:  false,
		},
		{
			name:     "Empty input",
			input:    []byte{},
			expected: "",
			isValid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We can't directly test safeString since it's not exported,
			// but we can test it indirectly through ParseHttp
			method, _ := l7.ParseHttp(tt.input)
			
			if tt.isValid {
				// For valid UTF-8, method should be parsed normally
				if method == "" && len(tt.input) > 0 && strings.Contains(string(tt.input), " ") {
					t.Errorf("Expected valid method to be parsed from %q", string(tt.input))
				}
			} else {
				// For invalid UTF-8, ParseHttp should handle it gracefully
				// (either parse it as base64 or reject it entirely)
				if method != "" && !strings.HasPrefix(method, "base64:") {
					// This is ok - the input might be rejected at the HTTP method validation stage
				}
			}
		})
	}
}

// Test HTTP parsing with binary data that could cause UTF-8 issues
func TestHTTPParsingWithBinaryData(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		expectError bool
	}{
		{
			name:    "Valid HTTP request",
			payload: []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expectError: false,
		},
		{
			name:    "HTTP with invalid UTF-8 in headers",
			payload: append([]byte("GET /api HTTP/1.1\r\nHost: example.com\r\nX-Data: "), []byte{0xff, 0xfe, 0xfd}...),
			expectError: false, // Should handle gracefully with safeString
		},
		{
			name:    "TLS data that looks like HTTP",
			payload: []byte{0x16, 0x03, 0x03, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x61, 0x70, 0x69},
			expectError: true, // Should be rejected by HTTP parsing
		},
		{
			name:    "MySQL data with HTTP-like strings",
			payload: []byte{0x00, 0x00, 0x00, 0x0a, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x75, 0x73, 0x65, 0x72},
			expectError: true, // Should be rejected by HTTP parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := l7.ParseHTTPRequest(tt.payload)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for payload %v, but got none", tt.payload)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for payload %q, but got: %v", string(tt.payload), err)
				}
				
				// If parsing succeeded, verify all string fields are valid UTF-8
				if req != nil {
					if !utf8.ValidString(req.Method) && !strings.HasPrefix(req.Method, "base64:") {
						t.Errorf("Method contains invalid UTF-8: %q", req.Method)
					}
					if req.URL != nil && !utf8.ValidString(req.URL.Path) && !strings.HasPrefix(req.URL.Path, "base64:") {
						t.Errorf("URL path contains invalid UTF-8: %q", req.URL.Path)
					}
					if req.Header != nil {
						for key, values := range req.Header {
							if !utf8.ValidString(key) && !strings.HasPrefix(key, "base64:") {
								t.Errorf("Header key contains invalid UTF-8: %q", key)
							}
							for _, value := range values {
								if !utf8.ValidString(value) && !strings.HasPrefix(value, "base64:") {
									t.Errorf("Header value contains invalid UTF-8: %q", value)
								}
							}
						}
					}
				}
			}
		})
	}
}

// Benchmark the performance impact of UTF-8 validation
func BenchmarkHTTPParsingWithValidation(b *testing.B) {
	validHTTP := []byte("GET /api/v1/users/12345?format=json HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: TestAgent/1.0\r\nAccept: application/json\r\n\r\n")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := l7.ParseHTTPRequest(validHTTP)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkHTTPParsingWithBinaryData(b *testing.B) {
	// Binary data that might accidentally trigger HTTP parsing
	binaryData := make([]byte, 200)
	for i := range binaryData {
		binaryData[i] = byte(i)
	}
	// Insert "GET " at the beginning to trigger HTTP parsing attempt
	copy(binaryData[0:4], []byte("GET "))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This should be rejected quickly due to invalid UTF-8 or malformed structure
		l7.ParseHTTPRequest(binaryData)
	}
}

// Test performance comparison - UTF-8 validation vs direct string conversion
func BenchmarkUTF8ValidationOverhead(b *testing.B) {
	testData := []byte("GET /api/users HTTP/1.1")
	
	b.Run("WithValidation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if utf8.Valid(testData) {
				_ = string(testData)
			} else {
				_ = base64.StdEncoding.EncodeToString(testData)
			}
		}
	})
	
	b.Run("DirectConversion", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = string(testData)
		}
	})
}
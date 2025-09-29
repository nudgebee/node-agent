package containers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
)

// HTTPRequestContext provides minimal HTTP request context for existing code compatibility
type HTTPRequestContext struct {
	// Basic HTTP data
	Method  string
	Path    string
	Host    string
	TraceID string
	Headers http.Header

	// Separated HTTP components
	HTTPBody     string // Just the HTTP body/payload without headers
	HTTPResponse string // Just the HTTP response body without headers

	// Encoded payloads for compatibility
	PayloadBase64  string
	ResponseBase64 string

	// Connection and timing context
	Connection *ActiveConnection
	Duration   time.Duration
	Status     l7.Status

	// Raw data
	RawPayload  []byte
	RawResponse []byte
}

// NewHTTPRequestProcessor creates a minimal HTTP request processor for backward compatibility
// This is a simplified version that works with the existing container.go code
func NewHTTPRequestProcessor(r *l7.RequestData, conn *ActiveConnection) *HTTPRequestContext {
	ctx := &HTTPRequestContext{
		Connection:  conn,
		Duration:    r.Duration,
		Status:      r.Status,
		RawPayload:  r.Payload,
		RawResponse: r.Response,
	}

	// Parse HTTP request minimally
	ctx.parseHTTPRequest()

	// Encode payloads for compatibility
	ctx.encodePayloads()

	// Extract trace ID if available
	ctx.extractTraceID()

	return ctx
}

// parseHTTPRequest extracts basic HTTP information and separates headers from body
func (ctx *HTTPRequestContext) parseHTTPRequest() {
	if len(ctx.RawPayload) == 0 {
		return
	}

	// Initialize headers map
	ctx.Headers = make(http.Header)

	// Check if payload contains binary data - if so, skip parsing
	if !isValidHTTPData(ctx.RawPayload) {
		// For binary data, set empty values instead of invalid parsing results
		ctx.Method = ""
		ctx.Path = ""
		ctx.Host = ""
		ctx.HTTPBody = ""
		return
	}

	// Build sensitive headers map from flags
	sensitiveHeaders := make(map[string]bool)
	if flags.SensitiveHeader != nil {
		sensitiveKeysList := strings.Split(*flags.SensitiveHeader, ",")
		for _, key := range sensitiveKeysList {
			sensitiveHeaders[strings.ToLower(strings.TrimSpace(key))] = true
		}
	}

	// Convert to string safely
	payload := string(ctx.RawPayload)
	lines := strings.Split(payload, "\n")
	
	headerEndIndex := 0
	
	if len(lines) > 0 {
		// Parse request line: "METHOD /path HTTP/1.1"
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			ctx.Method = parts[0]
			ctx.Path = parts[1]
		}

		// Parse headers and find where they end
		for i, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				// Empty line marks end of headers
				headerEndIndex = i + 2 // +1 for skipping first line, +1 for current line
				break
			}
			
			if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
				headerName := strings.TrimSpace(line[:colonIdx])
				headerValue := strings.TrimSpace(line[colonIdx+1:])
				
				if headerName != "" {
					// Extract Host specifically (before sanitization)
					if strings.ToLower(headerName) == "host" {
						ctx.Host = headerValue
					}
					
					// Apply sanitization if needed
					if sensitiveHeaders[strings.ToLower(headerName)] {
						headerValue = l7.SanitizeString(headerValue)
					}
					
					ctx.Headers.Set(headerName, headerValue)
				}
			}
		}
		
		// Extract HTTP body (everything after headers)
		if headerEndIndex > 0 && headerEndIndex < len(lines) {
			bodyLines := lines[headerEndIndex:]
			ctx.HTTPBody = strings.Join(bodyLines, "\n")
		}
	}
}

// encodePayloads encodes payloads to base64 for compatibility
func (ctx *HTTPRequestContext) encodePayloads() {
	// For request: encode just the HTTP body (without headers)
	if ctx.HTTPBody != "" {
		ctx.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte(ctx.HTTPBody))
	}
	
	// For response: keep legacy format (full response)
	if len(ctx.RawResponse) > 0 {
		ctx.ResponseBase64 = base64.StdEncoding.EncodeToString(ctx.RawResponse)
	}
}

// extractTraceID attempts to extract trace ID from headers
func (ctx *HTTPRequestContext) extractTraceID() {
	if ctx.Headers == nil {
		return
	}

	// Look for common trace ID headers in parsed headers
	traceHeaders := []string{
		"X-Trace-Id",
		"X-Request-Id", 
		"Traceparent",
		"X-Amzn-Trace-Id",
		"X-Correlation-Id",
	}

	for _, header := range traceHeaders {
		if value := ctx.Headers.Get(header); value != "" {
			ctx.TraceID = value
			return
		}
	}
}

// IsLLMRequest checks if this is a request to an LLM provider
func (ctx *HTTPRequestContext) IsLLMRequest() bool {
	if ctx.Host == "" && ctx.Path == "" {
		return false
	}

	// Common LLM API patterns
	llmPatterns := []string{
		"api.openai.com",
		"api.anthropic.com", 
		"api.cohere.ai",
		"generativelanguage.googleapis.com",
		"bedrock",
		"azure.com/openai",
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",
	}

	hostLower := strings.ToLower(ctx.Host)
	pathLower := strings.ToLower(ctx.Path)

	for _, pattern := range llmPatterns {
		if strings.Contains(hostLower, pattern) || strings.Contains(pathLower, pattern) {
			return true
		}
	}

	return false
}

// GetLLMProvider attempts to identify the LLM provider
func (ctx *HTTPRequestContext) GetLLMProvider() LLMProvider {
	if !ctx.IsLLMRequest() {
		return ProviderUnknown
	}

	hostLower := strings.ToLower(ctx.Host)
	pathLower := strings.ToLower(ctx.Path)

	switch {
	case strings.Contains(hostLower, "openai.com") || strings.Contains(hostLower, "azure.com/openai"):
		return ProviderOpenAI
	case strings.Contains(hostLower, "anthropic.com"):
		return ProviderAnthropic
	case strings.Contains(hostLower, "cohere"):
		return ProviderCohere
	case strings.Contains(hostLower, "googleapis.com"):
		return ProviderGoogle
	case strings.Contains(hostLower, "bedrock"):
		return ProviderAWSBedrock
	case strings.Contains(pathLower, "/v1/chat/completions") || strings.Contains(pathLower, "/v1/completions"):
		return ProviderOpenAICompatible
	default:
		return ProviderUnknown
	}
}

// isValidHTTPData checks if the data looks like valid HTTP request data
func isValidHTTPData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// Must be valid UTF-8
	if !utf8.Valid(data) {
		return false
	}
	
	// Convert to string and check for HTTP method patterns
	text := string(data)
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return false
	}
	
	// First line should look like "METHOD /path HTTP/1.1"
	firstLine := strings.TrimSpace(lines[0])
	if firstLine == "" {
		return false
	}
	
	// Check for common HTTP methods
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "TRACE"}
	for _, method := range httpMethods {
		if strings.HasPrefix(firstLine, method+" ") {
			parts := strings.Fields(firstLine)
			// Should have at least "METHOD /path HTTP/version"
			return len(parts) >= 3 && strings.HasPrefix(parts[2], "HTTP/")
		}
	}
	
	return false
}
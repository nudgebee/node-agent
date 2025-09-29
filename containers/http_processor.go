package containers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
)

// HTTPRequestContext provides minimal HTTP request context for existing code compatibility
type HTTPRequestContext struct {
	// Basic HTTP data
	Method  string
	Path    string
	Host    string
	TraceID string
	Headers http.Header

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

// parseHTTPRequest extracts basic HTTP information
func (ctx *HTTPRequestContext) parseHTTPRequest() {
	if len(ctx.RawPayload) == 0 {
		return
	}

	// Initialize headers map
	ctx.Headers = make(http.Header)

	// Convert to string safely
	payload := string(ctx.RawPayload)
	lines := strings.Split(payload, "\n")
	
	if len(lines) > 0 {
		// Parse request line: "METHOD /path HTTP/1.1"
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			ctx.Method = parts[0]
			ctx.Path = parts[1]
		}

		// Parse headers
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				break // End of headers
			}
			
			if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
				headerName := strings.TrimSpace(line[:colonIdx])
				headerValue := strings.TrimSpace(line[colonIdx+1:])
				
				if headerName != "" {
					ctx.Headers.Set(headerName, headerValue)
					
					// Extract Host specifically
					if strings.ToLower(headerName) == "host" {
						ctx.Host = headerValue
					}
				}
			}
		}
	}
}

// encodePayloads encodes raw payloads to base64 for compatibility
func (ctx *HTTPRequestContext) encodePayloads() {
	if len(ctx.RawPayload) > 0 {
		ctx.PayloadBase64 = base64.StdEncoding.EncodeToString(ctx.RawPayload)
	}
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
package containers

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
)

// HTTPRequestContext is a rich data object that encapsulates all HTTP request processing
// Parse once, use everywhere to eliminate duplication
type HTTPRequestContext struct {
	// Parsed HTTP data
	Method   string
	Path     string
	Host     string
	Headers  http.Header
	TraceID  string

	// Encoded payloads for consumers
	PayloadBase64  string
	ResponseBase64 string

	// Connection and timing context
	Connection *ActiveConnection
	Duration   time.Duration
	Status     l7.Status
	
	// Raw data (for specialized processing)
	RawPayload  []byte
	RawResponse []byte
	
	// Processing flags
	HasValidUTF8Payload  bool
	HasValidUTF8Response bool
}

// NewHTTPRequestProcessor creates and processes HTTP request data once
func NewHTTPRequestProcessor(r *l7.RequestData, conn *ActiveConnection) *HTTPRequestContext {
	ctx := &HTTPRequestContext{
		Connection:  conn,
		Duration:    r.Duration,
		Status:      r.Status,
		RawPayload:  r.Payload,
		RawResponse: r.Response,
	}
	
	// Parse HTTP request once
	ctx.parseHTTPRequest()
	
	// Encode payloads once
	ctx.encodePayloads()
	
	// Extract host information
	ctx.resolveHost()
	
	// Extract trace ID if available
	ctx.extractTraceID()
	
	return ctx
}

// parseHTTPRequest parses the HTTP request and extracts method, path, headers
func (ctx *HTTPRequestContext) parseHTTPRequest() {
	// Parse method and path from raw payload
	ctx.Method, ctx.Path = l7.ParseHttp(ctx.RawPayload)
	
	// Parse headers if available
	if req, err := l7.ParseHTTPRequest(ctx.RawPayload); err == nil && req != nil && req.Header != nil {
		ctx.Headers = req.Header
	} else {
		ctx.Headers = http.Header{}
	}
}

// encodePayloads converts raw payloads to base64 with UTF-8 validation
func (ctx *HTTPRequestContext) encodePayloads() {
	// Validate and encode request payload
	if len(ctx.RawPayload) > 0 {
		ctx.HasValidUTF8Payload = utf8.Valid(ctx.RawPayload)
		ctx.PayloadBase64 = base64.StdEncoding.EncodeToString(ctx.RawPayload)
	}
	
	// Validate and encode response payload
	if len(ctx.RawResponse) > 0 {
		ctx.HasValidUTF8Response = utf8.Valid(ctx.RawResponse)
		ctx.ResponseBase64 = base64.StdEncoding.EncodeToString(ctx.RawResponse)
	}
}

// resolveHost determines the host from connection or headers
func (ctx *HTTPRequestContext) resolveHost() {
	// Primary: Get host from destination workload
	ctx.Host = ctx.Connection.DestinationKey.GetDestinationWorkload().Name
	
	// Fallback: Extract from headers if primary is empty or IP
	if ctx.Host == "" || isIPAddress(ctx.Host) {
		if hostHeader := ctx.Headers.Get("Host"); hostHeader != "" {
			ctx.Host = hostHeader
		}
	}
}

// extractTraceID extracts OpenTelemetry trace ID from headers
func (ctx *HTTPRequestContext) extractTraceID() {
	// Extract common trace headers
	if traceParent := ctx.Headers.Get("traceparent"); traceParent != "" {
		ctx.TraceID = extractTraceIDFromTraceParent(traceParent)
	} else if xTraceID := ctx.Headers.Get("x-trace-id"); xTraceID != "" {
		ctx.TraceID = xTraceID
	} else if xB3TraceID := ctx.Headers.Get("x-b3-traceid"); xB3TraceID != "" {
		ctx.TraceID = xB3TraceID
	}
}

// extractTraceIDFromTraceParent parses W3C traceparent header
func extractTraceIDFromTraceParent(traceParent string) string {
	// W3C traceparent format: version-trace_id-parent_id-flags
	// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
	if len(traceParent) >= 35 { // Minimum length for valid traceparent
		parts := []rune(traceParent)
		if len(parts) > 3 && parts[2] == '-' {
			// Extract trace_id (32 hex chars starting at position 3)
			if len(parts) >= 35 {
				return string(parts[3:35])
			}
		}
	}
	return traceParent // Return as-is if parsing fails
}

// IsLLMRequest determines if this is an LLM API request
func (ctx *HTTPRequestContext) IsLLMRequest() bool {
	provider := DetectLLMProvider(ctx.Host)
	if provider != ProviderUnknown {
		return true
	}
	
	// Fallback detection from request content
	if ctx.HasValidUTF8Payload {
		provider = detectLLMFromHTTPRequest(ctx.RawPayload, ctx.ResponseBase64)
		return provider != ProviderUnknown
	}
	
	return false
}

// GetLLMProvider returns the detected LLM provider
func (ctx *HTTPRequestContext) GetLLMProvider() LLMProvider {
	provider := DetectLLMProvider(ctx.Host)
	if provider != ProviderUnknown {
		return provider
	}
	
	// Fallback detection
	if ctx.HasValidUTF8Payload {
		return detectLLMFromHTTPRequest(ctx.RawPayload, ctx.ResponseBase64)
	}
	
	return ProviderUnknown
}

// isIPAddress checks if a string represents an IP address
func isIPAddress(host string) bool {
	// Remove port if present
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	return net.ParseIP(host) != nil
}
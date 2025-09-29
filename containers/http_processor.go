package containers

import (
	"encoding/base64"
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

		// Extract Host header
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				ctx.Host = strings.TrimSpace(line[5:])
				break
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
	if len(ctx.RawPayload) == 0 {
		return
	}

	// Convert to string safely
	payload := string(ctx.RawPayload)
	lines := strings.Split(payload, "\n")

	// Look for common trace ID headers
	traceHeaders := []string{
		"x-trace-id:",
		"x-request-id:",
		"traceparent:",
		"x-amzn-trace-id:",
		"x-correlation-id:",
	}

	for _, line := range lines {
		line = strings.TrimSpace(strings.ToLower(line))
		for _, header := range traceHeaders {
			if strings.HasPrefix(line, header) {
				ctx.TraceID = strings.TrimSpace(line[len(header):])
				return
			}
		}
	}
}
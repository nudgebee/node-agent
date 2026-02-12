package containers

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"inet.af/netaddr"
)

// DNSResolver is a function type for looking up hostnames from IP addresses.
// This allows dependency injection of the registry's DNS cache.
type DNSResolver func(ip netaddr.IP) string

// HTTPRequestContext encapsulates all HTTP request processing.
// Parse once, use everywhere to eliminate duplication.
type HTTPRequestContext struct {
	// Parsed HTTP data
	Method  string
	Path    string
	Host    string // Resolved hostname (never an IP if resolvable)
	Headers http.Header
	TraceID string

	// Encoded payloads for consumers
	PayloadBase64  string
	ResponseBase64 string

	// Connection and timing context
	Connection *ActiveConnection
	Duration   time.Duration
	Status     l7.Status

	// Raw data (for specialized processing like LLM detection)
	RawPayload  []byte
	RawResponse []byte

	// Content type flags
	HasValidUTF8Payload  bool
	HasValidUTF8Response bool
	IsSSE                bool // Server-Sent Events (streaming response)

	// LLM detection cache (computed once)
	llmProvider     LLMProvider
	llmProviderDone bool
}

// NewHTTPRequestContext creates and processes HTTP request data.
// The dnsResolver parameter allows looking up hostnames from IPs at request time,
// fixing the race condition where DNS cache wasn't populated at connection time.
func NewHTTPRequestContext(r *l7.RequestData, conn *ActiveConnection, dnsResolver DNSResolver) *HTTPRequestContext {
	ctx := &HTTPRequestContext{
		Connection:  conn,
		Duration:    r.Duration,
		Status:      r.Status,
		RawPayload:  r.Payload,
		RawResponse: r.Response,
	}

	// Step 1: Parse HTTP request (method, path, headers)
	ctx.parseRequest()

	// Step 2: Resolve host with proper priority
	ctx.resolveHost(dnsResolver)

	// Step 3: Encode payloads for consumers
	ctx.encodePayloads()

	// Step 4: Extract distributed tracing context
	ctx.extractTraceID()

	// Step 5: Detect streaming response
	ctx.detectSSE()

	return ctx
}

// parseRequest extracts method, path, and headers from raw payload.
func (ctx *HTTPRequestContext) parseRequest() {
	if len(ctx.RawPayload) == 0 {
		ctx.Headers = http.Header{}
		return
	}

	// Parse method and path
	ctx.Method, ctx.Path = l7.ParseHttp(ctx.RawPayload)

	// Parse full HTTP request for headers
	if req, err := l7.ParseHTTPRequest(ctx.RawPayload); err == nil && req != nil && req.Header != nil {
		ctx.Headers = req.Header
	} else {
		ctx.Headers = http.Header{}
	}
}

// resolveHost determines the hostname using a priority-based approach.
// Priority order (highest to lowest):
//  1. Host header (HTTP/1.1) - most reliable for external services
//  2. :authority pseudo-header (HTTP/2)
//  3. DNS cache lookup - fixes race condition with connection creation
//  4. Destination workload name - fallback for internal services
func (ctx *HTTPRequestContext) resolveHost(dnsResolver DNSResolver) {
	// Priority 1: Host header (HTTP/1.1)
	// This is the most reliable source for external services like LLM APIs,
	// especially when using Google Private Access or similar proxy setups.
	if host := ctx.Headers.Get("Host"); host != "" {
		ctx.Host = stripPort(host)
		return
	}

	// Priority 2: :authority pseudo-header (HTTP/2)
	// Used in HTTP/2 and gRPC requests instead of Host header.
	if authority := ctx.Headers.Get(":authority"); authority != "" {
		ctx.Host = stripPort(authority)
		return
	}

	// Priority 3: DNS cache lookup
	// This fixes the race condition where DNS response arrives after TCP connect.
	// At L7 request time, DNS should be cached from the earlier lookup.
	if dnsResolver != nil {
		destIP := ctx.Connection.DestinationKey.ActualDestinationIfKnown().IP()
		if hostname := dnsResolver(destIP); hostname != "" {
			ctx.Host = hostname
			return
		}
	}

	// Priority 4: Destination workload name (fallback)
	// For internal services, this may be the service name.
	// For external services, this may be an IP address if DNS wasn't cached.
	ctx.Host = ctx.Connection.DestinationKey.GetDestinationWorkload().Name
}

// encodePayloads converts raw payloads to base64 with UTF-8 validation.
func (ctx *HTTPRequestContext) encodePayloads() {
	// Process request payload - extract body only
	if len(ctx.RawPayload) > 0 {
		body := extractHTTPBody(ctx.RawPayload)
		ctx.HasValidUTF8Payload = utf8.Valid(body)
		if len(body) > 0 {
			ctx.PayloadBase64 = base64.StdEncoding.EncodeToString(body)
		}
	}

	// Process response payload
	if len(ctx.RawResponse) > 0 {
		body := extractHTTPBody(ctx.RawResponse)
		ctx.HasValidUTF8Response = utf8.Valid(body)

		// For valid UTF-8, encode entire response (headers + body)
		// For binary, encode headers only
		if utf8.Valid(ctx.RawResponse) {
			ctx.ResponseBase64 = base64.StdEncoding.EncodeToString(ctx.RawResponse)
		} else {
			headers := extractHTTPHeaders(ctx.RawResponse)
			if len(headers) > 0 {
				ctx.ResponseBase64 = base64.StdEncoding.EncodeToString(headers)
			}
		}
	}
}

// extractTraceID extracts distributed tracing context from headers.
// Supports W3C Trace Context, B3, and custom trace ID headers.
func (ctx *HTTPRequestContext) extractTraceID() {
	// W3C Trace Context (preferred)
	if tp := ctx.Headers.Get("traceparent"); tp != "" {
		ctx.TraceID = parseW3CTraceID(tp)
		return
	}

	// B3 propagation (Zipkin)
	if b3 := ctx.Headers.Get("x-b3-traceid"); b3 != "" {
		ctx.TraceID = b3
		return
	}

	// Custom trace ID header
	if xTrace := ctx.Headers.Get("x-trace-id"); xTrace != "" {
		ctx.TraceID = xTrace
		return
	}

	// X-Request-ID (common in nginx/envoy)
	if reqID := ctx.Headers.Get("x-request-id"); reqID != "" {
		ctx.TraceID = reqID
	}
}

// detectSSE checks if this is a Server-Sent Events (streaming) response.
func (ctx *HTTPRequestContext) detectSSE() {
	// Check response Content-Type for SSE
	if len(ctx.RawResponse) > 0 {
		headers := extractHTTPHeaders(ctx.RawResponse)
		headerStr := strings.ToLower(string(headers))
		ctx.IsSSE = strings.Contains(headerStr, "text/event-stream")
	}
}

// GetLLMProvider returns the detected LLM provider with caching.
func (ctx *HTTPRequestContext) GetLLMProvider() LLMProvider {
	if ctx.llmProviderDone {
		return ctx.llmProvider
	}
	ctx.llmProviderDone = true

	// Primary: hostname-based detection
	ctx.llmProvider = DetectLLMProvider(ctx.Host)
	if ctx.llmProvider != ProviderUnknown {
		return ctx.llmProvider
	}

	// Fallback: content-based detection for unknown hosts
	if ctx.HasValidUTF8Payload {
		ctx.llmProvider = detectLLMFromHTTPRequest(ctx.RawPayload, ctx.ResponseBase64)
	}

	return ctx.llmProvider
}

// IsLLMRequest returns true if this is an LLM API request.
func (ctx *HTTPRequestContext) IsLLMRequest() bool {
	return ctx.GetLLMProvider() != ProviderUnknown
}

// --- Helper functions ---

// stripPort removes the port from a host:port string.
func stripPort(hostPort string) string {
	// IPv6 addresses are wrapped in brackets: [::1]:8080
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.LastIndex(hostPort, "]:"); idx != -1 {
			return hostPort[1:idx]
		}
		// No port, just brackets
		return strings.Trim(hostPort, "[]")
	}

	// IPv4 or hostname
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		// Verify it's actually a port (contains only digits after colon)
		port := hostPort[idx+1:]
		if len(port) > 0 && len(port) <= 5 {
			isPort := true
			for _, c := range port {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort {
				return hostPort[:idx]
			}
		}
	}
	return hostPort
}

// isIPAddress checks if a string represents an IP address.
func isIPAddress(host string) bool {
	host = stripPort(host)
	return net.ParseIP(host) != nil
}

// extractHTTPBody extracts the body from an HTTP message (after \r\n\r\n).
func extractHTTPBody(payload []byte) []byte {
	separator := []byte("\r\n\r\n")
	if idx := bytes.Index(payload, separator); idx != -1 {
		return payload[idx+4:]
	}
	// No separator found - might be body-only (e.g., continued chunk)
	return payload
}

// extractHTTPHeaders extracts headers from an HTTP message (before \r\n\r\n).
func extractHTTPHeaders(payload []byte) []byte {
	separator := []byte("\r\n\r\n")
	if idx := bytes.Index(payload, separator); idx != -1 {
		return payload[:idx]
	}
	return nil
}

// parseW3CTraceID extracts trace ID from W3C traceparent header.
// Format: version-traceid-parentid-flags (e.g., 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01)
func parseW3CTraceID(traceparent string) string {
	// Minimum valid length: 2 (version) + 1 (-) + 32 (trace_id) + 1 (-) = 36
	if len(traceparent) < 36 {
		return traceparent
	}

	// Version should be 2 hex chars followed by dash
	if traceparent[2] != '-' {
		return traceparent
	}

	// Extract 32-char trace ID (positions 3-34)
	traceID := traceparent[3:35]

	// Validate it's hex
	for _, c := range traceID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return traceparent
		}
	}

	return traceID
}

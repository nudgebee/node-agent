package containers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

const (
	maxActiveStreams    = 200              // Max concurrent streams
	maxBufferPerStream = 64 * 1024        // 64KB per stream (only need final usage JSON)
	streamIdleTimeout  = 30 * time.Second // Release abandoned streams
	streamMaxDuration  = 5 * time.Minute  // Cap for very long streams
	streamGCInterval   = 10 * time.Second // GC interval
)

type StreamState int

const (
	StreamStateActive StreamState = iota
	StreamStateCompleted
	StreamStateTimedOut
	StreamStateError
)

func (s StreamState) String() string {
	switch s {
	case StreamStateActive:
		return "active"
	case StreamStateCompleted:
		return "completed"
	case StreamStateTimedOut:
		return "timed_out"
	case StreamStateError:
		return "error"
	default:
		return "unknown"
	}
}

// LLMStream represents an active LLM streaming request
type LLMStream struct {
	StreamID      uint32
	Provider      LLMProvider
	Model         string
	Operation     string
	ServerAddress string

	// Trace correlation
	TraceParent  string // From traceparent header
	TraceID      string // Extracted or generated
	ParentSpanID string
	SpanID       string // Our span ID

	// Timing
	RequestTime    time.Time
	FirstTokenTime time.Time
	CompletionTime time.Time
	LastDataTime   time.Time

	// Token tracking
	InputTokens  int
	OutputTokens int

	// Buffer for token extraction (bounded)
	buffer     *bytes.Buffer
	bufferSize int

	// State
	State            StreamState
	CompletionReason string
	StatusCode       int

	// Request context
	ContainerID string
	PodName     string
	Namespace   string

	// Internal
	mu sync.Mutex
}

// LLMStreamTracker tracks active LLM streaming requests
type LLMStreamTracker struct {
	mu      sync.RWMutex
	streams map[string]*LLMStream // key: "pid:fd:streamID"

	// Callbacks
	onComplete func(*LLMStream)

	// Control
	stopCh chan struct{}
}

// NewLLMStreamTracker creates a new stream tracker
func NewLLMStreamTracker(onComplete func(*LLMStream)) *LLMStreamTracker {
	t := &LLMStreamTracker{
		streams:    make(map[string]*LLMStream),
		onComplete: onComplete,
		stopCh:     make(chan struct{}),
	}
	go t.runGC()
	return t
}

// Stop stops the stream tracker
func (t *LLMStreamTracker) Stop() {
	close(t.stopCh)
}

// ActiveStreamCount returns the number of active streams
func (t *LLMStreamTracker) ActiveStreamCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.streams)
}

// OnRequestHeaders is called when request HEADERS frame is received
func (t *LLMStreamTracker) OnRequestHeaders(
	pid, fd uint32,
	streamID uint32,
	host, path string,
	headers map[string]string,
	containerID, podName, namespace string,
) bool {
	// Detect if this is an LLM request
	provider := DetectLLMProvider(host)
	if provider == ProviderUnknown {
		provider, _ = DetectLLMProviderFromPath(path)
	}
	if provider == ProviderUnknown {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check stream limit
	if len(t.streams) >= maxActiveStreams {
		t.evictOldestLocked()
	}

	key := streamKey(pid, fd, streamID)

	// Skip if already tracking
	if _, exists := t.streams[key]; exists {
		return true
	}

	// Extract trace context
	traceParent := ""
	if headers != nil {
		traceParent = headers["traceparent"]
	}
	traceID, parentSpanID := parseTraceParent(traceParent)
	if traceID == "" {
		traceID = generateTraceID()
	}

	stream := &LLMStream{
		StreamID:      streamID,
		Provider:      provider,
		Model:         extractModelFromPath(path, provider),
		Operation:     GetOperation(path),
		ServerAddress: host,
		TraceParent:   traceParent,
		TraceID:       traceID,
		ParentSpanID:  parentSpanID,
		SpanID:        generateSpanID(),
		RequestTime:   time.Now(),
		LastDataTime:  time.Now(),
		buffer:        bytes.NewBuffer(make([]byte, 0, 4096)),
		State:         StreamStateActive,
		ContainerID:   containerID,
		PodName:       podName,
		Namespace:     namespace,
	}

	t.streams[key] = stream

	klog.V(4).Infof("LLM_STREAM_START: key=%s provider=%s model=%s op=%s trace_id=%s",
		key, provider, stream.Model, stream.Operation, traceID)

	return true
}

// OnResponseHeaders is called when response HEADERS frame is received
func (t *LLMStreamTracker) OnResponseHeaders(
	pid, fd uint32,
	streamID uint32,
	statusCode int,
	headers map[string]string,
) {
	key := streamKey(pid, fd, streamID)

	t.mu.RLock()
	stream, exists := t.streams[key]
	t.mu.RUnlock()

	if !exists {
		return
	}

	stream.mu.Lock()
	stream.StatusCode = statusCode
	stream.mu.Unlock()

	// Check for error status
	if statusCode >= 400 {
		t.mu.Lock()
		stream.State = StreamStateError
		stream.CompletionReason = fmt.Sprintf("http_%d", statusCode)
		t.mu.Unlock()

		t.completeStream(key)
	}
}

// OnDataFrame is called when DATA frame is received
func (t *LLMStreamTracker) OnDataFrame(
	pid, fd uint32,
	streamID uint32,
	data []byte,
	isResponse bool,
) {
	if !isResponse {
		return // Only track response data for now
	}

	key := streamKey(pid, fd, streamID)

	t.mu.RLock()
	stream, exists := t.streams[key]
	t.mu.RUnlock()

	if !exists {
		return
	}

	stream.mu.Lock()
	if stream.State != StreamStateActive {
		stream.mu.Unlock()
		return
	}

	now := time.Now()

	// Track first token time
	if stream.FirstTokenTime.IsZero() {
		stream.FirstTokenTime = now
		klog.V(4).Infof("LLM_STREAM_FIRST_TOKEN: key=%s ttft_ms=%d",
			key, now.Sub(stream.RequestTime).Milliseconds())
	}
	stream.LastDataTime = now

	// Accumulate data (bounded)
	if stream.bufferSize < maxBufferPerStream {
		n := len(data)
		if stream.bufferSize+n > maxBufferPerStream {
			n = maxBufferPerStream - stream.bufferSize
		}
		stream.buffer.Write(data[:n])
		stream.bufferSize += n
	}

	// Check for completion markers
	completed, reason := checkSSECompletion(data)
	stream.mu.Unlock()

	if completed {
		t.mu.Lock()
		stream.CompletionReason = reason
		t.mu.Unlock()
		t.completeStream(key)
	}
}

// OnStreamEnd is called when END_STREAM flag is received
func (t *LLMStreamTracker) OnStreamEnd(pid, fd uint32, streamID uint32) {
	key := streamKey(pid, fd, streamID)

	t.mu.RLock()
	_, exists := t.streams[key]
	t.mu.RUnlock()

	if !exists {
		return
	}

	t.mu.Lock()
	if stream, ok := t.streams[key]; ok {
		if stream.CompletionReason == "" {
			stream.CompletionReason = "end_stream"
		}
	}
	t.mu.Unlock()

	t.completeStream(key)
}

// checkSSECompletion checks if the data contains SSE completion markers
func checkSSECompletion(data []byte) (bool, string) {
	// OpenAI/Azure: "data: [DONE]"
	if bytes.Contains(data, []byte("data: [DONE]")) {
		return true, "done_marker"
	}

	// Gemini: "finishReason"
	if bytes.Contains(data, []byte(`"finishReason"`)) {
		return true, "finish_reason"
	}

	// Anthropic: "finish_reason" (snake_case)
	if bytes.Contains(data, []byte(`"finish_reason"`)) {
		return true, "finish_reason"
	}

	// Anthropic message_stop event
	if bytes.Contains(data, []byte(`"type":"message_stop"`)) ||
		bytes.Contains(data, []byte(`"type": "message_stop"`)) {
		return true, "message_stop"
	}

	// Anthropic content_block_stop (for streaming)
	if bytes.Contains(data, []byte(`"type":"message_delta"`)) {
		// Check if it contains stop_reason
		if bytes.Contains(data, []byte(`"stop_reason"`)) {
			return true, "stop_reason"
		}
	}

	return false, ""
}

func (t *LLMStreamTracker) completeStream(key string) {
	t.mu.Lock()
	stream, exists := t.streams[key]
	if !exists {
		t.mu.Unlock()
		return
	}
	delete(t.streams, key)
	t.mu.Unlock()

	stream.mu.Lock()
	if stream.State == StreamStateActive {
		stream.State = StreamStateCompleted
	}
	stream.CompletionTime = time.Now()

	// Extract tokens from accumulated data
	bufferData := stream.buffer.Bytes()
	stream.mu.Unlock()

	stream.InputTokens, stream.OutputTokens = extractTokensFromBuffer(stream.Provider, bufferData)

	duration := stream.CompletionTime.Sub(stream.RequestTime)
	var ttft time.Duration
	if !stream.FirstTokenTime.IsZero() {
		ttft = stream.FirstTokenTime.Sub(stream.RequestTime)
	}

	klog.Infof("LLM_STREAM_COMPLETE: key=%s provider=%s model=%s state=%s reason=%s "+
		"input_tokens=%d output_tokens=%d duration_ms=%d ttft_ms=%d",
		key, stream.Provider, stream.Model, stream.State, stream.CompletionReason,
		stream.InputTokens, stream.OutputTokens,
		duration.Milliseconds(), ttft.Milliseconds())

	// Callback to emit metrics and trace
	if t.onComplete != nil {
		t.onComplete(stream)
	}
}

func (t *LLMStreamTracker) runGC() {
	ticker := time.NewTicker(streamGCInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.gc()
		}
	}
}

func (t *LLMStreamTracker) gc() {
	now := time.Now()
	var toComplete []string

	t.mu.Lock()
	for key, stream := range t.streams {
		stream.mu.Lock()
		lastData := stream.LastDataTime
		requestTime := stream.RequestTime
		stream.mu.Unlock()

		// Idle timeout
		if now.Sub(lastData) > streamIdleTimeout {
			stream.State = StreamStateTimedOut
			stream.CompletionReason = "idle_timeout"
			toComplete = append(toComplete, key)
			continue
		}

		// Max duration
		if now.Sub(requestTime) > streamMaxDuration {
			stream.State = StreamStateTimedOut
			stream.CompletionReason = "max_duration"
			toComplete = append(toComplete, key)
		}
	}
	t.mu.Unlock()

	// Complete timed-out streams
	for _, key := range toComplete {
		t.completeStream(key)
	}
}

func (t *LLMStreamTracker) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, stream := range t.streams {
		if oldestKey == "" || stream.RequestTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = stream.RequestTime
		}
	}

	if oldestKey != "" {
		stream := t.streams[oldestKey]
		stream.State = StreamStateTimedOut
		stream.CompletionReason = "evicted"
		delete(t.streams, oldestKey)

		klog.Warningf("LLM_STREAM_EVICTED: key=%s (max streams reached)", oldestKey)

		if t.onComplete != nil {
			go t.onComplete(stream)
		}
	}
}

func streamKey(pid, fd, streamID uint32) string {
	return fmt.Sprintf("%d:%d:%d", pid, fd, streamID)
}

// parseTraceParent extracts trace ID and parent span ID from traceparent header
// Format: 00-{trace_id}-{parent_span_id}-{flags}
// Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
func parseTraceParent(header string) (traceID, parentSpanID string) {
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return "", ""
	}
	return parts[1], parts[2]
}

func generateTraceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSpanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// extractTokensFromBuffer extracts token counts from accumulated SSE data
func extractTokensFromBuffer(provider LLMProvider, data []byte) (inputTokens, outputTokens int) {
	switch provider {
	case ProviderOpenAI, ProviderAzureOpenAI:
		return extractOpenAITokens(data)
	case ProviderAnthropic:
		return extractAnthropicTokens(data)
	case ProviderGoogle:
		return extractGeminiTokens(data)
	case ProviderAWSBedrock:
		return extractBedrockTokens(data)
	default:
		return 0, 0
	}
}

// extractOpenAITokens extracts tokens from OpenAI streaming response
// Looks for: {"usage":{"prompt_tokens":10,"completion_tokens":50}}
func extractOpenAITokens(data []byte) (input, output int) {
	// OpenAI sends usage in the final chunk for some endpoints
	// Try to find usage object
	usagePattern := regexp.MustCompile(`"usage"\s*:\s*\{[^}]*"prompt_tokens"\s*:\s*(\d+)[^}]*"completion_tokens"\s*:\s*(\d+)`)
	matches := usagePattern.FindSubmatch(data)
	if len(matches) >= 3 {
		fmt.Sscanf(string(matches[1]), "%d", &input)
		fmt.Sscanf(string(matches[2]), "%d", &output)
		return
	}

	// Alternative pattern
	usagePattern2 := regexp.MustCompile(`"usage"\s*:\s*\{[^}]*"completion_tokens"\s*:\s*(\d+)[^}]*"prompt_tokens"\s*:\s*(\d+)`)
	matches = usagePattern2.FindSubmatch(data)
	if len(matches) >= 3 {
		fmt.Sscanf(string(matches[1]), "%d", &output)
		fmt.Sscanf(string(matches[2]), "%d", &input)
		return
	}

	return 0, 0
}

// extractAnthropicTokens extracts tokens from Anthropic streaming response
// Looks for: {"usage":{"input_tokens":10,"output_tokens":50}}
func extractAnthropicTokens(data []byte) (input, output int) {
	// Anthropic sends usage in message_start and message_delta events
	inputPattern := regexp.MustCompile(`"input_tokens"\s*:\s*(\d+)`)
	outputPattern := regexp.MustCompile(`"output_tokens"\s*:\s*(\d+)`)

	// Find all input_tokens and take the first (from message_start)
	inputMatches := inputPattern.FindAllSubmatch(data, -1)
	if len(inputMatches) > 0 {
		fmt.Sscanf(string(inputMatches[0][1]), "%d", &input)
	}

	// Find all output_tokens and sum them or take the last
	outputMatches := outputPattern.FindAllSubmatch(data, -1)
	if len(outputMatches) > 0 {
		// Take the last output_tokens value (final count)
		fmt.Sscanf(string(outputMatches[len(outputMatches)-1][1]), "%d", &output)
	}

	return
}

// extractGeminiTokens extracts tokens from Gemini streaming response
// Looks for: {"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":50}}
func extractGeminiTokens(data []byte) (input, output int) {
	// Gemini sends usageMetadata in each chunk
	promptPattern := regexp.MustCompile(`"promptTokenCount"\s*:\s*(\d+)`)
	candidatesPattern := regexp.MustCompile(`"candidatesTokenCount"\s*:\s*(\d+)`)

	// Find all and take the last (most recent/accurate)
	promptMatches := promptPattern.FindAllSubmatch(data, -1)
	if len(promptMatches) > 0 {
		fmt.Sscanf(string(promptMatches[len(promptMatches)-1][1]), "%d", &input)
	}

	candidatesMatches := candidatesPattern.FindAllSubmatch(data, -1)
	if len(candidatesMatches) > 0 {
		fmt.Sscanf(string(candidatesMatches[len(candidatesMatches)-1][1]), "%d", &output)
	}

	return
}

// extractBedrockTokens extracts tokens from AWS Bedrock streaming response
func extractBedrockTokens(data []byte) (input, output int) {
	// Bedrock format varies by model, try common patterns

	// Claude on Bedrock
	inputPattern := regexp.MustCompile(`"inputTokens"\s*:\s*(\d+)`)
	outputPattern := regexp.MustCompile(`"outputTokens"\s*:\s*(\d+)`)

	inputMatches := inputPattern.FindSubmatch(data)
	if len(inputMatches) >= 2 {
		fmt.Sscanf(string(inputMatches[1]), "%d", &input)
	}

	outputMatches := outputPattern.FindSubmatch(data)
	if len(outputMatches) >= 2 {
		fmt.Sscanf(string(outputMatches[1]), "%d", &output)
	}

	return
}

// extractModelFromPath extracts the model name from the URL path
func extractModelFromPath(path string, provider LLMProvider) string {
	switch provider {
	case ProviderGoogle:
		// /v1beta/models/gemini-2.0-flash:generateContent
		// /v1/models/gemini-pro:streamGenerateContent
		modelPattern := regexp.MustCompile(`/models/([^/:]+)`)
		if matches := modelPattern.FindStringSubmatch(path); len(matches) >= 2 {
			return matches[1]
		}
	case ProviderOpenAI, ProviderAzureOpenAI:
		// Model is in request body, not path - will be extracted from request payload
		return ""
	case ProviderAnthropic:
		// Model is in request body
		return ""
	case ProviderAWSBedrock:
		// /model/anthropic.claude-v2/invoke
		modelPattern := regexp.MustCompile(`/model/([^/]+)`)
		if matches := modelPattern.FindStringSubmatch(path); len(matches) >= 2 {
			return matches[1]
		}
	}
	return ""
}

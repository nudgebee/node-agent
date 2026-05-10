package containers

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

func generateSpanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Pre-compiled regexes for token extraction from streaming responses.
// These are used by extractTokensFromSSE and must never be compiled per-call.
var (
	// OpenAI/Azure: {"usage":{"prompt_tokens":10,"completion_tokens":50}}
	reOpenAIUsage1 = regexp.MustCompile(`"usage"\s*:\s*\{[^}]*"prompt_tokens"\s*:\s*(\d+)[^}]*"completion_tokens"\s*:\s*(\d+)`)
	reOpenAIUsage2 = regexp.MustCompile(`"usage"\s*:\s*\{[^}]*"completion_tokens"\s*:\s*(\d+)[^}]*"prompt_tokens"\s*:\s*(\d+)`)

	// Anthropic: "input_tokens": 10, "output_tokens": 50
	reAnthropicInput  = regexp.MustCompile(`"input_tokens"\s*:\s*(\d+)`)
	reAnthropicOutput = regexp.MustCompile(`"output_tokens"\s*:\s*(\d+)`)

	// Google Gemini: "promptTokenCount": 10, "candidatesTokenCount": 50
	reGeminiPrompt     = regexp.MustCompile(`"promptTokenCount"\s*:\s*(\d+)`)
	reGeminiCandidates = regexp.MustCompile(`"candidatesTokenCount"\s*:\s*(\d+)`)
	reGeminiCached     = regexp.MustCompile(`"cachedContentTokenCount"\s*:\s*(\d+)`)
	reGeminiFuncCall   = regexp.MustCompile(`"functionCall"\s*:\s*\{`)
	// Gemini embeddings (:embedContent / :batchEmbedContents) return
	// "totalTokens" at top level instead of usageMetadata. Embeddings have
	// no output, so this maps to input_tokens.
	reGeminiTotalTokens = regexp.MustCompile(`"totalTokens"\s*:\s*(\d+)`)

	// AWS Bedrock: "inputTokens": 10, "outputTokens": 50
	reBedrockInput  = regexp.MustCompile(`"inputTokens"\s*:\s*(\d+)`)
	reBedrockOutput = regexp.MustCompile(`"outputTokens"\s*:\s*(\d+)`)

	// Model extraction from response JSON (all providers return model in response)
	reModelField        = regexp.MustCompile(`"model"\s*:\s*"([^"]+)"`)
	reModelVersionField = regexp.MustCompile(`"modelVersion"\s*:\s*"([^"]+)"`)

	// Bedrock model from path
	reBedrockPathModel = regexp.MustCompile(`/model/([^/]+)`)
	// Google model from path
	reGooglePathModel = regexp.MustCompile(`/models/([^/:]+)`)
)

// LLMEvent is the unified output of the LLM parser.
// Both HTTP/1.1 and HTTP/2, streaming and non-streaming, produce this.
type LLMEvent struct {
	Provider      LLMProvider
	Model         string
	Operation     string
	ServerAddress string
	StatusCode    int
	InputTokens   int
	OutputTokens  int
	// CachedInputTokens are input tokens served from the provider's prompt
	// cache. Already counted in InputTokens; the cost calculator subtracts
	// them and applies the cached rate.
	CachedInputTokens int
	// ToolCallCount is the number of tool/function-call invocations in the
	// response. 0 for non-tool-using requests.
	ToolCallCount int
	Duration      time.Duration
	TTFT          time.Duration // Zero if non-streaming or unknown
	IsStreaming   bool
	ContainerID   string
	PodName       string
	Namespace     string

	// Trace context (propagated from request headers)
	TraceID      string
	ParentSpanID string
	SpanID       string
}

const (
	llmMaxStreams  = 200              // Max concurrent HTTP/2 LLM streams per container
	llmMaxBuffer   = 64 * 1024        // 64KB response buffer per stream
	llmIdleTimeout = 30 * time.Second // GC idle streams
	llmMaxDuration = 5 * time.Minute  // Cap stream lifetime
	llmGCInterval  = 10 * time.Second
)

// llmStream tracks one in-flight HTTP/2 LLM streaming request.
type llmStream struct {
	provider     LLMProvider
	host         string
	path         string
	statusCode   int
	requestTime  time.Time
	firstDataAt  time.Time
	lastDataAt   time.Time
	buffer       bytes.Buffer
	bufferSize   int
	completed    bool
	traceID      string
	parentSpanID string
	spanID       string
}

// LLMParser handles LLM response parsing for a single container.
// It provides two entry points:
//   - ParseHTTP1: for completed HTTP/1.1 request/response pairs
//   - FeedHTTP2: for incremental HTTP/2 DATA frames on LLM-tagged connections
type LLMParser struct {
	mu      sync.Mutex
	streams map[uint32]*llmStream // HTTP/2 stream ID → state

	// Container context (set at creation, immutable)
	containerID string
	podName     string
	namespace   string

	// Callback for completed events
	onEvent func(*LLMEvent)

	// Control
	stopCh chan struct{}
}

// NewLLMParser creates a parser for a container.
// onEvent is called for each completed LLM request (both streaming and non-streaming).
func NewLLMParser(containerID, podName, namespace string, onEvent func(*LLMEvent)) *LLMParser {
	p := &LLMParser{
		streams:     make(map[uint32]*llmStream),
		containerID: containerID,
		podName:     podName,
		namespace:   namespace,
		onEvent:     onEvent,
		stopCh:      make(chan struct{}),
	}
	go p.runGC()
	return p
}

// Stop shuts down the parser and its GC goroutine.
func (p *LLMParser) Stop() {
	close(p.stopCh)
}

// ParseHTTP1 handles a completed HTTP/1.1 LLM request/response bytes.
// Called when the full request and response are available (non-streaming or SSE complete).
func (p *LLMParser) ParseHTTP1(tag *LLMConnectionTag, statusCode int,
	path string, requestBody, responseBody []byte, duration time.Duration,
	traceID string) {

	// HTTP/1.1 LLM responses (Gemini in particular) often arrive as
	// Transfer-Encoding: chunked + Content-Encoding: gzip. The eBPF capture
	// has stripped the response headers in extractHTTPBody, but the body
	// still carries chunk-size framing and gzip-compressed bytes — both
	// invisible to plain regex. Decode best-effort before extraction.
	if decoded := decodeHTTPBody(responseBody); decoded != nil {
		responseBody = decoded
	}

	model, inputTokens, outputTokens := extractFromResponseBody(tag.Provider, responseBody)
	cachedTokens := extractCachedTokens(tag.Provider, responseBody)
	toolCalls := extractToolCallCount(tag.Provider, responseBody)

	// Fallback: try request body for model if response didn't have it
	if model == "" {
		model = extractModelFromRequestBody(tag.Provider, requestBody)
	}
	// Fallback: try path
	if model == "" {
		model = modelFromPath(tag.Provider, path)
	}
	if model == "" {
		model = "unknown"
	}

	operation := GetOperation(path)
	if operation == "" {
		operation = "unknown"
	}

	event := &LLMEvent{
		Provider:          tag.Provider,
		Model:             model,
		Operation:         operation,
		ServerAddress:     tag.Host,
		StatusCode:        statusCode,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CachedInputTokens: cachedTokens,
		ToolCallCount:     toolCalls,
		Duration:          duration,
		IsStreaming:       false,
		ContainerID:       p.containerID,
		PodName:           p.podName,
		Namespace:         p.namespace,
		TraceID:           traceID,
	}

	klog.V(3).Infof("LLM_HTTP1: provider=%s model=%s status=%d input=%d output=%d dur=%s",
		tag.Provider, model, statusCode, inputTokens, outputTokens, duration)

	if klog.V(2).Enabled() && inputTokens == 0 && outputTokens == 0 && len(responseBody) > 0 {
		hasPromptTok := bytes.Contains(responseBody, []byte("promptTokenCount"))
		hasUsageMeta := bytes.Contains(responseBody, []byte("usageMetadata"))
		isGzip := len(responseBody) >= 2 && responseBody[0] == 0x1f && responseBody[1] == 0x8b
		head := responseBody
		if len(head) > 64 {
			head = head[:64]
		}
		klog.V(2).Infof("LLM_HTTP1_NOTOKENS: provider=%s len=%d gzip=%v hasPromptTokenCount=%v hasUsageMetadata=%v head=%x",
			tag.Provider, len(responseBody), isGzip, hasPromptTok, hasUsageMeta, head)
	}

	if p.onEvent != nil {
		p.onEvent(event)
	}
}

// FeedHTTP2Data feeds an HTTP/2 DATA frame from an LLM-tagged connection.
// streamID identifies the HTTP/2 stream. isResponse indicates direction.
func (p *LLMParser) FeedHTTP2Data(tag *LLMConnectionTag, streamID uint32,
	data []byte, isResponse bool, path string, statusCode int,
	headers map[string]string) {

	if !isResponse {
		// Request data — we could extract model from it, but response is more reliable.
		// For now, just ensure the stream exists.
		p.mu.Lock()
		if _, exists := p.streams[streamID]; !exists {
			if len(p.streams) >= llmMaxStreams {
				p.evictOldestLocked()
			}

			traceID, parentSpanID := "", ""
			if headers != nil {
				if tp, ok := headers["traceparent"]; ok {
					parts := strings.Split(tp, "-")
					if len(parts) == 4 {
						traceID = parts[1]
						parentSpanID = parts[2]
					}
				}
			}

			p.streams[streamID] = &llmStream{
				provider:     tag.Provider,
				host:         tag.Host,
				path:         path,
				requestTime:  time.Now(),
				lastDataAt:   time.Now(),
				traceID:      traceID,
				parentSpanID: parentSpanID,
				spanID:       generateSpanID(),
			}
		}
		p.mu.Unlock()
		return
	}

	// Response data
	p.mu.Lock()
	s, exists := p.streams[streamID]
	if !exists {
		// Stream created by response before we saw request headers.
		// Create it now — we have the tag from the connection.
		if len(p.streams) >= llmMaxStreams {
			p.evictOldestLocked()
		}
		s = &llmStream{
			provider:    tag.Provider,
			host:        tag.Host,
			path:        path,
			requestTime: time.Now(),
			lastDataAt:  time.Now(),
			spanID:      generateSpanID(),
		}
		p.streams[streamID] = s
	}

	if s.completed {
		p.mu.Unlock()
		return
	}

	// Update status if provided
	if statusCode > 0 {
		s.statusCode = statusCode
	}

	// Track first response data time (TTFT)
	now := time.Now()
	if s.firstDataAt.IsZero() {
		s.firstDataAt = now
	}
	s.lastDataAt = now

	// Accumulate response with ring-buffer behavior — keep the LAST llmMaxBuffer
	// bytes, dropping older bytes when over the cap. For Gemini streaming
	// (and most SSE-style LLM responses), the chunks carrying modelVersion
	// and usageMetadata are continuous through the stream OR concentrated
	// at the tail (finishReason + total tokens). Keeping the head and
	// dropping the tail (the previous behavior) reliably loses both. Ring-
	// buffer behavior preserves the tail.
	s.buffer.Write(data)
	if s.buffer.Len() > llmMaxBuffer {
		s.buffer.Next(s.buffer.Len() - llmMaxBuffer)
	}
	s.bufferSize = s.buffer.Len()

	// Check for SSE completion markers
	completed, reason := checkSSECompletion(data)
	p.mu.Unlock()

	if completed {
		klog.V(3).Infof("LLM_SSE_COMPLETE: stream=%d reason=%s", streamID, reason)
		p.completeStream(streamID)
	}
}

// OnHTTP2StreamEnd is called when END_STREAM flag is received for a stream.
func (p *LLMParser) OnHTTP2StreamEnd(streamID uint32) {
	p.mu.Lock()
	_, exists := p.streams[streamID]
	p.mu.Unlock()

	if exists {
		p.completeStream(streamID)
	}
}

// OnHTTP2Status is called when a response status is received for a stream.
func (p *LLMParser) OnHTTP2Status(streamID uint32, statusCode int) {
	p.mu.Lock()
	s, exists := p.streams[streamID]
	if exists {
		s.statusCode = statusCode
	}
	p.mu.Unlock()

	// Error responses complete immediately
	if exists && statusCode >= 400 {
		p.completeStream(streamID)
	}
}

func (p *LLMParser) completeStream(streamID uint32) {
	p.mu.Lock()
	s, exists := p.streams[streamID]
	if !exists || s.completed {
		p.mu.Unlock()
		return
	}
	s.completed = true
	delete(p.streams, streamID)
	bufData := make([]byte, s.buffer.Len())
	copy(bufData, s.buffer.Bytes())
	p.mu.Unlock()

	completionTime := time.Now()
	duration := completionTime.Sub(s.requestTime)

	var ttft time.Duration
	if !s.firstDataAt.IsZero() {
		ttft = s.firstDataAt.Sub(s.requestTime)
	}

	// Extract model and tokens from accumulated response data
	model, inputTokens, outputTokens := extractFromSSEBuffer(s.provider, bufData)
	cachedTokens := extractCachedTokensFromSSEBuffer(s.provider, bufData)
	toolCalls := extractToolCallCountFromSSEBuffer(s.provider, bufData)
	// DEBUG: log buffer characteristics when token extraction yields zero
	// to help diagnose why downstream metrics (cost/tokens) aren't emitted
	// even when model resolves cleanly via path. Remove once we have a fix.
	if klog.V(2).Enabled() && (inputTokens == 0 && outputTokens == 0) && len(bufData) > 0 {
		isGzip := len(bufData) >= 2 && bufData[0] == 0x1f && bufData[1] == 0x8b
		head := bufData
		if len(head) > 200 {
			head = head[:200]
		}
		klog.V(2).Infof("LLM_BUFFER_DEBUG: provider=%s path=%s buf_len=%d gzip=%v head=%q",
			s.provider, s.path, len(bufData), isGzip, string(head))
	}
	if model == "" {
		model = modelFromPath(s.provider, s.path)
	}
	if model == "" {
		model = "unknown"
	}

	operation := GetOperation(s.path)
	if operation == "" {
		operation = "unknown"
	}

	event := &LLMEvent{
		Provider:          s.provider,
		Model:             model,
		Operation:         operation,
		ServerAddress:     s.host,
		StatusCode:        s.statusCode,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CachedInputTokens: cachedTokens,
		ToolCallCount:     toolCalls,
		Duration:          duration,
		TTFT:              ttft,
		IsStreaming:       true,
		ContainerID:       p.containerID,
		PodName:           p.podName,
		Namespace:         p.namespace,
		TraceID:           s.traceID,
		ParentSpanID:      s.parentSpanID,
		SpanID:            s.spanID,
	}

	klog.Infof("LLM_STREAM_COMPLETE: provider=%s model=%s status=%d input=%d output=%d dur=%s ttft=%s",
		s.provider, model, s.statusCode, inputTokens, outputTokens, duration, ttft)

	if p.onEvent != nil {
		p.onEvent(event)
	}
}

func (p *LLMParser) runGC() {
	ticker := time.NewTicker(llmGCInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.gc()
		}
	}
}

func (p *LLMParser) gc() {
	now := time.Now()
	var toComplete []uint32

	p.mu.Lock()
	for streamID, s := range p.streams {
		if s.completed {
			continue
		}
		if now.Sub(s.lastDataAt) > llmIdleTimeout {
			toComplete = append(toComplete, streamID)
			continue
		}
		if now.Sub(s.requestTime) > llmMaxDuration {
			toComplete = append(toComplete, streamID)
		}
	}
	p.mu.Unlock()

	for _, streamID := range toComplete {
		klog.V(3).Infof("LLM_STREAM_GC: stream=%d", streamID)
		p.completeStream(streamID)
	}
}

func (p *LLMParser) evictOldestLocked() {
	var oldestID uint32
	var oldestTime time.Time
	found := false

	for id, s := range p.streams {
		if !found || s.requestTime.Before(oldestTime) {
			oldestID = id
			oldestTime = s.requestTime
			found = true
		}
	}

	if found {
		klog.Warningf("LLM_STREAM_EVICTED: stream=%d (max streams reached)", oldestID)
		delete(p.streams, oldestID)
	}
}

// ActiveStreamCount returns the number of active streams (for observability).
func (p *LLMParser) ActiveStreamCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.streams)
}

// --- Response body parsing (non-streaming) ---

// extractFromResponseBody extracts model, input tokens, and output tokens from
// a complete (non-streaming) JSON response body.
func extractFromResponseBody(provider LLMProvider, body []byte) (model string, input, output int) {
	if len(body) == 0 {
		return
	}

	// Extract model from response (works for all providers)
	model = extractModelFromResponseJSON(provider, body)

	// Extract tokens based on provider
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		var resp struct {
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			input = resp.Usage.PromptTokens
			output = resp.Usage.CompletionTokens
		}

	case ProviderAnthropic:
		var resp struct {
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			input = resp.Usage.InputTokens
			output = resp.Usage.OutputTokens
		}

	case ProviderGoogle:
		// Gemini's streamGenerateContent returns SSE (multiple "data: {...}"
		// events), not a single JSON object — json.Unmarshal silently fails
		// on the concatenated body. Use regex over the last match so we get
		// the most recent (cumulative) usageMetadata chunk.
		if m := reGeminiPrompt.FindAllSubmatch(body, -1); len(m) > 0 {
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &input)
		}
		if m := reGeminiCandidates.FindAllSubmatch(body, -1); len(m) > 0 {
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &output)
		}
		// Embeddings (:embedContent, :batchEmbedContents) report only
		// "totalTokens" at top level. Map to input_tokens since there is
		// no output to bill.
		if input == 0 {
			if m := reGeminiTotalTokens.FindSubmatch(body); len(m) >= 2 {
				fmt.Sscanf(string(m[1]), "%d", &input)
			}
		}

	case ProviderCohere:
		var resp struct {
			Meta struct {
				Tokens struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"tokens"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			input = resp.Meta.Tokens.InputTokens
			output = resp.Meta.Tokens.OutputTokens
		}

	case ProviderAWSBedrock:
		// Try Converse API
		var converse struct {
			Usage struct {
				InputTokens  int `json:"inputTokens"`
				OutputTokens int `json:"outputTokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &converse); err == nil && (converse.Usage.InputTokens > 0 || converse.Usage.OutputTokens > 0) {
			input = converse.Usage.InputTokens
			output = converse.Usage.OutputTokens
			return
		}
		// Try InvokeModel (Anthropic format)
		var invoke struct {
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &invoke); err == nil {
			input = invoke.Usage.InputTokens
			output = invoke.Usage.OutputTokens
		}
	}

	return
}

// extractCachedTokens extracts the number of input tokens served from the
// provider's prompt cache (already counted in InputTokens above). Returns
// 0 when the provider does not report caching info.
func extractCachedTokens(provider LLMProvider, body []byte) int {
	if len(body) == 0 {
		return 0
	}
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		var resp struct {
			Usage struct {
				PromptTokensDetails struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			return resp.Usage.PromptTokensDetails.CachedTokens
		}
	case ProviderAnthropic:
		var resp struct {
			Usage struct {
				CacheReadInputTokens int `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			return resp.Usage.CacheReadInputTokens
		}
	case ProviderGoogle:
		// Regex: SSE stream isn't a single JSON object; pick the latest match.
		if m := reGeminiCached.FindAllSubmatch(body, -1); len(m) > 0 {
			n := 0
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &n)
			return n
		}
	case ProviderAWSBedrock:
		// Anthropic-on-Bedrock InvokeModel has the same field as Anthropic direct.
		var resp struct {
			Usage struct {
				CacheReadInputTokens int `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			return resp.Usage.CacheReadInputTokens
		}
	}
	return 0
}

// extractToolCallCount counts tool/function calls in a non-streaming response
// body. Tool-call counting is independent of token tokens — used to spot
// agentic workloads and characterize per-request tool fan-out.
func extractToolCallCount(provider LLMProvider, body []byte) int {
	if len(body) == 0 {
		return 0
	}
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		// Chat Completions: choices[].message.tool_calls[]; legacy: function_call (count 1)
		var resp struct {
			Choices []struct {
				Message struct {
					ToolCalls []struct {
						ID string `json:"id"`
					} `json:"tool_calls"`
					FunctionCall *struct {
						Name string `json:"name"`
					} `json:"function_call"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			n := 0
			for _, c := range resp.Choices {
				n += len(c.Message.ToolCalls)
				if c.Message.FunctionCall != nil && c.Message.FunctionCall.Name != "" {
					n++
				}
			}
			return n
		}
	case ProviderAnthropic:
		// Messages API: content[] entries with type="tool_use".
		var resp struct {
			Content []struct {
				Type string `json:"type"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			n := 0
			for _, c := range resp.Content {
				if c.Type == "tool_use" {
					n++
				}
			}
			return n
		}
	case ProviderGoogle:
		// Gemini: count "functionCall": { occurrences. Regex handles SSE
		// (multiple data: events) where json.Unmarshal would fail.
		return len(reGeminiFuncCall.FindAllIndex(body, -1))
	case ProviderAWSBedrock:
		// Converse: output.message.content[] with toolUse entries.
		var converse struct {
			Output struct {
				Message struct {
					Content []struct {
						ToolUse *struct {
							ToolUseID string `json:"toolUseId"`
						} `json:"toolUse"`
					} `json:"content"`
				} `json:"message"`
			} `json:"output"`
		}
		if err := json.Unmarshal(body, &converse); err == nil {
			n := 0
			for _, c := range converse.Output.Message.Content {
				if c.ToolUse != nil && c.ToolUse.ToolUseID != "" {
					n++
				}
			}
			if n > 0 {
				return n
			}
		}
		// InvokeModel (Anthropic-shaped) fallback.
		var anthropic struct {
			Content []struct {
				Type string `json:"type"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &anthropic); err == nil {
			n := 0
			for _, c := range anthropic.Content {
				if c.Type == "tool_use" {
					n++
				}
			}
			return n
		}
	}
	return 0
}

// --- SSE buffer parsing (streaming) ---

// extractFromSSEBuffer extracts model, input tokens, and output tokens from
// accumulated SSE (Server-Sent Events) streaming response data.
// Uses regex instead of JSON parsing because SSE buffers contain multiple
// concatenated JSON fragments.
func extractFromSSEBuffer(provider LLMProvider, data []byte) (model string, input, output int) {
	if len(data) == 0 {
		return
	}

	// Extract model from the response data
	model = extractModelFromResponseJSON(provider, data)

	// Extract tokens using provider-specific patterns
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		if m := reOpenAIUsage1.FindSubmatch(data); len(m) >= 3 {
			fmt.Sscanf(string(m[1]), "%d", &input)
			fmt.Sscanf(string(m[2]), "%d", &output)
		} else if m := reOpenAIUsage2.FindSubmatch(data); len(m) >= 3 {
			fmt.Sscanf(string(m[1]), "%d", &output)
			fmt.Sscanf(string(m[2]), "%d", &input)
		}

	case ProviderAnthropic:
		// First input_tokens value (from message_start)
		if m := reAnthropicInput.FindAllSubmatch(data, -1); len(m) > 0 {
			fmt.Sscanf(string(m[0][1]), "%d", &input)
		}
		// Last output_tokens value (cumulative from message_delta)
		if m := reAnthropicOutput.FindAllSubmatch(data, -1); len(m) > 0 {
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &output)
		}

	case ProviderGoogle:
		// Last values (most recent/accurate)
		if m := reGeminiPrompt.FindAllSubmatch(data, -1); len(m) > 0 {
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &input)
		}
		if m := reGeminiCandidates.FindAllSubmatch(data, -1); len(m) > 0 {
			fmt.Sscanf(string(m[len(m)-1][1]), "%d", &output)
		}

	case ProviderAWSBedrock:
		if m := reBedrockInput.FindSubmatch(data); len(m) >= 2 {
			fmt.Sscanf(string(m[1]), "%d", &input)
		}
		if m := reBedrockOutput.FindSubmatch(data); len(m) >= 2 {
			fmt.Sscanf(string(m[1]), "%d", &output)
		}
	}

	return
}

// --- Model extraction helpers ---

// extractModelFromResponseJSON extracts model name from JSON response data.
// Works for both complete JSON and SSE buffer fragments.
func extractModelFromResponseJSON(provider LLMProvider, data []byte) string {
	switch provider {
	case ProviderGoogle:
		// Google uses "modelVersion" field
		if m := reModelVersionField.FindSubmatch(data); len(m) >= 2 {
			return string(m[1])
		}
		// Fallback to "model" field
		if m := reModelField.FindSubmatch(data); len(m) >= 2 {
			return string(m[1])
		}
	default:
		// All other providers use "model" field
		if m := reModelField.FindSubmatch(data); len(m) >= 2 {
			return string(m[1])
		}
	}
	return ""
}

// extractModelFromRequestBody tries to get model from request JSON body.
// Only used as fallback when response doesn't contain model.
func extractModelFromRequestBody(provider LLMProvider, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if m := reModelField.FindSubmatch(body); len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

// modelFromPath extracts model from URL path as last-resort fallback.
// Uses the same logic for all code paths (no duplication).
func modelFromPath(provider LLMProvider, path string) string {
	if path == "" {
		return ""
	}

	switch provider {
	case ProviderGoogle:
		if m := reGooglePathModel.FindStringSubmatch(path); len(m) >= 2 {
			return m[1]
		}

	case ProviderAWSBedrock:
		if m := reBedrockPathModel.FindStringSubmatch(path); len(m) >= 2 {
			return cleanBedrockModel(m[1])
		}
	}

	return ""
}

// decodeHTTPBody best-effort decodes an HTTP/1.1 response body that may be
// chunked-transfer-encoded and/or gzip-compressed. Returns nil when no
// decoding applies (caller keeps the original bytes); returns the decoded
// bytes on success or partial-success (truncated capture is normal because
// eBPF caps payloads at 4KB).
//
// Detection is by content shape rather than headers: extractHTTPBody
// already stripped the headers, and for chunked encoding we look for the
// "<hex>\r\n" framing at offset 0; for gzip we look for the 1f 8b magic at
// offset 0 of the dechunked stream.
func decodeHTTPBody(body []byte) []byte {
	out := body
	// Step 1: dechunk if it looks like chunked transfer encoding.
	if dechunked := dechunkHTTPBody(body); dechunked != nil {
		out = dechunked
	}
	// Step 2: gunzip if it has the gzip magic.
	if len(out) >= 2 && out[0] == 0x1f && out[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(out))
		if err == nil {
			defer gz.Close()
			// Cap output at 1 MiB — these are LLM responses, not file
			// uploads, and a runaway stream shouldn't OOM the agent.
			plain, err := io.ReadAll(io.LimitReader(gz, 1<<20))
			if (err == nil || err == io.ErrUnexpectedEOF) && len(plain) > 0 {
				return plain
			}
		}
	}
	if !bytes.Equal(out, body) {
		return out
	}
	return nil
}

// dechunkHTTPBody parses HTTP/1.1 chunked transfer encoding. Returns the
// concatenated chunk data or nil if the body doesn't look chunked. Handles
// truncation gracefully: a partial final chunk is included up to the bytes
// available.
func dechunkHTTPBody(body []byte) []byte {
	// Quick reject: must start with hex digits followed by \r\n.
	first := bytes.Index(body, []byte("\r\n"))
	if first <= 0 || first > 16 {
		return nil
	}
	for _, c := range body[:first] {
		if !isHexDigit(c) {
			return nil
		}
	}
	out := make([]byte, 0, len(body))
	pos := 0
	for pos < len(body) {
		nl := bytes.Index(body[pos:], []byte("\r\n"))
		if nl <= 0 || nl > 16 {
			break
		}
		sizeStr := string(body[pos : pos+nl])
		// Strip optional chunk extensions after ';'
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		size64, err := strconv.ParseUint(sizeStr, 16, 32)
		if err != nil {
			break
		}
		pos += nl + 2
		if size64 == 0 {
			break
		}
		end := pos + int(size64)
		if end > len(body) {
			// Truncated mid-chunk — include what we have and stop.
			out = append(out, body[pos:]...)
			break
		}
		out = append(out, body[pos:end]...)
		pos = end + 2 // skip trailing \r\n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// cleanBedrockModel cleans up a Bedrock model identifier.
// Handles URL-encoded ARNs and extracts the friendly model name.
func cleanBedrockModel(raw string) string {
	// URL-decode (ARNs in paths are often percent-encoded)
	decoded := raw
	if strings.Contains(raw, "%") {
		// Simple percent-decoding for common cases
		decoded = strings.ReplaceAll(raw, "%3A", ":")
		decoded = strings.ReplaceAll(decoded, "%2F", "/")
		decoded = strings.ReplaceAll(decoded, "%2f", "/")
		decoded = strings.ReplaceAll(decoded, "%3a", ":")
	}

	// Extract friendly name from ARN:
	// arn:aws:bedrock:region:account:inference-profile/us.meta.llama4-maverick-17b-instruct-v1:0
	if strings.HasPrefix(decoded, "arn:") {
		if lastSlash := strings.LastIndex(decoded, "/"); lastSlash != -1 {
			return decoded[lastSlash+1:]
		}
		if lastColon := strings.LastIndex(decoded, ":"); lastColon != -1 {
			return decoded[lastColon+1:]
		}
	}

	return decoded
}

// --- SSE buffer parsing for cached tokens and tool calls ---

// SSE responses are sequences of JSON fragments rather than single objects;
// each fragment may carry partial state. We use regex over the accumulated
// buffer rather than json.Unmarshal because the byte sequence is not a
// single valid JSON document.
var (
	// OpenAI SSE: "usage":{"prompt_tokens_details":{"cached_tokens":N}}
	reOpenAICachedTokens = regexp.MustCompile(`"prompt_tokens_details"\s*:\s*\{[^}]*"cached_tokens"\s*:\s*(\d+)`)
	// Anthropic SSE: "cache_read_input_tokens":N
	reAnthropicCachedTokens = regexp.MustCompile(`"cache_read_input_tokens"\s*:\s*(\d+)`)
	// Gemini SSE: "cachedContentTokenCount":N
	reGeminiCachedTokens = regexp.MustCompile(`"cachedContentTokenCount"\s*:\s*(\d+)`)

	// OpenAI tool_calls in stream deltas: each tool_call has an "index" field
	// and may be split across many delta frames. Counting unique indices
	// approximates the tool call count without joining fragments.
	reOpenAIToolCallIndex = regexp.MustCompile(`"tool_calls"\s*:\s*\[\s*\{[^}]*"index"\s*:\s*(\d+)`)
	// Anthropic stream: content_block_start with type:tool_use, one per call.
	reAnthropicToolUseStart = regexp.MustCompile(`"type"\s*:\s*"content_block_start"[^}]*"type"\s*:\s*"tool_use"`)
	// Gemini streaming: functionCall objects appearing in parts[].
	reGeminiFunctionCall = regexp.MustCompile(`"functionCall"\s*:\s*\{`)
)

func extractCachedTokensFromSSEBuffer(provider LLMProvider, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	var re *regexp.Regexp
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		re = reOpenAICachedTokens
	case ProviderAnthropic, ProviderAWSBedrock:
		re = reAnthropicCachedTokens
	case ProviderGoogle:
		re = reGeminiCachedTokens
	default:
		return 0
	}
	if m := re.FindSubmatch(data); len(m) >= 2 {
		var n int
		fmt.Sscanf(string(m[1]), "%d", &n)
		return n
	}
	return 0
}

func extractToolCallCountFromSSEBuffer(provider LLMProvider, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		// Count distinct tool_call indices observed in delta frames.
		matches := reOpenAIToolCallIndex.FindAllSubmatch(data, -1)
		if len(matches) == 0 {
			return 0
		}
		seen := map[string]struct{}{}
		for _, m := range matches {
			seen[string(m[1])] = struct{}{}
		}
		return len(seen)
	case ProviderAnthropic, ProviderAWSBedrock:
		return len(reAnthropicToolUseStart.FindAllIndex(data, -1))
	case ProviderGoogle:
		return len(reGeminiFunctionCall.FindAllIndex(data, -1))
	}
	return 0
}

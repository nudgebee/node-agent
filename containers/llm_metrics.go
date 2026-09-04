package containers

import (
	"fmt"
	"strconv"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
)

// LLM Metrics — container_llm_* naming convention.
// Label names follow OTel GenAI semantic conventions where possible.
var (
	ContainerLLMRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_requests_total",
			Help: "Total number of LLM API requests made by containers",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",     // chat, text_completion, embeddings, generate_content
			"gen_ai_request_model",      // gpt-4, claude-3, gemini-2.5-pro, etc.
			"gen_ai_provider_name",      // openai, anthropic, gcp.gemini, aws.bedrock
			"server_address",            // api.openai.com, generativelanguage.googleapis.com
			"http_response_status_code", // 200, 400, 429, 500
		},
	)

	ContainerLLMTokenUsageTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_token_usage_total",
			Help: "Total tokens processed by LLM APIs",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
			"server_address",
			"gen_ai_token_type", // input, output
		},
	)

	ContainerLLMTimeToFirstToken = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "container_llm_time_to_first_token_seconds",
			Help: "Time from request sent to first response token received",
			// OTel GenAI v1.37 recommended boundaries for gen_ai.server.time_to_first_token.
			Buckets: []float64{0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0},
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
			"server_address",
		},
	)

	ContainerLLMRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "container_llm_request_duration_seconds",
			Help: "Total LLM request duration",
			// OTel GenAI v1.37 recommended boundaries for gen_ai.client.operation.duration.
			Buckets: []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92},
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
			"server_address",
		},
	)

	ContainerLLMTokensPerSecond = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_tokens_per_second",
			Help:    "Token generation throughput (output tokens / generation time)",
			Buckets: []float64{5, 10, 20, 30, 50, 75, 100, 150, 200},
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
		},
	)

	ContainerLLMErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_errors_total",
			Help: "Total LLM request errors by error type",
		},
		[]string{
			"container_id",
			"gen_ai_provider_name",
			"gen_ai_request_model",
			"error_type", // rate_limit, timeout, invalid_request, server_error, auth_error
		},
	)

	// LLMSNITagsTotal counts successful SNI-based provider tags. Each
	// increment means the agent caught a TLS ClientHello with an SNI that
	// matched a known LLM provider. Useful for spotting tagging regressions
	// independently of whether downstream HTTP/2 parsing succeeds.
	LLMSNITagsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_llm_sni_tags_total",
			Help: "Total LLM connections tagged via TLS ClientHello SNI",
		},
		[]string{"provider"},
	)

	// LLMHPACKDecodeErrorsTotal counts HPACK decode failures in the HTTP/2
	// parser. When non-zero on llm-server connections, indicates the agent
	// joined a long-lived HTTP/2 connection mid-stream and lost dynamic-table
	// state (the classic Go-TLS-HTTP/2 mid-stream-join failure mode).
	// The SNI path bypasses this; this counter is the early warning.
	LLMHPACKDecodeErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "node_agent_hpack_decode_errors_total",
			Help: "Total HPACK decode errors in HTTP/2 parser (mid-stream join indicator)",
		},
	)

	// L7EventsTotal counts L7 events reaching userspace, and
	// L7PayloadTruncatedTotal counts the subset whose payload exceeded
	// MAX_PAYLOAD_SIZE and was therefore cut short in the kernel (the tail is
	// discarded, not delivered in a later event).
	//
	// The pair exists to make the truncation rate measurable per protocol and
	// per destination class. It matters most for HTTP/2: HPACK is stateful, so
	// a truncated frame cannot simply be skipped the way a truncated HTTP/1.1
	// request can. Compare
	//   rate(node_agent_l7_payload_truncated_total{protocol="http2",destination="external"}[5m])
	// against the same labels on node_agent_l7_events_total to see what share of
	// external HTTP/2 traffic is arriving incomplete.
	// direction is "client"/"server" for HTTP/2 (which frames the event carries)
	// and "-" for protocols where the distinction does not apply.
	//
	// External HTTP/2 delivers ~22,000 events per stream created, against ~105
	// internally. Splitting by direction separates the two explanations for
	// that: if server-frame events are scarce, responses never reach the parser;
	// if they are plentiful, the bytes being fed to it are not HTTP/2 at all and
	// the port-based detection heuristic is over-matching.
	L7EventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_l7_events_total",
			Help: "L7 events processed, by protocol, destination class and frame direction",
		},
		[]string{"protocol", "destination", "direction"},
	)

	L7PayloadTruncatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_l7_payload_truncated_total",
			Help: "L7 events whose payload exceeded MAX_PAYLOAD_SIZE and was truncated in the kernel",
		},
		[]string{"protocol", "destination"},
	)

	// Http2ParserCapDropsTotal counts HTTP/2 events discarded because the
	// per-container parser map was already at maxHTTP2ParsersPerContainer.
	//
	// gc() only reclaims a parser whose connection is gone if the parser also
	// looks idle (no active requests, no partial data). A parser holding
	// requests that never completed therefore survives its connection
	// indefinitely, so a container with connection churn can fill the cap and
	// then silently drop every subsequent HTTP/2 connection. Non-zero here means
	// events are being lost before any parsing is attempted.
	Http2ParserCapDropsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_parser_cap_drops_total",
			Help: "HTTP/2 events dropped because the per-container parser cap was reached",
		},
		[]string{"destination"},
	)

	// Http2ParserStaleReuseTotal counts times a parser was found for a pid/fd
	// but had been created for a different connection (the fd was recycled).
	//
	// Parsers are keyed by pid+fd only. A recycled fd therefore hands the new
	// connection a parser whose HPACK dynamic table belongs to the previous one,
	// which desynchronises decoding immediately. Non-zero here is a direct
	// source of node_agent_hpack_decode_errors_total.
	Http2ParserStaleReuseTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_parser_stale_reuse_total",
			Help: "HTTP/2 parsers reused across different connections on a recycled fd",
		},
		[]string{"destination"},
	)

	// Http2StageTotal counts HTTP/2 requests reaching each stage of the parser
	// pipeline, so the point where they stop can be read directly instead of
	// inferred. Stages, in order:
	//
	//   stream_created   client HEADERS decoded, request object created
	//   response_status  :status seen on the response
	//   end_stream       END_STREAM flag seen (a frame flag, not HPACK)
	//   completed        both of the above -> request emitted
	//   hpack_error      HPACK block failed to decode; decoder reset
	//
	// A request is only emitted with BOTH response_status and end_stream, so
	// whichever stage drops to zero is the blocker.
	Http2StageTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_stage_total",
			Help: "HTTP/2 requests reaching each stage of the parser pipeline",
		},
		[]string{"stage", "destination"},
	)

	// Http2FramesTotal counts HTTP/2 frame headers the parser walks, by type.
	//
	// External HTTP/2 delivers ~44k client-frame events per 5 minutes but only
	// ~71 streams, against ~161k events and ~10.8k streams internally — 86x
	// worse. Either those events contain almost no HEADERS frames, or they are
	// not HTTP/2 at all. Frame type distinguishes the two directly: "invalid"
	// dominating means the bytes are not HTTP/2 and the eBPF port heuristic is
	// over-matching; DATA/WINDOW_UPDATE dominating with no HEADERS means the
	// request headers are being lost before the parser sees them.
	//
	// Deliberately structural. These events carry decrypted application
	// traffic, so dumping payloads to diagnose this would put Authorization
	// headers and request bodies into agent logs; frame type, and the counts
	// alone, disclose nothing.
	Http2FramesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_frames_total",
			Help: "HTTP/2 frame headers parsed, by frame type and destination class",
		},
		[]string{"type", "destination"},
	)

	// Http2PayloadSizeTotal buckets the delivered payload length of HTTP/2
	// events, by destination class and frame direction.
	//
	// 96% of external HTTP/2 events yield no parseable frame (8,881 frames from
	// ~221k events) against 44% internally. Parse() can only produce nothing for
	// three reasons: an empty payload, fewer than 9 bytes (shorter than a frame
	// header), or a first frame header that fails validation — and the third is
	// already counted as type="invalid" in Http2FramesTotal. So the answer is in
	// the size distribution.
	//
	// The "9-16" bucket is the one to watch. A correct HTTP/2 reader does
	// io.ReadFull(header[:9]) and then reads the frame payload separately, so
	// SSL_read returns header-sized and payload-only chunks rather than whole
	// frames. The parser assumes each event begins on a frame boundary and
	// contains complete frames; if external reads are predominantly 9 bytes,
	// that assumption is the bug and the parser needs to treat the connection as
	// a continuous byte stream instead.
	Http2PayloadSizeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_payload_size_total",
			Help: "HTTP/2 event payload sizes delivered to the parser, bucketed",
		},
		[]string{"bucket", "destination", "direction"},
	)

	// ContainerLLMCachedTokensTotal counts input tokens served from the
	// provider's prompt cache. Already counted in token_usage_total{type=input};
	// this is a separate metric to make cache-hit rate computable.
	ContainerLLMCachedTokensTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_cached_input_tokens_total",
			Help: "Cumulative input tokens served from the provider's prompt cache",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
			"server_address",
		},
	)

	// ContainerLLMToolCallsTotal counts tool/function-call invocations in
	// completed responses. Useful for spotting agentic workloads and per-
	// request tool fan-out.
	ContainerLLMToolCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_tool_calls_total",
			Help: "Cumulative tool/function-call invocations in LLM responses",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
		},
	)

	// ContainerLLMCostUSDTotal records derived cost in USD from a static
	// pricing table (containers/llm_pricing.go). Best-effort and excludes
	// volume discounts; reconcile with provider invoices for billing.
	// Series only emitted when pricing matches the model.
	ContainerLLMCostUSDTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_cost_usd_total",
			Help: "Cumulative LLM cost in USD (best-effort, list prices, no volume discount)",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_provider_name",
			"server_address",
		},
	)
)

// RegisterLLMMetrics registers all LLM metrics with the provided registerer
// and wires l7-package callbacks that increment self-observability counters.
func RegisterLLMMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		ContainerLLMRequestsTotal,
		ContainerLLMTokenUsageTotal,
		ContainerLLMTimeToFirstToken,
		ContainerLLMRequestDuration,
		ContainerLLMTokensPerSecond,
		ContainerLLMErrorsTotal,
		LLMSNITagsTotal,
		LLMHPACKDecodeErrorsTotal,
		L7EventsTotal,
		L7PayloadTruncatedTotal,
		Http2ParserCapDropsTotal,
		Http2ParserStaleReuseTotal,
		Http2StageTotal,
		Http2FramesTotal,
		Http2PayloadSizeTotal,
		ContainerLLMCachedTokensTotal,
		ContainerLLMToolCallsTotal,
		ContainerLLMCostUSDTotal,
	)
	// Hook the HTTP/2 parser's HPACK error path so we get a counter without
	// l7 having to import prometheus.
	l7.OnHPACKDecodeError = func() { LLMHPACKDecodeErrorsTotal.Inc() }
	l7.OnHttp2Frame = func(frameType, dest string) {
		if dest == "" {
			dest = "unknown"
		}
		Http2FramesTotal.WithLabelValues(frameType, dest).Inc()
	}
	l7.OnHttp2Stage = func(stage, dest string) {
		if dest == "" {
			dest = "unknown"
		}
		Http2StageTotal.WithLabelValues(stage, dest).Inc()
	}
}

// RecordLLMEvent is the single entry point for recording LLM metrics.
// Both HTTP/1.1 and HTTP/2, streaming and non-streaming, use this function.
// This replaces the old split between trackLLMRequest() and RecordLLMStreamMetrics().
func RecordLLMEvent(event *LLMEvent) {
	if event == nil {
		return
	}

	containerID := event.ContainerID
	provider := string(event.Provider)
	model := event.Model
	if model == "" {
		model = "unknown"
	}
	operation := event.Operation
	if operation == "" {
		operation = "unknown"
	}

	statusStr := strconv.Itoa(event.StatusCode)
	if event.StatusCode == 0 {
		statusStr = "200" // Default for non-streaming where status wasn't captured
	}

	// Request counter
	ContainerLLMRequestsTotal.With(prometheus.Labels{
		"container_id":              containerID,
		"gen_ai_operation_name":     operation,
		"gen_ai_request_model":      model,
		"gen_ai_provider_name":      provider,
		"server_address":            event.ServerAddress,
		"http_response_status_code": statusStr,
	}).Inc()

	baseLabels := prometheus.Labels{
		"container_id":          containerID,
		"gen_ai_operation_name": operation,
		"gen_ai_request_model":  model,
		"gen_ai_provider_name":  provider,
		"server_address":        event.ServerAddress,
	}

	// Token usage
	if event.InputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_provider_name":  provider,
			"server_address":        event.ServerAddress,
			"gen_ai_token_type":     "input",
		}).Add(float64(event.InputTokens))
	}
	if event.OutputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_provider_name":  provider,
			"server_address":        event.ServerAddress,
			"gen_ai_token_type":     "output",
		}).Add(float64(event.OutputTokens))
	}

	// Cached input tokens (subset of input tokens served from prompt cache).
	if event.CachedInputTokens > 0 {
		ContainerLLMCachedTokensTotal.With(baseLabels).Add(float64(event.CachedInputTokens))
	}

	// Tool/function calls observed in the response.
	if event.ToolCallCount > 0 {
		ContainerLLMToolCallsTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_provider_name":  provider,
		}).Add(float64(event.ToolCallCount))
	}

	// Cost in USD (best-effort from static pricing table). Only emitted when
	// a pricing entry matches the model — absent series means "no pricing"
	// rather than "$0".
	if cost := CalculateCostUSD(event.Provider, event.Model,
		event.InputTokens, event.OutputTokens, event.CachedInputTokens); cost > 0 {
		ContainerLLMCostUSDTotal.With(baseLabels).Add(cost)
	}

	// Duration
	if event.Duration > 0 {
		ContainerLLMRequestDuration.With(baseLabels).Observe(event.Duration.Seconds())
	}

	// TTFT (streaming only)
	if event.TTFT > 0 {
		ContainerLLMTimeToFirstToken.With(baseLabels).Observe(event.TTFT.Seconds())
	}

	// Tokens per second (streaming: output_tokens / generation_time)
	if event.OutputTokens > 0 && event.TTFT > 0 && event.Duration > event.TTFT {
		genDuration := (event.Duration - event.TTFT).Seconds()
		if genDuration > 0 {
			tps := float64(event.OutputTokens) / genDuration
			ContainerLLMTokensPerSecond.With(prometheus.Labels{
				"container_id":          containerID,
				"gen_ai_operation_name": operation,
				"gen_ai_request_model":  model,
				"gen_ai_provider_name":  provider,
			}).Observe(tps)
		}
	}

	// Errors
	if event.StatusCode >= 400 {
		ContainerLLMErrorsTotal.With(prometheus.Labels{
			"container_id":         containerID,
			"gen_ai_provider_name": provider,
			"gen_ai_request_model": model,
			"error_type":           categorizeHTTPError(event.StatusCode),
		}).Inc()
	}
}

// categorizeHTTPError converts HTTP status code to error type.
func categorizeHTTPError(statusCode int) string {
	switch statusCode {
	case 429:
		return "rate_limit"
	case 400, 422:
		return "invalid_request"
	case 401, 403:
		return "auth_error"
	case 500, 502, 503, 504:
		return "server_error"
	case 408:
		return "timeout"
	default:
		if statusCode >= 400 && statusCode < 500 {
			return "client_error"
		}
		if statusCode >= 500 {
			return "server_error"
		}
		return fmt.Sprintf("http_%d", statusCode)
	}
}

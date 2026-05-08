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
			"gen_ai_system",             // openai, anthropic, gcp.gemini, aws.bedrock
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
			"gen_ai_system",
			"server_address",
			"gen_ai_token_type", // input, output
		},
	)

	ContainerLLMTimeToFirstToken = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_time_to_first_token_seconds",
			Help:    "Time from request sent to first response token received",
			Buckets: []float64{0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0},
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_system",
			"server_address",
		},
	)

	ContainerLLMRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_request_duration_seconds",
			Help:    "Total LLM request duration",
			Buckets: []float64{0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0},
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",
			"gen_ai_request_model",
			"gen_ai_system",
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
			"gen_ai_system",
		},
	)

	ContainerLLMErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_errors_total",
			Help: "Total LLM request errors by error type",
		},
		[]string{
			"container_id",
			"gen_ai_system",
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
	)
	// Hook the HTTP/2 parser's HPACK error path so we get a counter without
	// l7 having to import prometheus.
	l7.OnHPACKDecodeError = func() { LLMHPACKDecodeErrorsTotal.Inc() }
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
		"gen_ai_system":             provider,
		"server_address":            event.ServerAddress,
		"http_response_status_code": statusStr,
	}).Inc()

	baseLabels := prometheus.Labels{
		"container_id":          containerID,
		"gen_ai_operation_name": operation,
		"gen_ai_request_model":  model,
		"gen_ai_system":         provider,
		"server_address":        event.ServerAddress,
	}

	// Token usage
	if event.InputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_system":         provider,
			"server_address":        event.ServerAddress,
			"gen_ai_token_type":     "input",
		}).Add(float64(event.InputTokens))
	}
	if event.OutputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_system":         provider,
			"server_address":        event.ServerAddress,
			"gen_ai_token_type":     "output",
		}).Add(float64(event.OutputTokens))
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
				"gen_ai_system":         provider,
			}).Observe(tps)
		}
	}

	// Errors
	if event.StatusCode >= 400 {
		ContainerLLMErrorsTotal.With(prometheus.Labels{
			"container_id":         containerID,
			"gen_ai_system":        provider,
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

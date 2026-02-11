package containers

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// LLM Metrics - container_llm_* naming convention
// These metrics track LLM API usage from containers
var (
	// ContainerLLMRequestsTotal tracks total LLM API requests
	ContainerLLMRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_requests_total",
			Help: "Total number of LLM API requests made by containers",
		},
		[]string{
			"container_id",
			"gen_ai_operation_name",     // chat, text_completion, embeddings, generate_content
			"gen_ai_request_model",      // gemini-2.5-pro, gpt-4, claude-3, etc.
			"gen_ai_system",             // openai, anthropic, gcp.gemini, aws.bedrock, azure.ai.openai
			"server_address",            // api.openai.com, generativelanguage.googleapis.com
			"http_response_status_code", // 200, 400, 429, 500, etc.
		},
	)

	// ContainerLLMTokenUsageTotal tracks tokens consumed
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

	// ContainerLLMTimeToFirstToken tracks TTFT - critical UX metric
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

	// ContainerLLMRequestDuration tracks total request duration
	ContainerLLMRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_request_duration_seconds",
			Help:    "Total LLM request duration from first byte to stream complete",
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

	// ContainerLLMTokensPerSecond tracks generation throughput
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

	// ContainerLLMErrorsTotal tracks errors by type
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
)

// RegisterLLMMetrics registers LLM metrics with the provided registerer.
// This must be called with the same registerer used for other container metrics.
func RegisterLLMMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		ContainerLLMRequestsTotal,
		ContainerLLMTokenUsageTotal,
		ContainerLLMTimeToFirstToken,
		ContainerLLMRequestDuration,
		ContainerLLMTokensPerSecond,
		ContainerLLMErrorsTotal,
	)
}

// RecordLLMStreamMetrics records metrics for a completed LLM stream
func RecordLLMStreamMetrics(stream *LLMStream) {
	if stream == nil {
		return
	}

	containerID := stream.ContainerID

	provider := string(stream.Provider)
	model := stream.Model
	if model == "" {
		model = "unknown"
	}
	operation := stream.Operation
	if operation == "" {
		operation = "unknown"
	}
	serverAddress := stream.ServerAddress

	// Request counter
	ContainerLLMRequestsTotal.With(prometheus.Labels{
		"container_id":              containerID,
		"gen_ai_operation_name":     operation,
		"gen_ai_request_model":      model,
		"gen_ai_system":             provider,
		"server_address":            serverAddress,
		"http_response_status_code": strconv.Itoa(stream.StatusCode),
	}).Inc()

	// Token usage
	if stream.InputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_system":         provider,
			"server_address":        serverAddress,
			"gen_ai_token_type":     "input",
		}).Add(float64(stream.InputTokens))
	}
	if stream.OutputTokens > 0 {
		ContainerLLMTokenUsageTotal.With(prometheus.Labels{
			"container_id":          containerID,
			"gen_ai_operation_name": operation,
			"gen_ai_request_model":  model,
			"gen_ai_system":         provider,
			"server_address":        serverAddress,
			"gen_ai_token_type":     "output",
		}).Add(float64(stream.OutputTokens))
	}

	baseLabels := prometheus.Labels{
		"container_id":          containerID,
		"gen_ai_operation_name": operation,
		"gen_ai_request_model":  model,
		"gen_ai_system":         provider,
		"server_address":        serverAddress,
	}

	// TTFT (Time to First Token)
	if !stream.FirstTokenTime.IsZero() {
		ttft := stream.FirstTokenTime.Sub(stream.RequestTime).Seconds()
		ContainerLLMTimeToFirstToken.With(baseLabels).Observe(ttft)
	}

	// Request duration
	if !stream.CompletionTime.IsZero() {
		duration := stream.CompletionTime.Sub(stream.RequestTime).Seconds()
		ContainerLLMRequestDuration.With(baseLabels).Observe(duration)
	}

	// Tokens per second
	if stream.OutputTokens > 0 && !stream.FirstTokenTime.IsZero() && !stream.CompletionTime.IsZero() {
		genDuration := stream.CompletionTime.Sub(stream.FirstTokenTime).Seconds()
		if genDuration > 0 {
			tps := float64(stream.OutputTokens) / genDuration
			ContainerLLMTokensPerSecond.With(prometheus.Labels{
				"container_id":          containerID,
				"gen_ai_operation_name": operation,
				"gen_ai_request_model":  model,
				"gen_ai_system":         provider,
			}).Observe(tps)
		}
	}

	// Errors
	if stream.State == StreamStateError || stream.StatusCode >= 400 {
		errorType := categorizeHTTPError(stream.StatusCode)
		if stream.State == StreamStateTimedOut {
			errorType = "timeout"
		}
		ContainerLLMErrorsTotal.With(prometheus.Labels{
			"container_id":         containerID,
			"gen_ai_system":        provider,
			"gen_ai_request_model": model,
			"error_type":           errorType,
		}).Inc()
	}
}

// categorizeHTTPError converts HTTP status code to error type
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

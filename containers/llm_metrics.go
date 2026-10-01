package containers

import (
	"strconv"

	"github.com/coroot/coroot-node-agent/llm"
	"github.com/prometheus/client_golang/prometheus"
)

// LLM metrics follow the OpenTelemetry GenAI semantic conventions for label
// names and values. Cost is deliberately absent: prices change and are
// negotiated per customer, so it belongs where token counts are joined with a
// price list, not in the agent.
var llmLabels = []string{
	"container_id",
	"gen_ai_provider_name",
	"gen_ai_request_model",
	"gen_ai_operation_name",
	"server_address",
}

var (
	ContainerLLMRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_requests_total",
			Help: "LLM API requests, by response status",
		},
		append(llmLabels[:len(llmLabels):len(llmLabels)], "http_response_status_code"),
	)

	// ContainerLLMTokensTotal splits usage into disjoint token types, so the
	// sum over gen_ai_token_type is what the provider bills: input (not served
	// from a cache), cached_input, cache_write, output (excluding reasoning)
	// and reasoning.
	ContainerLLMTokensTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_llm_tokens_total",
			Help: "LLM tokens used, by token type",
		},
		append(llmLabels[:len(llmLabels):len(llmLabels)], "gen_ai_token_type"),
	)

	ContainerLLMRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_request_duration_seconds",
			Help:    "Time from the first byte of an LLM API request to the last byte of its response",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 40, 80},
		},
		llmLabels,
	)

	ContainerLLMTimeToFirstToken = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "container_llm_time_to_first_token_seconds",
			Help:    "Time from the first byte of a streaming LLM API request to the first byte of its response body",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16},
		},
		llmLabels,
	)

	// LLMCaptureTotal makes the capture's completeness measurable. Per
	// request: completed (usage extracted), no_usage, undecodable, truncated.
	// Per connection: tagged, missed_start, unrecoverable, overflow, and
	// capacity when a container has too many captured connections.
	LLMCaptureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_llm_capture_total",
			Help: "LLM capture outcomes, per request and per connection",
		},
		[]string{"outcome"},
	)
)

func RegisterLLMMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		ContainerLLMRequestsTotal,
		ContainerLLMTokensTotal,
		ContainerLLMRequestDuration,
		ContainerLLMTimeToFirstToken,
		LLMCaptureTotal,
	)
}

func recordLLMExchange(containerID string, e *llm.Exchange) {
	model := e.Model
	if model == "" {
		model = "unknown"
	}
	labels := []string{containerID, string(e.Provider), model, string(e.Operation), e.ServerAddress}
	ContainerLLMRequestsTotal.WithLabelValues(append(labels, strconv.Itoa(e.StatusCode))...).Inc()
	for _, t := range []struct {
		name  string
		count int64
	}{
		{"input", e.Usage.Input},
		{"cached_input", e.Usage.CachedInput},
		{"cache_write", e.Usage.CacheWrite},
		{"output", e.Usage.Output},
		{"reasoning", e.Usage.Reasoning},
	} {
		if t.count > 0 {
			ContainerLLMTokensTotal.WithLabelValues(append(labels, t.name)...).Add(float64(t.count))
		}
	}
	if d := e.Duration(); d > 0 {
		ContainerLLMRequestDuration.WithLabelValues(labels...).Observe(d.Seconds())
	}
	if ttft := e.TimeToFirstToken(); ttft > 0 {
		ContainerLLMTimeToFirstToken.WithLabelValues(labels...).Observe(ttft.Seconds())
	}
	if e.Outcome != "" {
		LLMCaptureTotal.WithLabelValues(string(e.Outcome)).Inc()
	}
}

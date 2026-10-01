package llm

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Usage is the token accounting of one request. The fields are disjoint, so
// their sum is what the provider bills, and each can be priced on its own:
//
//	Input        prompt tokens not served from a cache
//	CachedInput  prompt tokens read from the provider's prompt cache
//	CacheWrite   prompt tokens written to the cache (billed at a premium)
//	Output       generated tokens, excluding reasoning
//	Reasoning    hidden reasoning ("thinking") tokens, billed as output
//
// Providers report overlapping totals instead (OpenAI's prompt_tokens includes
// cached tokens, Gemini's promptTokenCount does too, Anthropic's input_tokens
// does not), so each wire format is normalised here.
type Usage struct {
	Input       int64
	CachedInput int64
	CacheWrite  int64
	Output      int64
	Reasoning   int64
}

func (u Usage) Total() int64 {
	return u.Input + u.CachedInput + u.CacheWrite + u.Output + u.Reasoning
}

// counts are the raw usage fields of every supported wire format. JSON keys
// differ by more than case between formats, so one struct holds them all.
type counts struct {
	// OpenAI chat/completions/embeddings
	PromptTokens        *int64 `json:"prompt_tokens"`
	CompletionTokens    *int64 `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`

	// OpenAI Responses API, Anthropic, Cohere v2
	InputTokens        *int64 `json:"input_tokens"`
	OutputTokens       *int64 `json:"output_tokens"`
	InputTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`

	// Bedrock Converse
	BedrockInputTokens  *int64 `json:"inputTokens"`
	BedrockOutputTokens *int64 `json:"outputTokens"`
	BedrockCacheRead    *int64 `json:"cacheReadInputTokens"`
	BedrockCacheWrite   *int64 `json:"cacheWriteInputTokens"`

	// Cohere v2: {"usage": {"tokens": {...}, "billed_units": {...}}}
	Tokens      *counts `json:"tokens"`
	BilledUnits *counts `json:"billed_units"`
}

type geminiUsage struct {
	PromptTokenCount        *int64 `json:"promptTokenCount"`
	CandidatesTokenCount    *int64 `json:"candidatesTokenCount"`
	CachedContentTokenCount *int64 `json:"cachedContentTokenCount"`
	ThoughtsTokenCount      *int64 `json:"thoughtsTokenCount"`
	ToolUsePromptTokenCount *int64 `json:"toolUsePromptTokenCount"`
}

type bedrockMetrics struct {
	InputTokenCount           *int64 `json:"inputTokenCount"`
	OutputTokenCount          *int64 `json:"outputTokenCount"`
	CacheReadInputTokenCount  *int64 `json:"cacheReadInputTokenCount"`
	CacheWriteInputTokenCount *int64 `json:"cacheWriteInputTokenCount"`
}

// document is any JSON payload a supported API returns or streams.
type document struct {
	Model        string `json:"model"`
	ModelVersion string `json:"modelVersion"`

	Usage         *counts      `json:"usage"`
	UsageMetadata *geminiUsage `json:"usageMetadata"`

	// Anthropic message_start; OpenAI Responses response.completed
	Message *struct {
		Model string  `json:"model"`
		Usage *counts `json:"usage"`
	} `json:"message"`
	Response *struct {
		Model string  `json:"model"`
		Usage *counts `json:"usage"`
	} `json:"response"`

	// Cohere v1
	Meta *struct {
		BilledUnits *counts `json:"billed_units"`
	} `json:"meta"`

	// Bedrock InvokeModel: the last streamed chunk carries these, and Titan
	// embeddings report their input size this way.
	InvocationMetrics   *bedrockMetrics `json:"amazon-bedrock-invocationMetrics"`
	InputTextTokenCount *int64          `json:"inputTextTokenCount"`
	// Bedrock invoke-with-response-stream wraps each model chunk in base64.
	Bytes []byte `json:"bytes"`
}

// tally accumulates usage across the payloads of one response. Streams repeat
// or extend counts as they go, so for every field the last value seen wins.
type tally struct {
	model string
	found bool

	input, cached, cacheWrite, output, reasoning *int64
	// inputIncludesCached marks formats whose input count is a superset of
	// the cached count (OpenAI, Gemini), as opposed to disjoint (Anthropic,
	// Bedrock).
	inputIncludesCached  bool
	outputIncludesReason bool
}

func set(dst **int64, v *int64) {
	if v != nil {
		*dst = v
	}
}

func setV(dst **int64, v int64) {
	*dst = &v
}

func (t *tally) counts(f family, c *counts) {
	if c == nil {
		return
	}
	if c.Tokens != nil {
		c = c.Tokens
	} else if c.BilledUnits != nil && c.InputTokens == nil && c.PromptTokens == nil {
		c = c.BilledUnits
	}
	before := *t
	switch {
	case c.PromptTokens != nil: // OpenAI chat/completions/embeddings
		set(&t.input, c.PromptTokens)
		set(&t.output, c.CompletionTokens)
		if c.PromptTokensDetails != nil {
			setV(&t.cached, c.PromptTokensDetails.CachedTokens)
		}
		if c.CompletionTokensDetails != nil {
			setV(&t.reasoning, c.CompletionTokensDetails.ReasoningTokens)
		}
		t.inputIncludesCached, t.outputIncludesReason = true, true
	case c.InputTokens != nil || c.OutputTokens != nil:
		set(&t.input, c.InputTokens)
		set(&t.output, c.OutputTokens)
		if f == familyAnthropic || c.CacheReadInputTokens != nil || c.CacheCreationInputTokens != nil {
			set(&t.cached, c.CacheReadInputTokens)
			set(&t.cacheWrite, c.CacheCreationInputTokens)
		} else { // OpenAI Responses API
			if c.InputTokensDetails != nil {
				setV(&t.cached, c.InputTokensDetails.CachedTokens)
				t.inputIncludesCached = true
			}
			if c.OutputTokensDetails != nil {
				setV(&t.reasoning, c.OutputTokensDetails.ReasoningTokens)
				t.outputIncludesReason = true
			}
		}
	case c.BedrockInputTokens != nil || c.BedrockOutputTokens != nil:
		set(&t.input, c.BedrockInputTokens)
		set(&t.output, c.BedrockOutputTokens)
		set(&t.cached, c.BedrockCacheRead)
		set(&t.cacheWrite, c.BedrockCacheWrite)
	}
	if t.input != before.input || t.output != before.output {
		t.found = true
	}
}

func (t *tally) document(f family, d *document) {
	switch {
	case d.Message != nil && d.Message.Model != "":
		t.model = d.Message.Model
	case d.Response != nil && d.Response.Model != "":
		t.model = d.Response.Model
	case d.ModelVersion != "":
		t.model = d.ModelVersion
	case d.Model != "":
		t.model = d.Model
	}
	t.counts(f, d.Usage)
	if d.Message != nil {
		t.counts(f, d.Message.Usage)
	}
	if d.Response != nil {
		t.counts(f, d.Response.Usage)
	}
	if d.Meta != nil {
		t.counts(f, d.Meta.BilledUnits)
	}
	if g := d.UsageMetadata; g != nil && (g.PromptTokenCount != nil || g.CandidatesTokenCount != nil) {
		input := g.PromptTokenCount
		if input != nil && g.ToolUsePromptTokenCount != nil {
			v := *input + *g.ToolUsePromptTokenCount
			input = &v
		}
		set(&t.input, input)
		set(&t.output, g.CandidatesTokenCount)
		set(&t.cached, g.CachedContentTokenCount)
		set(&t.reasoning, g.ThoughtsTokenCount)
		t.inputIncludesCached = true
		t.found = true
	}
	if m := d.InvocationMetrics; m != nil && (m.InputTokenCount != nil || m.OutputTokenCount != nil) {
		set(&t.input, m.InputTokenCount)
		set(&t.output, m.OutputTokenCount)
		set(&t.cached, m.CacheReadInputTokenCount)
		set(&t.cacheWrite, m.CacheWriteInputTokenCount)
		t.found = true
	}
	if d.InputTextTokenCount != nil {
		set(&t.input, d.InputTextTokenCount)
		t.found = true
	}
	if len(d.Bytes) > 0 {
		var inner document
		if json.Unmarshal(d.Bytes, &inner) == nil {
			t.document(f, &inner)
		}
	}
}

func (t *tally) usage() Usage {
	v := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	u := Usage{
		Input:       v(t.input),
		CachedInput: v(t.cached),
		CacheWrite:  v(t.cacheWrite),
		Output:      v(t.output),
		Reasoning:   v(t.reasoning),
	}
	if t.inputIncludesCached {
		u.Input -= u.CachedInput
	}
	if t.outputIncludesReason {
		u.Output -= u.Reasoning
	}
	if u.Input < 0 {
		u.Input = 0
	}
	if u.Output < 0 {
		u.Output = 0
	}
	return u
}

// bedrockHeaderUsage reads the token counts Bedrock InvokeModel returns as
// response headers. They exist for every model, so they win over whatever the
// model-specific body says.
func bedrockHeaderUsage(h http.Header) (Usage, bool) {
	in, errIn := strconv.ParseInt(h.Get("X-Amzn-Bedrock-Input-Token-Count"), 10, 64)
	out, errOut := strconv.ParseInt(h.Get("X-Amzn-Bedrock-Output-Token-Count"), 10, 64)
	if errIn != nil && errOut != nil {
		return Usage{}, false
	}
	u := Usage{Input: in, Output: out}
	if v, err := strconv.ParseInt(h.Get("X-Amzn-Bedrock-Cache-Read-Input-Token-Count"), 10, 64); err == nil {
		u.CachedInput = v
	}
	if v, err := strconv.ParseInt(h.Get("X-Amzn-Bedrock-Cache-Write-Input-Token-Count"), 10, 64); err == nil {
		u.CacheWrite = v
	}
	return u, true
}

// extractUsage reads the model and token usage from a decoded response body.
func extractUsage(f family, header http.Header, body []byte) (model string, u Usage, found bool) {
	var t tally
	for _, p := range payloads(header.Get("Content-Type"), body) {
		var d document
		if json.Unmarshal(p, &d) != nil {
			continue
		}
		t.document(f, &d)
	}
	if f == familyBedrock {
		if hu, ok := bedrockHeaderUsage(header); ok {
			return t.model, hu, true
		}
	}
	return t.model, t.usage(), t.found
}

package containers

import "strings"

// ModelPricing is per-million-tokens pricing in USD for a given model.
// Values are best-known list prices; the agent does NOT include enterprise
// discounts or volume tiers. Cost is purely informational — accurate
// billing requires reconciliation with provider invoices.
type ModelPricing struct {
	InputPer1M  float64
	OutputPer1M float64
	CachedPer1M float64 // Provider-side prompt cache hits; 0 if no caching support.
}

// modelPricing maps a normalized "provider:model-prefix" key to pricing.
// Lookup is by longest-prefix-match: requests for "gpt-4o-2024-05-13" hit
// the "gpt-4o" entry. Add new entries when a customer reports a model
// you don't have pricing for.
//
// Prices reflect public list prices as of late-2025 / early-2026. Treat
// any number here as a best-effort approximation.
var modelPricing = map[string]ModelPricing{
	// OpenAI / Azure OpenAI
	"openai:gpt-4o-mini":            {0.15, 0.60, 0.075},
	"openai:gpt-4o":                 {2.50, 10.00, 1.25},
	"openai:gpt-4-turbo":            {10.00, 30.00, 0},
	"openai:gpt-4":                  {30.00, 60.00, 0},
	"openai:gpt-3.5-turbo":          {0.50, 1.50, 0},
	"openai:o1-mini":                {3.00, 12.00, 1.50},
	"openai:o1":                     {15.00, 60.00, 7.50},
	"openai:o3-mini":                {1.10, 4.40, 0.55},
	"openai:o3":                     {2.00, 8.00, 0.50},
	"openai:gpt-5":                  {2.00, 8.00, 0.50}, // assumed parity with o3 at GA
	"openai:text-embedding-3-small": {0.02, 0, 0},
	"openai:text-embedding-3-large": {0.13, 0, 0},
	"openai:text-embedding-ada-002": {0.10, 0, 0},

	// Anthropic
	"anthropic:claude-3-5-haiku":  {1.00, 5.00, 0.10},
	"anthropic:claude-3-5-sonnet": {3.00, 15.00, 0.30},
	"anthropic:claude-3-haiku":    {0.25, 1.25, 0},
	"anthropic:claude-3-opus":     {15.00, 75.00, 0},
	"anthropic:claude-3-sonnet":   {3.00, 15.00, 0},
	"anthropic:claude-sonnet-4":   {3.00, 15.00, 0.30},
	"anthropic:claude-opus-4":     {15.00, 75.00, 1.50},
	"anthropic:claude-haiku-4":    {1.00, 5.00, 0.10},

	// Google Gemini (1.5 + 2.x + 3.x preview)
	"gcp.gemini:gemini-1.5-flash":    {0.075, 0.30, 0.019},
	"gcp.gemini:gemini-1.5-flash-8b": {0.0375, 0.15, 0.01},
	"gcp.gemini:gemini-1.5-pro":      {1.25, 5.00, 0.31},
	"gcp.gemini:gemini-2.0-flash":    {0.10, 0.40, 0.025},
	"gcp.gemini:gemini-2.5-flash":    {0.10, 0.40, 0.025},
	"gcp.gemini:gemini-2.5-pro":      {1.25, 10.00, 0.31},
	"gcp.gemini:gemini-3-flash":      {0.10, 0.40, 0.025},
	"gcp.gemini:gemini-3.1-pro":      {1.25, 10.00, 0.31},
	"gcp.gemini:text-embedding-004":  {0.025, 0, 0},
	"gcp.gemini:gemini-embedding":    {0.15, 0, 0}, // gemini-embedding-001 and successors

	// AWS Bedrock — Anthropic on Bedrock pricing matches direct
	"aws.bedrock:anthropic.claude-3-5-haiku":  {1.00, 5.00, 0.10},
	"aws.bedrock:anthropic.claude-3-5-sonnet": {3.00, 15.00, 0.30},
	"aws.bedrock:anthropic.claude-3-haiku":    {0.25, 1.25, 0},
	"aws.bedrock:anthropic.claude-3-opus":     {15.00, 75.00, 0},
	"aws.bedrock:anthropic.claude-3-sonnet":   {3.00, 15.00, 0},
	"aws.bedrock:amazon.titan-embed-text":     {0.10, 0, 0},
	"aws.bedrock:amazon.nova-micro":           {0.035, 0.14, 0},
	"aws.bedrock:amazon.nova-lite":            {0.06, 0.24, 0},
	"aws.bedrock:amazon.nova-pro":             {0.80, 3.20, 0},
	"aws.bedrock:meta.llama3-1-70b":           {0.99, 0.99, 0},
	"aws.bedrock:meta.llama3-1-8b":            {0.22, 0.22, 0},
	"aws.bedrock:mistral.mixtral-8x7b":        {0.45, 0.70, 0},
	"aws.bedrock:cohere.command-r":            {0.15, 0.60, 0},
	"aws.bedrock:cohere.command-r-plus":       {2.50, 10.00, 0},

	// Cohere (direct)
	"cohere:command-r":             {0.15, 0.60, 0},
	"cohere:command-r-plus":        {2.50, 10.00, 0},
	"cohere:command-a":             {2.50, 10.00, 0},
	"cohere:embed-english-v3":      {0.10, 0, 0},
	"cohere:embed-multilingual-v3": {0.10, 0, 0},

	// OpenAI-compatible providers (representative; pricing varies by host)
	"openai-compatible:llama-3.1-70b": {0.59, 0.79, 0},
	"openai-compatible:llama-3.3-70b": {0.59, 0.79, 0},
	"openai-compatible:llama-3.1-8b":  {0.05, 0.08, 0},
	"openai-compatible:mixtral-8x7b":  {0.24, 0.24, 0},
	"openai-compatible:deepseek-chat": {0.14, 0.28, 0},
	"openai-compatible:deepseek-r1":   {0.55, 2.19, 0},
	"openai-compatible:mistral-large": {2.00, 6.00, 0},
}

// LookupModelPricing returns pricing by longest-prefix match against
// modelPricing. Returns the matched pricing and ok=false if none matched.
func LookupModelPricing(provider LLMProvider, model string) (ModelPricing, bool) {
	if model == "" {
		return ModelPricing{}, false
	}
	model = strings.ToLower(model)
	prefix := string(provider) + ":"

	var best string
	var bestPricing ModelPricing
	for key, p := range modelPricing {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		modelKey := key[len(prefix):]
		if !strings.HasPrefix(model, modelKey) {
			continue
		}
		if len(modelKey) > len(best) {
			best = modelKey
			bestPricing = p
		}
	}
	return bestPricing, best != ""
}

// CalculateCostUSD returns the cost in USD for a given event's tokens.
// Returns 0 if no pricing entry matches the model — callers should treat
// 0 as "unknown" rather than free.
func CalculateCostUSD(provider LLMProvider, model string, inputTokens, outputTokens, cachedTokens int) float64 {
	p, ok := LookupModelPricing(provider, model)
	if !ok {
		return 0
	}
	// Cached tokens are billed at the cached rate (typically lower); count
	// them separately so we don't double-charge at the input rate.
	billableInput := inputTokens - cachedTokens
	if billableInput < 0 {
		billableInput = 0
	}
	cost := float64(billableInput)*p.InputPer1M/1_000_000 +
		float64(outputTokens)*p.OutputPer1M/1_000_000 +
		float64(cachedTokens)*p.CachedPer1M/1_000_000
	return cost
}

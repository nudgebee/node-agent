package containers

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// LLMProvider represents supported LLM providers
type LLMProvider string

const (
	ProviderOpenAI           LLMProvider = "openai"
	ProviderAnthropic        LLMProvider = "anthropic"
	ProviderGoogle           LLMProvider = "gcp.gemini" // OTel standard name
	ProviderCohere           LLMProvider = "cohere"
	ProviderAWSBedrock       LLMProvider = "aws.bedrock" // OTel standard name
	ProviderAzureOpenAI      LLMProvider = "azure.ai.openai"
	ProviderOpenAICompatible LLMProvider = "openai-compatible"
	ProviderUnknown          LLMProvider = "unknown"
)

// OTel GenAI operation names
const (
	OperationChat           = "chat"
	OperationTextCompletion = "text_completion"
	OperationEmbeddings     = "embeddings"
	OperationGenerate       = "generate_content"
)

// LLMRequest represents parsed LLM request data
type LLMRequest struct {
	Provider    LLMProvider `json:"provider"`
	Model       string      `json:"model"`
	Operation   string      `json:"operation"` // OTel operation name
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
}

// LLMResponse represents parsed LLM response data
type LLMResponse struct {
	Provider         LLMProvider `json:"provider"`
	Model            string      `json:"model"`
	PromptTokens     int         `json:"prompt_tokens"`
	CompletionTokens int         `json:"completion_tokens"`
	TotalTokens      int         `json:"total_tokens"`
}

// LLM provider hostname mappings
var llmProviders = map[string]LLMProvider{
	// OpenAI
	"api.openai.com": ProviderOpenAI,

	// Anthropic
	"api.anthropic.com": ProviderAnthropic,
	"claude.ai":         ProviderAnthropic,

	// Google Gemini
	"generativelanguage.googleapis.com": ProviderGoogle,
	"ai.googleapis.com":                 ProviderGoogle, // Vertex AI
	"aiplatform.googleapis.com":         ProviderGoogle, // Vertex AI Platform

	// Cohere
	"api.cohere.ai":  ProviderCohere,
	"api.cohere.com": ProviderCohere,
}

// AWS Bedrock hostname pattern: bedrock-runtime.<region>.amazonaws.com
var bedrockHostnameRegex = regexp.MustCompile(`^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$`)

// Azure OpenAI hostname pattern: <resource>.openai.azure.com
var azureOpenAIHostnameRegex = regexp.MustCompile(`^[a-z0-9-]+\.openai\.azure\.com$`)

// providerDefaultHost returns the canonical hostname for a provider when the
// actual host is unknown (e.g., detected from payload structure only).
func providerDefaultHost(provider LLMProvider) string {
	switch provider {
	case ProviderOpenAI:
		return "api.openai.com"
	case ProviderAnthropic:
		return "api.anthropic.com"
	case ProviderGoogle:
		return "generativelanguage.googleapis.com"
	case ProviderCohere:
		return "api.cohere.com"
	case ProviderAWSBedrock:
		return "bedrock-runtime.amazonaws.com"
	case ProviderAzureOpenAI:
		return "openai.azure.com"
	default:
		return "unknown"
	}
}

// DetectLLMProvider identifies if a hostname belongs to an LLM provider
func DetectLLMProvider(hostname string) LLMProvider {
	hostname = strings.ToLower(hostname)

	// Strip port if present (e.g., "generativelanguage.googleapis.com:443" -> "generativelanguage.googleapis.com")
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}

	// Direct hostname match
	if provider, exists := llmProviders[hostname]; exists {
		return provider
	}

	// AWS Bedrock pattern: bedrock-runtime.<region>.amazonaws.com
	if bedrockHostnameRegex.MatchString(hostname) {
		return ProviderAWSBedrock
	}

	// Azure OpenAI pattern: <resource>.openai.azure.com
	if azureOpenAIHostnameRegex.MatchString(hostname) {
		return ProviderAzureOpenAI
	}

	// Subdomain matching for cases like "chat.openai.com"
	for host, provider := range llmProviders {
		if strings.HasSuffix(hostname, "."+host) {
			return provider
		}
	}

	return ProviderUnknown
}

// DetectLLMProviderFromPath detects provider from URL path patterns.
// Used for OpenAI-compatible endpoints and fallback detection.
func DetectLLMProviderFromPath(path string) (LLMProvider, string) {
	path = strings.ToLower(path)

	// Google Gemini patterns - extract model from path
	// Pattern: /v1beta/models/gemini-1.5-flash:generateContent
	if strings.Contains(path, "/models/gemini") {
		model := extractGoogleModelFromPath(path)
		return ProviderGoogle, model
	}
	if strings.Contains(path, ":generatecontent") || strings.Contains(path, ":streamgeneratecontent") {
		model := extractGoogleModelFromPath(path)
		return ProviderGoogle, model
	}

	// AWS Bedrock patterns
	// Pattern: /model/<model-id>/converse or /model/<model-id>/invoke
	if strings.Contains(path, "/model/") && (strings.Contains(path, "/converse") || strings.Contains(path, "/invoke")) {
		model := extractBedrockModelFromPath(path)
		return ProviderAWSBedrock, model
	}

	// OpenAI-compatible patterns - match standard endpoints exactly, not sub-paths.
	// This prevents false positives on custom paths like /v1/completions/chat_suggestions.
	if isOpenAICompatiblePath(path) {
		return ProviderOpenAICompatible, ""
	}

	// Anthropic patterns
	if isExactAPIPath(path, "/v1/messages") {
		return ProviderAnthropic, ""
	}

	// Cohere patterns
	if isExactAPIPath(path, "/v1/generate") || isExactAPIPath(path, "/v1/chat") {
		return ProviderCohere, ""
	}

	return ProviderUnknown, ""
}

// extractGoogleModelFromPath extracts model name from Google Gemini API path.
// Pattern: /v1beta/models/gemini-1.5-flash:generateContent
func extractGoogleModelFromPath(path string) string {
	// Look for /models/<model>: pattern
	if idx := strings.Index(path, "/models/"); idx != -1 {
		modelPart := path[idx+8:]
		// Find the end of model name (: or / or end of string)
		endIdx := len(modelPart)
		if colonIdx := strings.Index(modelPart, ":"); colonIdx != -1 && colonIdx < endIdx {
			endIdx = colonIdx
		}
		if slashIdx := strings.Index(modelPart, "/"); slashIdx != -1 && slashIdx < endIdx {
			endIdx = slashIdx
		}
		if endIdx > 0 {
			return modelPart[:endIdx]
		}
	}
	return "gemini" // Default fallback
}

// extractBedrockModelFromPath extracts model ID from AWS Bedrock API path.
// Pattern: /model/anthropic.claude-3-sonnet-20240229-v1:0/converse
// Also handles ARN-based paths: /model/arn%3Aaws%3Abedrock%3A.../converse
func extractBedrockModelFromPath(path string) string {
	if idx := strings.Index(path, "/model/"); idx != -1 {
		modelPart := path[idx+7:]
		if slashIdx := strings.Index(modelPart, "/"); slashIdx != -1 {
			modelPart = modelPart[:slashIdx]
		}
		// URL-decode (ARNs in paths are often percent-encoded)
		if decoded, err := url.PathUnescape(modelPart); err == nil {
			modelPart = decoded
		}
		// Extract friendly name from ARN format:
		// arn:aws:bedrock:region:account:inference-profile/us.meta.llama4-maverick-17b-instruct-v1:0
		if strings.HasPrefix(modelPart, "arn:") {
			if lastSlash := strings.LastIndex(modelPart, "/"); lastSlash != -1 {
				return modelPart[lastSlash+1:]
			}
			// ARN without slash - extract after last colon (resource-id)
			if lastColon := strings.LastIndex(modelPart, ":"); lastColon != -1 {
				return modelPart[lastColon+1:]
			}
		}
		return modelPart
	}
	return ""
}

// isOpenAICompatiblePath checks if the path matches a standard OpenAI API endpoint.
// Uses exact path matching to avoid false positives on sub-paths like
// /v1/completions/chat_suggestions or /v1/completions/conversation-usage-metrics.
func isOpenAICompatiblePath(path string) bool {
	normalized := normalizeAPIPath(path)
	switch normalized {
	case "/v1/chat/completions", "/v1/completions", "/v1/embeddings":
		return true
	}
	return false
}

// isExactAPIPath checks if the path matches a specific API endpoint exactly.
func isExactAPIPath(path, target string) bool {
	normalized := normalizeAPIPath(path)
	return normalized == target
}

// normalizeAPIPath strips query parameters and trailing slashes from a path.
func normalizeAPIPath(path string) string {
	if idx := strings.IndexByte(path, '?'); idx != -1 {
		path = path[:idx]
	}
	return strings.TrimRight(path, "/")
}

// GetOperation determines the OTel GenAI operation name from path.
func GetOperation(path string) string {
	path = strings.ToLower(path)
	normalized := normalizeAPIPath(path)

	// Exact matches for standard endpoints
	switch normalized {
	case "/v1/chat/completions", "/v1/messages", "/v1/chat":
		return OperationChat
	case "/v1/completions":
		return OperationTextCompletion
	case "/v1/embeddings", "/v1/embed":
		return OperationEmbeddings
	}

	// Pattern matches for provider-specific paths
	if strings.Contains(path, "/converse") {
		return OperationChat
	}
	if strings.Contains(path, ":generatecontent") || strings.Contains(path, ":streamgeneratecontent") {
		return OperationGenerate
	}
	if strings.Contains(path, "/model/") && strings.Contains(path, "/invoke") {
		return OperationChat // Bedrock InvokeModel
	}

	return OperationChat // Default to chat
}

// ParseLLMRequest extracts LLM parameters from base64-encoded request payload
func ParseLLMRequest(provider LLMProvider, payloadBase64 string, path string) (*LLMRequest, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, err
	}

	if !utf8.Valid(payloadBytes) {
		return nil, nil
	}

	jsonPayload := extractJSON(string(payloadBytes))
	if jsonPayload == "" {
		return nil, nil
	}

	var req *LLMRequest
	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		req, err = parseOpenAIRequest(jsonPayload)
	case ProviderAnthropic:
		req, err = parseAnthropicRequest(jsonPayload)
	case ProviderGoogle:
		req, err = parseGoogleRequest(jsonPayload)
		// Extract model from path if not in payload
		if req != nil && (req.Model == "" || req.Model == "gemini") {
			if model := extractGoogleModelFromPath(path); model != "" {
				req.Model = model
			}
		}
	case ProviderCohere:
		req, err = parseCohereRequest(jsonPayload)
	case ProviderAWSBedrock:
		req, err = parseBedrockRequest(jsonPayload, path)
	default:
		return nil, nil
	}

	if req != nil {
		req.Operation = GetOperation(path)
	}

	return req, err
}

// ParseLLMResponse extracts token usage from base64-encoded response payload
func ParseLLMResponse(provider LLMProvider, responseBase64 string, path string) (*LLMResponse, error) {
	if responseBase64 == "" {
		return nil, nil
	}

	responseBytes, err := base64.StdEncoding.DecodeString(responseBase64)
	if err != nil {
		return nil, err
	}

	if !utf8.Valid(responseBytes) {
		return nil, nil
	}

	jsonResponse := extractJSON(string(responseBytes))
	if jsonResponse == "" {
		return nil, nil
	}

	switch provider {
	case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzureOpenAI:
		return parseOpenAIResponse(jsonResponse)
	case ProviderAnthropic:
		return parseAnthropicResponse(jsonResponse)
	case ProviderGoogle:
		resp, err := parseGoogleResponse(jsonResponse)
		// Extract model from path if not in response
		if resp != nil && (resp.Model == "" || resp.Model == "gemini") {
			if model := extractGoogleModelFromPath(path); model != "" {
				resp.Model = model
			}
		}
		return resp, err
	case ProviderCohere:
		return parseCohereResponse(jsonResponse)
	case ProviderAWSBedrock:
		return parseBedrockResponse(jsonResponse, path)
	default:
		return nil, nil
	}
}

// extractJSON finds and extracts JSON object from HTTP payload
func extractJSON(payload string) string {
	// Find first { character
	jsonStart := strings.Index(payload, "{")
	if jsonStart == -1 {
		return ""
	}
	return payload[jsonStart:]
}

// --- Provider-specific parsers ---

// OpenAI request parsing
func parseOpenAIRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		Model       string  `json:"model"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		return nil, err
	}

	return &LLMRequest{
		Provider:    ProviderOpenAI,
		Model:       req.Model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}, nil
}

// OpenAI response parsing
func parseOpenAIResponse(jsonResponse string) (*LLMResponse, error) {
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &resp); err != nil {
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderOpenAI,
		Model:            resp.Model,
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		TotalTokens:      resp.Usage.TotalTokens,
	}, nil
}

// Anthropic request parsing
func parseAnthropicRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		Model       string  `json:"model"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		return nil, err
	}

	return &LLMRequest{
		Provider:    ProviderAnthropic,
		Model:       req.Model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}, nil
}

// Anthropic response parsing
func parseAnthropicResponse(jsonResponse string) (*LLMResponse, error) {
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &resp); err != nil {
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderAnthropic,
		Model:            resp.Model,
		PromptTokens:     resp.Usage.InputTokens,
		CompletionTokens: resp.Usage.OutputTokens,
		TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
	}, nil
}

// Google Gemini request parsing
func parseGoogleRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		GenerationConfig struct {
			MaxOutputTokens int     `json:"maxOutputTokens"`
			Temperature     float64 `json:"temperature"`
		} `json:"generationConfig"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		return nil, err
	}

	return &LLMRequest{
		Provider:    ProviderGoogle,
		Model:       "", // Will be extracted from path
		MaxTokens:   req.GenerationConfig.MaxOutputTokens,
		Temperature: req.GenerationConfig.Temperature,
	}, nil
}

// Google Gemini response parsing
func parseGoogleResponse(jsonResponse string) (*LLMResponse, error) {
	var resp struct {
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
		ModelVersion string `json:"modelVersion"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &resp); err != nil {
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderGoogle,
		Model:            resp.ModelVersion, // May be empty, path extraction will fill it
		PromptTokens:     resp.UsageMetadata.PromptTokenCount,
		CompletionTokens: resp.UsageMetadata.CandidatesTokenCount,
		TotalTokens:      resp.UsageMetadata.TotalTokenCount,
	}, nil
}

// Cohere request parsing
func parseCohereRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		Model       string  `json:"model"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		return nil, err
	}

	return &LLMRequest{
		Provider:    ProviderCohere,
		Model:       req.Model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}, nil
}

// Cohere response parsing
func parseCohereResponse(jsonResponse string) (*LLMResponse, error) {
	var resp struct {
		Meta struct {
			Tokens struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"tokens"`
		} `json:"meta"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &resp); err != nil {
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderCohere,
		Model:            "cohere",
		PromptTokens:     resp.Meta.Tokens.InputTokens,
		CompletionTokens: resp.Meta.Tokens.OutputTokens,
		TotalTokens:      resp.Meta.Tokens.InputTokens + resp.Meta.Tokens.OutputTokens,
	}, nil
}

// AWS Bedrock request parsing
// Supports both Converse API and InvokeModel API
func parseBedrockRequest(jsonPayload string, path string) (*LLMRequest, error) {
	// Try Converse API format first
	var converseReq struct {
		InferenceConfig struct {
			MaxTokens   int     `json:"maxTokens"`
			Temperature float64 `json:"temperature"`
		} `json:"inferenceConfig"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &converseReq); err == nil && converseReq.InferenceConfig.MaxTokens > 0 {
		return &LLMRequest{
			Provider:    ProviderAWSBedrock,
			Model:       extractBedrockModelFromPath(path),
			MaxTokens:   converseReq.InferenceConfig.MaxTokens,
			Temperature: converseReq.InferenceConfig.Temperature,
		}, nil
	}

	// Try InvokeModel format (Anthropic on Bedrock)
	var invokeReq struct {
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
		// Also check anthropic_version for Claude models
		AnthropicVersion string `json:"anthropic_version"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &invokeReq); err == nil {
		return &LLMRequest{
			Provider:    ProviderAWSBedrock,
			Model:       extractBedrockModelFromPath(path),
			MaxTokens:   invokeReq.MaxTokens,
			Temperature: invokeReq.Temperature,
		}, nil
	}

	// Fallback - return with model from path
	return &LLMRequest{
		Provider: ProviderAWSBedrock,
		Model:    extractBedrockModelFromPath(path),
	}, nil
}

// AWS Bedrock response parsing
func parseBedrockResponse(jsonResponse string, path string) (*LLMResponse, error) {
	// Try Converse API format
	var converseResp struct {
		Usage struct {
			InputTokens  int `json:"inputTokens"`
			OutputTokens int `json:"outputTokens"`
			TotalTokens  int `json:"totalTokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &converseResp); err == nil && converseResp.Usage.TotalTokens > 0 {
		return &LLMResponse{
			Provider:         ProviderAWSBedrock,
			Model:            extractBedrockModelFromPath(path),
			PromptTokens:     converseResp.Usage.InputTokens,
			CompletionTokens: converseResp.Usage.OutputTokens,
			TotalTokens:      converseResp.Usage.TotalTokens,
		}, nil
	}

	// Try InvokeModel format (Anthropic on Bedrock)
	var invokeResp struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &invokeResp); err == nil {
		total := invokeResp.Usage.InputTokens + invokeResp.Usage.OutputTokens
		if total > 0 {
			return &LLMResponse{
				Provider:         ProviderAWSBedrock,
				Model:            extractBedrockModelFromPath(path),
				PromptTokens:     invokeResp.Usage.InputTokens,
				CompletionTokens: invokeResp.Usage.OutputTokens,
				TotalTokens:      total,
			}, nil
		}
	}

	return nil, nil
}

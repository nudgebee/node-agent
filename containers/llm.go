package containers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"
)

// LLMProvider represents supported LLM providers
type LLMProvider string

const (
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderGoogle    LLMProvider = "google"
	ProviderCohere    LLMProvider = "cohere"
	ProviderUnknown   LLMProvider = "unknown"
)

// LLMRequest represents parsed LLM request data
type LLMRequest struct {
	Provider    LLMProvider `json:"provider"`
	Model       string      `json:"model"`
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
	"api.openai.com":                    ProviderOpenAI,
	"api.anthropic.com":                 ProviderAnthropic,
	"generativelanguage.googleapis.com": ProviderGoogle,
	"ai.googleapis.com":                 ProviderGoogle, // Vertex AI
	"aiplatform.googleapis.com":         ProviderGoogle, // Vertex AI Platform
	"api.cohere.ai":                     ProviderCohere,
	"api.cohere.com":                    ProviderCohere,
	"claude.ai":                         ProviderAnthropic, // Claude web interface
}

// DetectLLMProvider identifies if a hostname belongs to an LLM provider
func DetectLLMProvider(hostname string) LLMProvider {
	// Direct hostname match
	if provider, exists := llmProviders[hostname]; exists {
		return provider
	}

	// Subdomain matching for cases like "chat.openai.com"
	for host, provider := range llmProviders {
		if strings.HasSuffix(hostname, "."+host) || strings.HasSuffix(hostname, host) {
			return provider
		}
	}

	return ProviderUnknown
}

// ParseLLMRequest extracts LLM parameters from base64-encoded request payload
func ParseLLMRequest(provider LLMProvider, payloadBase64 string) (*LLMRequest, error) {
	// Decode base64 payload
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, err
	}

	// Find JSON body in HTTP request or HTTP/2 frame
	// Validate payload contains valid UTF-8 before processing
	if !utf8.Valid(payloadBytes) {
		return nil, fmt.Errorf("payload contains invalid UTF-8 data")
	}
	payloadStr := string(payloadBytes)
	jsonStart := strings.Index(payloadStr, "{")
	if jsonStart == -1 {
		// For HTTP/2, the payload might be the JSON directly
		if strings.HasPrefix(strings.TrimSpace(payloadStr), "{") {
			jsonStart = strings.Index(strings.TrimSpace(payloadStr), "{")
			jsonStart += len(payloadStr) - len(strings.TrimSpace(payloadStr))
		} else {
			return nil, nil // No JSON found
		}
	}

	jsonPayload := payloadStr[jsonStart:]

	// Parse based on provider
	switch provider {
	case ProviderOpenAI:
		return parseOpenAIRequest(jsonPayload)
	case ProviderAnthropic:
		return parseAnthropicRequest(jsonPayload)
	case ProviderGoogle:
		return parseGoogleRequest(jsonPayload)
	case ProviderCohere:
		return parseCohereRequest(jsonPayload)
	default:
		return nil, nil
	}
}

// ParseLLMResponse extracts token usage from base64-encoded response payload
func ParseLLMResponse(provider LLMProvider, responseBase64 string) (*LLMResponse, error) {
	if responseBase64 == "" {
		return nil, nil
	}

	// Decode base64 response
	responseBytes, err := base64.StdEncoding.DecodeString(responseBase64)
	if err != nil {
		return nil, err
	}

	// Find JSON in HTTP response or HTTP/2 frame
	// Validate response contains valid UTF-8 before processing
	if !utf8.Valid(responseBytes) {
		return nil, fmt.Errorf("response contains invalid UTF-8 data")
	}
	responseStr := string(responseBytes)
	jsonStart := strings.Index(responseStr, "{")
	if jsonStart == -1 {
		// For HTTP/2, the response might be the JSON directly
		if strings.HasPrefix(strings.TrimSpace(responseStr), "{") {
			jsonStart = strings.Index(strings.TrimSpace(responseStr), "{")
			jsonStart += len(responseStr) - len(strings.TrimSpace(responseStr))
		} else {
			return nil, nil // No JSON found
		}
	}

	jsonResponse := responseStr[jsonStart:]

	// Parse based on provider
	switch provider {
	case ProviderOpenAI:
		return parseOpenAIResponse(jsonResponse)
	case ProviderAnthropic:
		return parseAnthropicResponse(jsonResponse)
	case ProviderGoogle:
		return parseGoogleResponse(jsonResponse)
	case ProviderCohere:
		return parseCohereResponse(jsonResponse)
	default:
		return nil, nil
	}
}

// OpenAI request parsing
func parseOpenAIRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		Model       string  `json:"model"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		log.Printf("Failed to parse OpenAI request: %v", err)
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
		log.Printf("Failed to parse OpenAI response: %v", err)
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
		log.Printf("Failed to parse Anthropic request: %v", err)
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
		log.Printf("Failed to parse Anthropic response: %v", err)
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

// Google request parsing (Gemini API)
func parseGoogleRequest(jsonPayload string) (*LLMRequest, error) {
	var req struct {
		GenerationConfig struct {
			MaxOutputTokens int     `json:"maxOutputTokens"`
			Temperature     float64 `json:"temperature"`
		} `json:"generationConfig"`
	}

	if err := json.Unmarshal([]byte(jsonPayload), &req); err != nil {
		log.Printf("Failed to parse Google request: %v", err)
		return nil, err
	}

	// Extract model from URL path if available
	model := "gemini" // Default

	return &LLMRequest{
		Provider:    ProviderGoogle,
		Model:       model,
		MaxTokens:   req.GenerationConfig.MaxOutputTokens,
		Temperature: req.GenerationConfig.Temperature,
	}, nil
}

// Google response parsing (Gemini API)
func parseGoogleResponse(jsonResponse string) (*LLMResponse, error) {
	var resp struct {
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}

	if err := json.Unmarshal([]byte(jsonResponse), &resp); err != nil {
		log.Printf("Failed to parse Google response: %v", err)
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderGoogle,
		Model:            "gemini",
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
		log.Printf("Failed to parse Cohere request: %v", err)
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
		log.Printf("Failed to parse Cohere response: %v", err)
		return nil, err
	}

	return &LLMResponse{
		Provider:         ProviderCohere,
		Model:            "cohere", // Default
		PromptTokens:     resp.Meta.Tokens.InputTokens,
		CompletionTokens: resp.Meta.Tokens.OutputTokens,
		TotalTokens:      resp.Meta.Tokens.InputTokens + resp.Meta.Tokens.OutputTokens,
	}, nil
}

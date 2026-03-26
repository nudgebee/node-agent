package containers

import (
	"net"
	"regexp"
	"strings"
)

// LLMProvider represents supported LLM providers.
type LLMProvider string

const (
	ProviderOpenAI           LLMProvider = "openai"
	ProviderAnthropic        LLMProvider = "anthropic"
	ProviderGoogle           LLMProvider = "gcp.gemini"
	ProviderCohere           LLMProvider = "cohere"
	ProviderAWSBedrock       LLMProvider = "aws.bedrock"
	ProviderAzureOpenAI      LLMProvider = "azure.ai.openai"
	ProviderOpenAICompatible LLMProvider = "openai-compatible"
	ProviderUnknown          LLMProvider = "unknown"
)

// OTel GenAI operation names.
const (
	OperationChat           = "chat"
	OperationTextCompletion = "text_completion"
	OperationEmbeddings     = "embeddings"
	OperationGenerate       = "generate_content"
)

// LLM provider hostname mappings.
var llmProviders = map[string]LLMProvider{
	"api.openai.com":                    ProviderOpenAI,
	"api.anthropic.com":                 ProviderAnthropic,
	"claude.ai":                         ProviderAnthropic,
	"generativelanguage.googleapis.com": ProviderGoogle,
	"ai.googleapis.com":                 ProviderGoogle,
	"aiplatform.googleapis.com":         ProviderGoogle,
	"api.cohere.ai":                     ProviderCohere,
	"api.cohere.com":                    ProviderCohere,
}

var bedrockHostnameRegex = regexp.MustCompile(`^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$`)
var azureOpenAIHostnameRegex = regexp.MustCompile(`^[a-z0-9-]+\.openai\.azure\.com$`)

// DetectLLMProvider identifies if a hostname belongs to an LLM provider.
func DetectLLMProvider(hostname string) LLMProvider {
	hostname = strings.ToLower(hostname)

	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}

	if provider, exists := llmProviders[hostname]; exists {
		return provider
	}

	if bedrockHostnameRegex.MatchString(hostname) {
		return ProviderAWSBedrock
	}
	if azureOpenAIHostnameRegex.MatchString(hostname) {
		return ProviderAzureOpenAI
	}

	// Subdomain matching (e.g., "chat.openai.com")
	for host, provider := range llmProviders {
		if strings.HasSuffix(hostname, "."+host) {
			return provider
		}
	}

	return ProviderUnknown
}

// DetectLLMProviderFromPath detects provider from URL path patterns.
// Used as fallback when hostname-based detection fails.
func DetectLLMProviderFromPath(path string) (LLMProvider, string) {
	path = strings.ToLower(path)

	if strings.Contains(path, "/models/gemini") {
		return ProviderGoogle, modelFromPath(ProviderGoogle, path)
	}
	if strings.Contains(path, ":generatecontent") || strings.Contains(path, ":streamgeneratecontent") {
		return ProviderGoogle, modelFromPath(ProviderGoogle, path)
	}

	if strings.Contains(path, "/model/") && (strings.Contains(path, "/converse") || strings.Contains(path, "/invoke")) {
		return ProviderAWSBedrock, modelFromPath(ProviderAWSBedrock, path)
	}

	if isOpenAICompatiblePath(path) {
		return ProviderOpenAICompatible, ""
	}

	if isExactAPIPath(path, "/v1/messages") {
		return ProviderAnthropic, ""
	}

	if isExactAPIPath(path, "/v1/generate") || isExactAPIPath(path, "/v1/chat") {
		return ProviderCohere, ""
	}

	return ProviderUnknown, ""
}

// GetOperation determines the OTel GenAI operation name from path.
func GetOperation(path string) string {
	path = strings.ToLower(path)
	normalized := normalizeAPIPath(path)

	switch normalized {
	case "/v1/chat/completions", "/v1/messages", "/v1/chat":
		return OperationChat
	case "/v1/completions":
		return OperationTextCompletion
	case "/v1/embeddings", "/v1/embed":
		return OperationEmbeddings
	}

	if strings.Contains(path, "/converse") {
		return OperationChat
	}
	if strings.Contains(path, ":generatecontent") || strings.Contains(path, ":streamgeneratecontent") {
		return OperationGenerate
	}
	if strings.Contains(path, "/model/") && strings.Contains(path, "/invoke") {
		return OperationChat
	}

	return OperationChat
}

// isLLMRelevantHost returns true if the host matches a known LLM provider.
// Used by the HTTP/2 parser for late-tag fallback detection.
func isLLMRelevantHost(host string) bool {
	return DetectLLMProvider(host) != ProviderUnknown
}

// providerDefaultHost returns the canonical hostname for a provider.
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

// --- Path helpers ---

func isOpenAICompatiblePath(path string) bool {
	normalized := normalizeAPIPath(path)
	switch normalized {
	case "/v1/chat/completions", "/v1/completions", "/v1/embeddings":
		return true
	}
	return false
}

func isExactAPIPath(path, target string) bool {
	return normalizeAPIPath(path) == target
}

func normalizeAPIPath(path string) string {
	if idx := strings.IndexByte(path, '?'); idx != -1 {
		path = path[:idx]
	}
	return strings.TrimRight(path, "/")
}

// checkSSECompletion checks if data contains SSE stream completion markers.
func checkSSECompletion(data []byte) (bool, string) {
	// OpenAI/Azure
	if containsBytes(data, "data: [DONE]") {
		return true, "done_marker"
	}
	// Gemini
	if containsBytes(data, `"finishReason"`) {
		return true, "finish_reason"
	}
	// Anthropic
	if containsBytes(data, `"finish_reason"`) {
		return true, "finish_reason"
	}
	if containsBytes(data, `"type":"message_stop"`) || containsBytes(data, `"type": "message_stop"`) {
		return true, "message_stop"
	}
	if containsBytes(data, `"type":"message_delta"`) && containsBytes(data, `"stop_reason"`) {
		return true, "stop_reason"
	}
	return false, ""
}

func containsBytes(data []byte, s string) bool {
	return strings.Contains(string(data), s)
}

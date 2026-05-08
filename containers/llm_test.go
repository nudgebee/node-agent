package containers

import "testing"

func TestDetectLLMProvider(t *testing.T) {
	cases := []struct {
		host string
		want LLMProvider
	}{
		// Exact matches
		{"api.openai.com", ProviderOpenAI},
		{"api.anthropic.com", ProviderAnthropic},
		{"claude.ai", ProviderAnthropic},
		{"generativelanguage.googleapis.com", ProviderGoogle},
		{"ai.googleapis.com", ProviderGoogle},
		{"aiplatform.googleapis.com", ProviderGoogle},
		{"api.cohere.com", ProviderCohere},
		{"api.cohere.ai", ProviderCohere},

		// Bedrock regional (regex)
		{"bedrock-runtime.us-west-2.amazonaws.com", ProviderAWSBedrock},
		{"bedrock-runtime.eu-central-1.amazonaws.com", ProviderAWSBedrock},

		// Azure OpenAI (regex)
		{"my-resource.openai.azure.com", ProviderAzureOpenAI},

		// Vertex AI regional (regex) — ensures task #6 stays fixed
		{"us-central1-aiplatform.googleapis.com", ProviderGoogle},
		{"europe-west4-aiplatform.googleapis.com", ProviderGoogle},
		{"asia-southeast1-aiplatform.googleapis.com", ProviderGoogle},

		// OpenAI-compatible providers (task #7)
		{"api.groq.com", ProviderOpenAICompatible},
		{"api.together.xyz", ProviderOpenAICompatible},
		{"api.fireworks.ai", ProviderOpenAICompatible},
		{"api.deepseek.com", ProviderOpenAICompatible},
		{"api.mistral.ai", ProviderOpenAICompatible},
		{"api.perplexity.ai", ProviderOpenAICompatible},

		// Subdomains of known LLM hosts should match
		{"v1.api.openai.com", ProviderOpenAI},

		// False-positive guards — these must NOT match an LLM provider
		{"chat.googleapis.com", ProviderUnknown},                    // Google Chat, not LLM
		{"compute.googleapis.com", ProviderUnknown},                 // GCE
		{"storage.googleapis.com", ProviderUnknown},                 // GCS
		{"openaipublic.blob.core.windows.net", ProviderUnknown},     // OpenAI tokenizer CDN, not API
		{"discovery.openai.com", ProviderUnknown},                   // not a known LLM endpoint pattern
		{"foo.bar.baz", ProviderUnknown},
		{"", ProviderUnknown},

		// Case-insensitivity
		{"API.OPENAI.COM", ProviderOpenAI},

		// Host:port form
		{"api.openai.com:443", ProviderOpenAI},
		{"us-central1-aiplatform.googleapis.com:443", ProviderGoogle},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			got := DetectLLMProvider(c.host)
			if got != c.want {
				t.Fatalf("DetectLLMProvider(%q) = %q, want %q", c.host, got, c.want)
			}
		})
	}
}

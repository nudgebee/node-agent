package llm

import "testing"

func TestClassifyPath(t *testing.T) {
	for _, tc := range []struct {
		path      string
		ok        bool
		family    family
		operation Operation
		model     string
		streaming bool
	}{
		{"/v1beta/models/gemini-x-flash:streamGenerateContent?alt=sse", true, familyGemini, OperationGenerate, "gemini-x-flash", true},
		{"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-x-pro:generateContent", true, familyGemini, OperationGenerate, "gemini-x-pro", false},
		{"/v1beta/models/text-embedding-x:batchEmbedContents", true, familyGemini, OperationEmbeddings, "text-embedding-x", false},
		{"/v1beta/models/gemini-x-flash:countTokens", false, 0, "", "", false},
		{"/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123%3Ainference-profile%2Fus.meta.llama-x/converse", true, familyBedrock, OperationChat, "us.meta.llama-x", false},
		{"/model/cohere.embed-english-v3/invoke", true, familyBedrock, OperationEmbeddings, "cohere.embed-english-v3", false},
		{"/model/anthropic.claude-x/invoke-with-response-stream", true, familyBedrock, OperationChat, "anthropic.claude-x", true},
		{"/v1/chat/completions", true, familyOpenAI, OperationChat, "", false},
		{"/openai/deployments/prod-gpt/chat/completions?api-version=2024-10-21", true, familyOpenAI, OperationChat, "", false},
		{"/openai/deployments/prod-embed/embeddings?api-version=2024-10-21", true, familyOpenAI, OperationEmbeddings, "", false},
		{"/v1/responses", true, familyOpenAI, OperationChat, "", false},
		{"/v1/completions", true, familyOpenAI, OperationTextCompletion, "", false},
		{"/gateway/v1/embeddings", true, familyOpenAI, OperationEmbeddings, "", false},
		{"/v1/messages", true, familyAnthropic, OperationChat, "", false},
		{"/v2/chat", true, familyCohere, OperationChat, "", false},
		{"/v1/models", false, 0, "", "", false},
		{"/healthz", false, 0, "", "", false},
	} {
		r, ok := classifyPath(tc.path)
		if ok != tc.ok || r.family != tc.family || r.operation != tc.operation || r.model != tc.model || r.streaming != tc.streaming {
			t.Errorf("%s: got ok=%v %+v", tc.path, ok, r)
		}
	}
}

func TestProviderForHost(t *testing.T) {
	for host, want := range map[string]Provider{
		"api.openai.com:443":                      ProviderOpenAI,
		"bedrock-runtime.eu-west-1.amazonaws.com": ProviderBedrock,
		"europe-west4-aiplatform.googleapis.com":  ProviderVertexAI,
		"my-resource.openai.azure.com":            ProviderAzure,
		"generativelanguage.googleapis.com":       ProviderGemini,
		"storage.googleapis.com":                  "",
		"example.com":                             "",
	} {
		got, _ := ProviderForHost(host)
		if got != want {
			t.Errorf("%s: got %q, want %q", host, got, want)
		}
	}
}

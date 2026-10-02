// Package llm turns the plaintext byte streams of LLM API connections into
// per-request usage records. It is fed by the kernel's LLM capture channel and
// has no dependency on eBPF, so it is tested by replaying real client traffic.
package llm

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Provider is the OTel GenAI gen_ai.provider.name of an endpoint.
type Provider string

const (
	ProviderOpenAI     Provider = "openai"
	ProviderAzure      Provider = "azure.ai.openai"
	ProviderAnthropic  Provider = "anthropic"
	ProviderGemini     Provider = "gcp.gemini"
	ProviderVertexAI   Provider = "gcp.vertex_ai"
	ProviderBedrock    Provider = "aws.bedrock"
	ProviderCohere     Provider = "cohere"
	ProviderDeepSeek   Provider = "deepseek"
	ProviderGroq       Provider = "groq"
	ProviderMistral    Provider = "mistral_ai"
	ProviderPerplexity Provider = "perplexity"
	ProviderXAI        Provider = "x_ai"
	// ProviderCompatible is an endpoint that speaks a provider's wire format
	// without being one: a self-hosted model server or an LLM gateway.
	ProviderCompatible Provider = "openai_compatible"
)

// Operation is the OTel GenAI gen_ai.operation.name.
type Operation string

const (
	OperationChat           Operation = "chat"
	OperationTextCompletion Operation = "text_completion"
	OperationEmbeddings     Operation = "embeddings"
	OperationGenerate       Operation = "generate_content"
)

// family is the wire format of a request, which decides how usage is read.
type family uint8

const (
	familyUnknown family = iota
	familyOpenAI
	familyAnthropic
	familyGemini
	familyBedrock
	familyCohere
)

var hostProviders = map[string]Provider{
	"api.openai.com":                    ProviderOpenAI,
	"api.anthropic.com":                 ProviderAnthropic,
	"generativelanguage.googleapis.com": ProviderGemini,
	"aiplatform.googleapis.com":         ProviderVertexAI,
	"api.cohere.ai":                     ProviderCohere,
	"api.cohere.com":                    ProviderCohere,
	"api.deepseek.com":                  ProviderDeepSeek,
	"api.groq.com":                      ProviderGroq,
	"api.mistral.ai":                    ProviderMistral,
	"api.perplexity.ai":                 ProviderPerplexity,
	"api.x.ai":                          ProviderXAI,
	"api.together.xyz":                  ProviderCompatible,
	"api.fireworks.ai":                  ProviderCompatible,
}

var (
	reBedrockHost = regexp.MustCompile(`^bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com$`)
	reAzureHost   = regexp.MustCompile(`^[a-z0-9-]+\.(openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$`)
	reVertexHost  = regexp.MustCompile(`^[a-z0-9-]+-aiplatform\.googleapis\.com$`)
)

// ProviderForHost identifies a public LLM API by hostname, as seen in TLS SNI,
// an HTTP Host header or an HTTP/2 :authority. ok is false for anything else.
func ProviderForHost(host string) (p Provider, ok bool) {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if p, ok := hostProviders[host]; ok {
		return p, true
	}
	switch {
	case reBedrockHost.MatchString(host):
		return ProviderBedrock, true
	case reAzureHost.MatchString(host):
		return ProviderAzure, true
	case reVertexHost.MatchString(host):
		return ProviderVertexAI, true
	}
	return "", false
}

// route is what a request path says about an LLM call.
type route struct {
	family    family
	operation Operation
	model     string // only for APIs that put the model in the path
	streaming bool   // the path itself selects a streaming response
}

// classifyPath recognises the LLM API paths of every supported wire format.
// It is how gateways and self-hosted servers, which have no recognisable
// hostname, are detected. ok is false for non-LLM paths.
func classifyPath(rawPath string) (r route, ok bool) {
	path := rawPath
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimRight(path, "/")
	lower := strings.ToLower(path)

	// Gemini and Vertex AI: .../models/{model}:{method}
	if i := strings.LastIndex(lower, "/models/"); i >= 0 {
		if j := strings.LastIndexByte(lower, ':'); j > i {
			model, method := path[i+len("/models/"):j], lower[j+1:]
			switch method {
			case "generatecontent":
				return route{family: familyGemini, operation: OperationGenerate, model: model}, true
			case "streamgeneratecontent":
				return route{family: familyGemini, operation: OperationGenerate, model: model, streaming: true}, true
			case "embedcontent", "batchembedcontents", "predict":
				return route{family: familyGemini, operation: OperationEmbeddings, model: model}, true
			}
		}
	}

	// Bedrock runtime: /model/{modelId}/{invoke|invoke-with-response-stream|converse|converse-stream}
	if strings.HasPrefix(lower, "/model/") {
		rest := path[len("/model/"):]
		if j := strings.LastIndexByte(rest, '/'); j > 0 {
			model, action := bedrockModel(rest[:j]), strings.ToLower(rest[j+1:])
			r := route{family: familyBedrock, operation: OperationChat, model: model}
			if strings.Contains(strings.ToLower(model), "embed") {
				r.operation = OperationEmbeddings
			}
			switch action {
			case "converse", "invoke":
				return r, true
			case "converse-stream", "invoke-with-response-stream":
				r.streaming = true
				return r, true
			}
		}
	}

	// OpenAI and everything compatible with it, including Azure's
	// /openai/deployments/{name}/... and gateways mounting it under a prefix.
	switch {
	case strings.HasSuffix(lower, "/chat/completions"):
		return route{family: familyOpenAI, operation: OperationChat}, true
	case strings.HasSuffix(lower, "/v1/responses") || strings.HasSuffix(lower, "/openai/responses"):
		return route{family: familyOpenAI, operation: OperationChat}, true
	case strings.HasSuffix(lower, "/v1/completions") || strings.HasSuffix(lower, "/completions") && strings.Contains(lower, "/deployments/"):
		return route{family: familyOpenAI, operation: OperationTextCompletion}, true
	case strings.HasSuffix(lower, "/embeddings"):
		return route{family: familyOpenAI, operation: OperationEmbeddings}, true
	case strings.HasSuffix(lower, "/v1/messages"):
		return route{family: familyAnthropic, operation: OperationChat}, true
	case lower == "/v2/chat" || lower == "/v1/chat":
		return route{family: familyCohere, operation: OperationChat}, true
	case lower == "/v2/embed" || lower == "/v1/embed":
		return route{family: familyCohere, operation: OperationEmbeddings}, true
	}
	return route{}, false
}

// IsAPIPath reports whether a request path is an LLM API call in any of the
// supported wire formats.
func IsAPIPath(path string) bool {
	_, ok := classifyPath(path)
	return ok
}

// bedrockModel turns the modelId path segment into a model name. It may be
// percent-encoded, and may be the ARN of an inference profile or a
// provisioned model, whose last segment is the name.
func bedrockModel(segment string) string {
	if s, err := url.PathUnescape(segment); err == nil {
		segment = s
	}
	if strings.HasPrefix(segment, "arn:") {
		if i := strings.LastIndexByte(segment, '/'); i >= 0 {
			return segment[i+1:]
		}
	}
	return segment
}

// RequestPathAndHost reads the target and Host header of an HTTP/1.x
// request from the start of its bytes.
func RequestPathAndHost(b []byte) (path, host string) {
	end := bytes.Index(b, []byte("\r\n"))
	if end < 0 {
		return "", ""
	}
	parts := bytes.SplitN(b[:end], []byte(" "), 3)
	if len(parts) != 3 {
		return "", ""
	}
	path = string(parts[1])
	for _, line := range bytes.Split(b[end+2:], []byte("\r\n")) {
		if len(line) == 0 {
			break
		}
		if k, v, ok := bytes.Cut(line, []byte(":")); ok && strings.EqualFold(string(k), "host") {
			host = strings.TrimSpace(string(v))
			break
		}
	}
	return path, host
}

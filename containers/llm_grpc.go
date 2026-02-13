package containers

import (
	"strings"
)

// ExtractGRPCServiceMethod attempts to extract the service/method from gRPC path.
// gRPC paths follow format: /<package>.<Service>/<Method>
// For Gemini: /google.ai.generativelanguage.v1beta.GenerativeService/GenerateContent
func ExtractGRPCServiceMethod(path string) (service, method string) {
	if len(path) < 2 || path[0] != '/' {
		return "", ""
	}

	// Find the last /
	lastSlash := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			lastSlash = i
			break
		}
	}

	if lastSlash <= 0 {
		return "", ""
	}

	service = path[1:lastSlash]
	method = path[lastSlash+1:]
	return service, method
}

// IsGeminiGRPCService checks if the gRPC service is Google Gemini.
func IsGeminiGRPCService(service string) bool {
	// Match patterns like:
	// google.ai.generativelanguage.v1beta.GenerativeService
	// google.ai.generativelanguage.v1.GenerativeService
	return len(service) > 0 &&
		(strings.Contains(service, "generativelanguage") ||
			strings.Contains(service, "GenerativeService"))
}

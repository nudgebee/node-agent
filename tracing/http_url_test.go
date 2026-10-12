package tracing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Spans carry the normalized URL in http.url / http.path, which trace backends
// group on, and the exact request URL in url.full.
func TestHTTPURLAttributes(t *testing.T) {
	attrs := httpURLAttributes("https", "api.example.com",
		"/orgs/42/message?sessionId=123e4567-e89b-12d3-a456-426614174000&status=Busy")

	got := map[string]string{}
	for _, a := range attrs {
		got[string(a.Key)] = a.Value.AsString()
	}
	assert.Equal(t, "https://api.example.com/orgs/{id}/message", got["http.url"])
	assert.Equal(t, "/orgs/{id}/message", got["http.path"])
	assert.Equal(t, "https://api.example.com/orgs/42/message?sessionId=123e4567-e89b-12d3-a456-426614174000&status=Busy", got["url.full"])
}

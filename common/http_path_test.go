package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeHTTPPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"root", "/", "/"},
		{"static path unchanged", "/healthz", "/healthz"},
		{"short version segment unchanged", "/api/v1/items", "/api/v1/items"},
		{"query string dropped", "/static/app.js?v=3", "/static/app.js"},
		{"long-poll session id in query", "/message?sessionId=123e4567-e89b-12d3-a456-426614174000&status=Online", "/message"},
		{"numeric segment", "/121/renewjob", "/{id}/renewjob"},
		{"uuid segment", "/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{uuid}"},
		{"hex segment", "/commits/9fceb02d0ae598e95dc970b74767f19372d61af8", "/commits/{hex}"},
		{"long mixed alphanumeric segment", "/token/zzzz1zzzzz", "/token/{id}"},
		{"several id segments", "/orgs/42/repos/7/issues", "/orgs/{id}/repos/{id}/issues"},
		// The patterns are not anchored, so a UUID inside a longer segment still
		// templates it. Gating the UUID check on len(p) == 36 would change this.
		{"uuid inside a longer segment", "/orders/order-550e8400-e29b-41d4-a716-446655440000", "/orders/{uuid}"},
		// Numbers past int range fail strconv.Atoi and fall through to the hex
		// rule. Still templated; kept as is so existing metric series keep
		// their label values.
		{"numeric segment beyond int range", "/123456789012345678901234567890/jobs", "/{hex}/jobs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeHTTPPath(tt.in))
		})
	}
}

package logs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
)

func attrMap(attrs []attribute.KeyValue) map[string][]string {
	m := map[string][]string{}
	for _, a := range attrs {
		m[string(a.Key)] = append(m[string(a.Key)], a.Value.AsString())
	}
	return m
}

func TestLogRecordAttrs(t *testing.T) {
	// a JSON field named like the agent's attribute neither duplicates nor replaces it
	attrs, _, _ := logRecordAttrs("1234", map[string]string{"pattern.hash": "spoofed", "user": "alice"})
	assert.Equal(t, map[string][]string{"pattern.hash": {"1234"}, "user": {"alice"}}, attrMap(attrs))

	// hex trace context
	attrs, traceId, spanId := logRecordAttrs("1", map[string]string{
		"trace_id": "4BF92F3577B34DA6A3CE929D0E0E4736",
		"span_id":  "00f067aa0ba902b7",
	})
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", traceId.String())
	assert.Equal(t, "00f067aa0ba902b7", spanId.String())
	assert.Len(t, attrs, 1)

	// Datadog writes span ids in decimal: 16 digits must not be read as hex
	_, _, spanId = logRecordAttrs("1", map[string]string{
		"dd.trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
		"dd.span_id":  "1234567890123456",
	})
	assert.Equal(t, "000462d53c8abac0", spanId.String())

	// a span id without a trace id stays an attribute
	attrs, traceId, spanId = logRecordAttrs("1", map[string]string{"span_id": "00f067aa0ba902b7"})
	assert.Nil(t, traceId)
	assert.Nil(t, spanId)
	assert.Equal(t, []string{"00f067aa0ba902b7"}, attrMap(attrs)["span_id"])
}

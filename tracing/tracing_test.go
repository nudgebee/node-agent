package tracing

import "testing"

func TestParsing(t *testing.T) {
	traceId := "00-50a12d000e35277e8ec41bae28bef03b-fbacbbca60826c48-01"
	traceId = ParseTraceIdHeaders(traceId)
	if traceId != "50a12d000e35277e8ec41bae28bef03b" {
		t.Errorf("Expected 50a12d000e35277e8ec41bae28bef03b, got %s", traceId)
	}
}

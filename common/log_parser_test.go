package common

import (
	"strings"
	"testing"
	"time"

	"github.com/nudgebee/logparser"
	"gotest.tools/assert"
)

func TestLogParser(t *testing.T) {
	const defaultPatternsPerLevel = 256
	ch := make(chan logparser.LogEntry)
	parser := logparser.NewParser(ch, nil, nil, 1*time.Second, defaultPatternsPerLevel, logparser.SensitiveConfig{
		Enabled:       true,
		MinConfidence: "high",
		MaxDetections: 100,
	})

	ch <- logparser.LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAIOSFODNN7EXAMPLE", Level: logparser.LevelInfo}

	// wait for 10 seconds
	time.Sleep(10 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 1, len(counts))
	parser.Stop()
}

func TestGetCgroup(t *testing.T) {
	split := strings.Split(string("/k8s/kube-system/fluentbit-gke-pmknp/fluentbit"), "/")
	namespace := split[2]
	podName := split[3]
	assert.Equal(t, 5, len(split)) // ["", "k8s", "kube-system", "fluentbit-gke-pmknp", "fluentbit"]
	assert.Equal(t, "kube-system", namespace)
	assert.Equal(t, "fluentbit-gke-pmknp", podName)
}

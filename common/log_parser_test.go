package common

import (
	"strings"
	"testing"
	"time"

	"github.com/nudgebee/logparser"
	"gotest.tools/assert"
)

func TestLogParser(t *testing.T) {

	ch := make(chan logparser.LogEntry)
	parser := logparser.NewParser(ch, nil, nil, 0, false)

	ch <- logparser.LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAUCTZOIG66SPQV67B", Level: logparser.LevelInfo}

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
	assert.Equal(t, 1, len(split))
	assert.Equal(t, "kube-system", namespace)
	assert.Equal(t, "fluentbit-gke-pmknp", podName)
}

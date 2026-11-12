package containers

import (
	"fmt"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

// collectorMetrics returns every metric c exports.
func collectorMetrics(t *testing.T, c prometheus.Collector) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	var got []*dto.Metric
	for m := range ch {
		var pb dto.Metric
		assert.NoError(t, m.Write(&pb))
		got = append(got, &pb)
	}
	return got
}

func labelNames(m *dto.Metric) []string {
	var names []string
	for _, l := range m.GetLabel() {
		names = append(names, l.GetName())
	}
	return names
}

// The DNS latency histogram has no domain label: a container resolving many
// names keeps one histogram per destination, status and request type, while
// the request counter still names every domain.
func TestL7StatsDNSHistogramHasNoDomain(t *testing.T) {
	prevMax := *flags.MaxFQDNsPerContainer
	*flags.MaxFQDNsPerContainer = 50
	t.Cleanup(func() { *flags.MaxFQDNsPerContainer = prevMax })

	s := NewL7Stats(prometheus.Labels{"container_id": "/k8s/ci/runner/app"})
	dns := common.Workload{Name: "kube-dns", Namespace: "kube-system", Kind: "Deployment"}
	key := common.NewDestinationKey(netaddr.MustParseIPPort("192.0.2.53:53"), netaddr.MustParseIPPort("192.0.2.53:53"), nil, dns, dns)
	domains := []string{"example.com", "example.net", "example.org", "api.example.com", "cdn.example.com"}
	for i, name := range domains {
		r := dnsResponse(t, name, fmt.Sprintf("198.51.100.%d", i+1))
		s.observe(l7.ProtocolDNS, "ok", "", "", time.Millisecond, key, common.Workload{}, r, "")
	}

	histograms := collectorMetrics(t, s.latency[l7.ProtocolDNS])
	if assert.Len(t, histograms, 1, "one histogram for all domains") {
		assert.NotContains(t, labelNames(histograms[0]), "domain")
		assert.Contains(t, labelNames(histograms[0]), "request_type")
		assert.Equal(t, uint64(len(domains)), histograms[0].GetHistogram().GetSampleCount())
	}

	counters := collectorMetrics(t, s.requests[l7.ProtocolDNS])
	assert.Len(t, counters, len(domains), "the counter keeps one series per domain")
}

package containers

import (
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

// httpPathCounts collects the HTTP request counter and sums it by path.
func httpPathCounts(t *testing.T, s *L7Stats) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	s.requests[l7.ProtocolHTTP].Collect(ch)
	close(ch)
	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		assert.NoError(t, m.Write(&pb))
		for _, l := range pb.GetLabel() {
			if l.GetName() == "path" {
				got[l.GetValue()] += pb.GetCounter().GetValue()
			}
		}
	}
	return got
}

// The request counter labels a path from its second request, holds at most
// --max-http-paths-per-destination paths per destination, and deletes series
// idle for --http-path-idle-ttl.
func TestL7StatsHTTPPathsAreAdmittedCappedAndEvicted(t *testing.T) {
	prevMax := *flags.MaxHTTPPathsPerDestination
	*flags.MaxHTTPPathsPerDestination = 2
	t.Cleanup(func() { *flags.MaxHTTPPathsPerDestination = prevMax })

	s := NewL7Stats(prometheus.Labels{"container_id": "/k8s/shop/client/app"})
	web := common.Workload{Name: "web", Namespace: "shop", Kind: "Deployment"}
	key := common.NewDestinationKey(netaddr.MustParseIPPort("192.0.2.10:80"), netaddr.MustParseIPPort("192.0.2.10:80"), nil, web, web)
	get := func(status, path string) {
		s.observe(l7.ProtocolHTTP, status, "GET", path, 10*time.Millisecond, key, common.Workload{}, &l7.RequestData{}, "")
	}

	get("200", "/api/users")
	get("200", "/api/users")
	get("200", "/api/users")
	get("404", "/red.php")
	get("404", "/.gitmodules")
	get("200", "/api/orders")
	get("200", "/api/orders")
	get("200", "/api/carts")
	get("200", "/api/carts")

	assert.Equal(t, map[string]float64{
		"/api/users":  2, // its first request is counted under ~other
		"/api/orders": 1,
		"~other":      6, // first requests of users and orders, two probes, and both carts requests: past the limit of 2
	}, httpPathCounts(t, &s))

	s.EvictIdleHTTP(time.Now().Add(30*time.Minute), time.Hour)
	assert.Len(t, httpPathCounts(t, &s), 3, "nothing is idle for an hour yet")

	s.EvictIdleHTTP(time.Now().Add(2*time.Hour), time.Hour)
	assert.Empty(t, httpPathCounts(t, &s), "every series idle past the TTL is deleted")

	get("200", "/api/carts")
	get("200", "/api/carts")
	assert.Equal(t, map[string]float64{"~other": 1, "/api/carts": 1}, httpPathCounts(t, &s), "evicted paths free their slots")
}

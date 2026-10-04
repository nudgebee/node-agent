package containers

import (
	"testing"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
)

// stubResolver names every IP after a fixed table, falling back to the IP.
type stubResolver struct{ names map[string]string }

func (r stubResolver) workload(ip string) common.Workload {
	if n, ok := r.names[ip]; ok {
		return common.Workload{Name: n, Namespace: "ns", Kind: "Deployment"}
	}
	return common.Workload{Name: ip}
}
func (r stubResolver) ResolveIP(ip string) common.Workload       { return r.workload(ip) }
func (r stubResolver) ResolveActualIP(ip string) common.Workload { return r.workload(ip) }
func (r stubResolver) ResolveSource(ip string, _ common.Workload) common.Workload {
	return r.workload(ip)
}
func (r stubResolver) CacheDNS(string, string) common.Workload        { return common.Workload{} }
func (r stubResolver) StartWatching() error                           { return nil }
func (r stubResolver) StopWatching()                                  {}
func (r stubResolver) ResolvePodOwner(string, string) common.Workload { return common.Workload{} }

func newSocketTestContainer(t *testing.T, names map[string]string) *Container {
	t.Helper()
	prev := *flags.IgnoreControlPlane
	*flags.IgnoreControlPlane = "loki,victoria"
	t.Cleanup(func() { *flags.IgnoreControlPlane = prev })
	return &Container{
		registry:           &Registry{ip2fqdn: common.NewFQDNCache()},
		ip_resolver:        stubResolver{names: names},
		processes:          map[uint32]*Process{},
		connectionsByPidFd: map[PidFd]*ActiveConnection{},
	}
}

func socketInfo(src string, srcPort uint16, dst string, dstPort uint16) *ebpftracer.SocketInfo {
	return &ebpftracer.SocketInfo{SrcIP: src, SrcPort: srcPort, DstIP: dst, DstPort: dstPort, Valid: true}
}

// A connection built from an L7 event's socket tuple must pass the same
// filters as one seen opening. Before, it skipped them, and traffic to
// ignored destinations was tracked through this path alone.
func TestSocketConnectionAppliesConnectionFilters(t *testing.T) {
	c := newSocketTestContainer(t, map[string]string{"10.0.0.5": "loki-0"})

	for _, tc := range []struct {
		name string
		info *ebpftracer.SocketInfo
	}{
		{"ignored destination", socketInfo("10.0.0.2", 40000, "10.0.0.5", 3100)},
		{"loopback outside the host netns", socketInfo("127.0.0.1", 40001, "127.0.0.1", 8080)},
	} {
		conn, filtered := c.createConnectionFromSocketInfo(1, 7, 100, tc.info)
		if conn != nil || !filtered {
			t.Errorf("%s: got conn=%v filtered=%v, want it filtered", tc.name, conn, filtered)
		}
	}
	if len(c.connectionsByPidFd) != 0 {
		t.Errorf("filtered connections were tracked: %d entries", len(c.connectionsByPidFd))
	}
}

// A tracked one keeps the event's timestamp, so the events that follow on it
// pass the timestamp check instead of being dropped as stale.
func TestSocketConnectionKeepsEventTimestamp(t *testing.T) {
	c := newSocketTestContainer(t, map[string]string{"10.0.0.9": "api"})

	conn, filtered := c.createConnectionFromSocketInfo(1, 7, 12345, socketInfo("10.0.0.2", 40000, "10.0.0.9", 8443))
	if conn == nil || filtered {
		t.Fatalf("got conn=%v filtered=%v, want a tracked connection", conn, filtered)
	}
	if conn.Timestamp != 12345 {
		t.Errorf("Timestamp = %d, want the event's 12345", conn.Timestamp)
	}
	if got := c.connectionsByPidFd[PidFd{Pid: 1, Fd: 7}]; got != conn {
		t.Error("connection not registered under its pid and fd")
	}
	if dw := conn.DestinationKey.GetDestinationWorkload(); dw.Name != "api" {
		t.Errorf("destination workload = %q, want api", dw.Name)
	}
}

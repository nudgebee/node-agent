package common

import (
	"errors"
	"testing"

	"inet.af/netaddr"
)

func newTestVMResolver(t *testing.T, local ...string) *VMIPResolver {
	t.Helper()
	ips := make([]netaddr.IP, 0, len(local))
	for _, s := range local {
		ips = append(ips, netaddr.MustParseIP(s))
	}
	r, err := NewVMIPResolver("vm-1", func() ([]netaddr.IP, error) { return ips, nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StartWatching(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.StopWatching)
	return r
}

func TestVMIPResolverResolveIP(t *testing.T) {
	r := newTestVMResolver(t, "10.0.1.5", "203.0.113.7")
	r.CacheDNS("10.0.1.20", "db.internal")
	r.CacheDNS("198.51.100.9", "api.example.com")

	host := Workload{Name: "vm-1", Namespace: "vm-1", Kind: VMWorkloadKind}
	for _, tc := range []struct {
		ip   string
		want Workload
	}{
		// The host's own addresses, private or public, are the VM itself.
		{"10.0.1.5", host},
		{"203.0.113.7", host},
		{"127.0.0.1", LoopbackWorkload()},
		// Other private addresses are most likely other VMs: never "external".
		{"10.0.1.20", Workload{Name: "db.internal", Namespace: PrivateWorkloadKind, Kind: PrivateWorkloadKind}},
		{"192.168.5.4", Workload{Name: "192.168.5.4", Namespace: PrivateWorkloadKind, Kind: PrivateWorkloadKind}},
		{"100.64.0.8", Workload{Name: "100.64.0.8", Namespace: PrivateWorkloadKind, Kind: PrivateWorkloadKind}},
		{"198.51.100.9", Workload{Name: "api.example.com", Namespace: "external", Kind: "external"}},
		{"192.0.2.1", Workload{Name: "192.0.2.1", Namespace: "external", Kind: "external"}},
	} {
		if got := r.ResolveIP(tc.ip); got != tc.want {
			t.Errorf("ResolveIP(%q) = %+v, want %+v", tc.ip, got, tc.want)
		}
		if got := r.ResolveActualIP(tc.ip); got != tc.want {
			t.Errorf("ResolveActualIP(%q) = %+v, want %+v", tc.ip, got, tc.want)
		}
	}
}

// Without Kubernetes the source IP of a connection is the VM's own address,
// so resolving it by IP attributed every connection to the VM. The source has
// to be the service that opened it.
func TestVMIPResolverResolveSource(t *testing.T) {
	r := newTestVMResolver(t, "10.0.1.5")

	got := r.ResolveSource("10.0.1.5", Workload{Name: "nginx.service", Kind: "container"})
	want := Workload{Name: "nginx.service", Namespace: "vm-1", Kind: "container"}
	if got != want {
		t.Errorf("ResolveSource = %+v, want %+v", got, want)
	}

	// No container identity: fall back to the address.
	if got := r.ResolveSource("10.0.1.5", Workload{}); got.Kind != VMWorkloadKind {
		t.Errorf("ResolveSource without container = %+v, want kind %q", got, VMWorkloadKind)
	}
}

func TestVMIPResolverLocalIPsRefreshFailureKeepsLastKnown(t *testing.T) {
	ips := []netaddr.IP{netaddr.MustParseIP("10.0.1.5")}
	var listErr error
	r, err := NewVMIPResolver("vm-1", func() ([]netaddr.IP, error) { return ips, listErr }, false)
	if err != nil {
		t.Fatal(err)
	}
	r.refreshLocalIPs()
	listErr = errors.New("netlink unavailable")
	r.refreshLocalIPs()
	if got := r.ResolveIP("10.0.1.5"); got.Kind != VMWorkloadKind {
		t.Errorf("after failed refresh ResolveIP = %+v, want kind %q", got, VMWorkloadKind)
	}
}

func TestVMIPResolverStopWatchingIsIdempotent(t *testing.T) {
	r := newTestVMResolver(t)
	r.StopWatching()
	r.StopWatching()
}

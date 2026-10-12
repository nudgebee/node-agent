package common

import (
	"sync"
	"sync/atomic"
	"time"

	lrucache "github.com/hashicorp/golang-lru/v2"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	VMWorkloadKind      = "vm"
	PrivateWorkloadKind = "private"

	localIPsRefreshInterval = time.Minute
)

// VMIPResolver names connection endpoints on a host that is not a Kubernetes
// node, such as a standalone VM running the agent as a systemd service.
//
// There are no pods, services or nodes to map IPs to, so it only knows three
// things: the host's own addresses, whatever DNS names the agent captured, and
// whether an address is private. Every unresolved private address is labelled
// kind=private rather than external: on a VM fleet those are almost always
// other VMs, and calling them external puts them in the same bucket as the
// public internet. Matching them to a specific VM needs data from every host
// and is left to the server.
type VMIPResolver struct {
	hostname         string
	listLocalIPs     func() ([]netaddr.IP, error)
	localIPs         atomic.Pointer[map[netaddr.IP]struct{}]
	shouldResolveDns bool
	dnsResolvedIps   *lrucache.Cache[string, string]
	stopSignal       chan struct{}
	stopOnce         sync.Once
}

// NewVMIPResolver builds a resolver for hostname. listLocalIPs returns the
// host's own interface addresses; it is re-read periodically because DHCP
// and interface changes move them.
func NewVMIPResolver(hostname string, listLocalIPs func() ([]netaddr.IP, error), resolveDns bool) (*VMIPResolver, error) {
	dnsCache, err := lrucache.New[string, string](MAX_RESOLVED_DNS)
	if err != nil {
		return nil, err
	}
	r := &VMIPResolver{
		hostname:         hostname,
		listLocalIPs:     listLocalIPs,
		shouldResolveDns: resolveDns,
		dnsResolvedIps:   dnsCache,
		stopSignal:       make(chan struct{}),
	}
	empty := map[netaddr.IP]struct{}{}
	r.localIPs.Store(&empty)
	return r, nil
}

func (r *VMIPResolver) hostWorkload() Workload {
	return Workload{Name: r.hostname, Namespace: r.hostname, Kind: VMWorkloadKind}
}

func (r *VMIPResolver) ResolveIP(ip string) Workload {
	parsed, err := netaddr.ParseIP(StripPort(ip))
	if err == nil {
		if parsed.IsLoopback() {
			return LoopbackWorkload()
		}
		if _, ok := (*r.localIPs.Load())[parsed]; ok {
			return r.hostWorkload()
		}
	}
	host := ip
	if r.shouldResolveDns {
		if val, ok := r.dnsResolvedIps.Get(ip); ok {
			host = val
		}
	}
	if err == nil && IsIpPrivate(parsed) {
		return Workload{Name: host, Namespace: PrivateWorkloadKind, Kind: PrivateWorkloadKind}
	}
	return Workload{Name: host, Namespace: "external", Kind: "external"}
}

func (r *VMIPResolver) ResolveActualIP(ip string) Workload {
	return r.ResolveIP(ip)
}

// ResolveSource returns the process's own container as the source of a
// connection. Looking the source up by IP, as the Kubernetes resolver does,
// only yields the host address here, which would attribute every connection
// on the VM to the VM rather than to the service that made it.
func (r *VMIPResolver) ResolveSource(ip string, container Workload) Workload {
	if container.Name == "" {
		return r.ResolveIP(ip)
	}
	return Workload{Name: container.Name, Namespace: r.hostname, Kind: container.Kind}
}

func (r *VMIPResolver) CacheDNS(ip string, dns string) Workload {
	r.dnsResolvedIps.Add(ip, dns)
	return Workload{Name: dns, Namespace: "external", Kind: "external"}
}

// ResolvePodOwner is never reached on a VM (only /k8s/ container IDs call
// it); it returns the pod itself so a stray call still yields a stable label.
func (r *VMIPResolver) ResolvePodOwner(podName string, podNamespace string) Workload {
	return Workload{Name: podName, Namespace: podNamespace, Kind: "Pod"}
}

func (r *VMIPResolver) refreshLocalIPs() {
	ips, err := r.listLocalIPs()
	if err != nil {
		klog.Warningln("failed to list local IPs:", err)
		return
	}
	m := make(map[netaddr.IP]struct{}, len(ips))
	for _, ip := range ips {
		m[ip] = struct{}{}
	}
	r.localIPs.Store(&m)
}

func (r *VMIPResolver) StartWatching() error {
	r.refreshLocalIPs()
	go func() {
		ticker := time.NewTicker(localIPsRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopSignal:
				return
			case <-ticker.C:
				r.refreshLocalIPs()
			}
		}
	}()
	return nil
}

func (r *VMIPResolver) StopWatching() {
	r.stopOnce.Do(func() { close(r.stopSignal) })
}

package containers

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
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

// A recycled fd must not hand a new connection the previous one's HTTP/2
// parser (and so its HPACK table), but a parser already created for the new
// connection, by an L7 event that beat the open event, must survive. A parser
// without a timestamp came from an untracked socket, so it cannot belong to
// the tracked connection now opening on its fd.
func TestDropStaleHTTP2Parser(t *testing.T) {
	k := PidFd{Pid: 1, Fd: 7}
	parser := func(ts uint64) *l7.Http2Parser {
		p := l7.NewHttp2Parser()
		p.ConnTimestamp = ts
		return p
	}
	for _, tc := range []struct {
		name     string
		parserTs uint64
		connTs   uint64
		kept     bool
	}{
		{"previous connection's parser", 100, 200, false},
		{"this connection's parser", 200, 200, true},
		{"parser without a timestamp", 0, 200, false},
	} {
		c := &Container{googleHTTP2Parsers: map[PidFd]*l7.Http2Parser{k: parser(tc.parserTs)}}
		c.dropStaleHTTP2Parser(k, tc.connTs)
		if _, ok := c.googleHTTP2Parsers[k]; ok != tc.kept {
			t.Errorf("%s: kept=%v, want %v", tc.name, ok, tc.kept)
		}
	}
	(&Container{}).dropStaleHTTP2Parser(k, 1) // no parsers yet: must not panic
}

// isSocket tells the tracked entry of an fd apart from a later socket that got
// the same fd number, and gives the benefit of the doubt when it cannot tell.
func TestConnectionIsSocket(t *testing.T) {
	conn := &ActiveConnection{dst: netaddr.MustParseIPPort("192.0.2.53:53")}
	for _, tc := range []struct {
		name string
		info *ebpftracer.SocketInfo
		want bool
	}{
		{"same socket", socketInfo("10.0.0.2", 40000, "192.0.2.53", 53), true},
		{"same socket, IPv4-mapped", socketInfo("::ffff:10.0.0.2", 40000, "::ffff:192.0.2.53", 53), true},
		{"other address", socketInfo("10.0.0.2", 40001, "203.0.113.9", 443), false},
		{"other port", socketInfo("10.0.0.2", 40001, "192.0.2.53", 853), false},
		{"no tuple", nil, true},
		{"invalid tuple", &ebpftracer.SocketInfo{DstIP: "203.0.113.9", DstPort: 443}, true},
	} {
		if got := conn.isSocket(tc.info); got != tc.want {
			t.Errorf("%s: isSocket = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !(&ActiveConnection{}).isSocket(socketInfo("10.0.0.2", 40001, "203.0.113.9", 443)) {
		t.Error("a connection with no known address must not be taken for another socket")
	}
}

// A resolver must keep its own name. An application resolves a host over UDP,
// closes the socket, and connects to the host on the same fd number. When the
// UDP socket was tracked, its entry outlived it and the ClientHello on the new
// connection named the resolver after the host; every later query to the
// resolver then carried that host as its destination, a new set of series for
// every host the container connected to.
func TestDNSResolverKeepsItsNameAcrossReusedFd(t *testing.T) {
	c := newL7TestContainer(t)
	const (
		resolver = "192.0.2.53"
		hostIP   = "203.0.113.9"
	)
	dnsTuple := socketInfo("10.0.0.2", 40000, resolver, 53)
	tlsTuple := socketInfo("10.0.0.2", 40001, hostIP, 443)

	c.handleL7(t, 1, 7, 0, dnsResponse(t, "api.example.com", hostIP), dnsTuple)
	if _, ok := c.connectionsByPidFd[PidFd{Pid: 1, Fd: 7}]; ok {
		t.Error("the UDP socket of a DNS query was tracked")
	}

	ip2fqdn := c.handleL7(t, 1, 7, 100, clientHello(t, "api.example.com"), tlsTuple)
	if d := ip2fqdn[netaddr.MustParseIP(hostIP)]; d == nil || d.FQDN != "api.example.com" {
		t.Errorf("ClientHello did not name %s: %v", hostIP, ip2fqdn)
	}

	c.handleL7(t, 1, 7, 0, dnsResponse(t, "www.example.org", "198.51.100.7"), dnsTuple)
	if d := c.registry.getDomain(netaddr.MustParseIP(resolver)); d != nil {
		t.Errorf("resolver %s named %q", resolver, d.FQDN)
	}
	if got := c.dnsLabelValues(t, "destination"); len(got) != 1 || !got[resolver+":53"] {
		t.Errorf("DNS destinations = %v, want only %s:53", got, resolver)
	}
}

// The tracked entry of an fd may be an earlier socket's: this socket's open
// event is handled after its first write. A ClientHello names the address of
// its own socket, and a DNS query on that fd is not counted against the
// earlier connection.
func TestEarlierSocketOnFdIsNotUsed(t *testing.T) {
	c := newL7TestContainer(t)
	earlier, _ := c.createConnectionFromSocketInfo(1, 7, 0, socketInfo("10.0.0.2", 40000, "192.0.2.53", 53))
	if earlier == nil {
		t.Fatal("no connection for the earlier socket")
	}

	ip2fqdn := c.handleL7(t, 1, 7, 100, clientHello(t, "api.example.com"), socketInfo("10.0.0.2", 40001, "203.0.113.9", 443))
	if _, ok := ip2fqdn[netaddr.MustParseIP("192.0.2.53")]; ok {
		t.Errorf("ClientHello named the earlier socket's address: %v", ip2fqdn)
	}
	if d := ip2fqdn[netaddr.MustParseIP("203.0.113.9")]; d == nil || d.FQDN != "api.example.com" {
		t.Errorf("ClientHello did not name its own socket's address: %v", ip2fqdn)
	}
	if got := earlier.DestinationKey.DestinationLabelValue(); got != "192.0.2.53:53" {
		t.Errorf("earlier connection renamed to %q", got)
	}

	c.connectionsByPidFd[PidFd{Pid: 1, Fd: 7}], _ = c.connectionFromSocketInfo(1, 7, 100, socketInfo("10.0.0.2", 40001, "203.0.113.9", 443), true)
	c.handleL7(t, 1, 7, 0, dnsResponse(t, "www.example.org", "198.51.100.7"), socketInfo("10.0.0.2", 40002, "192.0.2.53", 53))
	if got := c.dnsLabelValues(t, "destination"); len(got) != 1 || !got["192.0.2.53:53"] {
		t.Errorf("DNS destinations = %v, want only 192.0.2.53:53", got)
	}
}

// The kernel's address translations are recorded for TCP connections only,
// keyed by local address. A UDP query whose local port an earlier TCP
// connection had used found that connection's server there, and was labelled
// with it: one more set of series for every server the container had reached.
// A TCP connection built from its tuple still takes its translation.
func TestDNSQueryTakesNoTCPTranslation(t *testing.T) {
	c := newL7TestContainer(t)
	tcpServer := netaddr.MustParseIPPort("198.51.100.80:8080")
	c.registry.actualDestination = func(netaddr.IPPort) (netaddr.IPPort, bool) { return tcpServer, true }

	c.handleL7(t, 1, 7, 0, dnsResponse(t, "api.example.com", "203.0.113.9"), socketInfo("10.0.0.2", 40000, "192.0.2.53", 53))
	if got := c.dnsLabelValues(t, "actual_destination"); len(got) != 1 || !got["192.0.2.53:53"] {
		t.Errorf("DNS actual destinations = %v, want only 192.0.2.53:53", got)
	}

	conn, _ := c.createConnectionFromSocketInfo(1, 8, 100, socketInfo("10.0.0.2", 40001, "192.0.2.80", 80))
	if conn == nil {
		t.Fatal("no connection for the TCP socket")
	}
	if got := conn.DestinationKey.ActualDestinationLabelValue(); got != tcpServer.String() {
		t.Errorf("TCP actual destination = %q, want %s", got, tcpServer)
	}
}

func newL7TestContainer(t *testing.T) *Container {
	t.Helper()
	// Without a parsed command line no public network is tracked.
	common.ConnectionFilter.WhitelistPrefix(netaddr.MustParseIPPrefix("0.0.0.0/0"))
	prevMax := *flags.MaxFQDNsPerContainer
	*flags.MaxFQDNsPerContainer = 50
	t.Cleanup(func() { *flags.MaxFQDNsPerContainer = prevMax })
	c := newSocketTestContainer(t, nil)
	c.l7Stats = NewL7Stats(nil)
	c.googleHTTP2Parsers = map[PidFd]*l7.Http2Parser{}
	c.llmCaptures = map[PidFd]*llmCapture{}
	return c
}

// handleL7 processes an L7 event as the registry does: the IP names it
// returns are recorded before the next event.
func (c *Container) handleL7(t *testing.T, pid uint32, fd uint64, ts uint64, r *l7.RequestData, si *ebpftracer.SocketInfo) map[netaddr.IP]*common.Domain {
	t.Helper()
	ip2fqdn, result := c.onL7RequestWithResult(pid, fd, ts, r, si)
	if result != L7RequestProcessed {
		t.Fatalf("protocol %d: result %v, want processed", r.Protocol, result)
	}
	for ip, d := range ip2fqdn {
		c.registry.ip2fqdn.Put(ip, d)
	}
	return ip2fqdn
}

// dnsLabelValues returns the values of label name on the DNS counter.
func (c *Container) dnsLabelValues(t *testing.T, name string) map[string]bool {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.l7Stats.requests[l7.ProtocolDNS].Collect(ch)
	close(ch)
	got := map[string]bool{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == name {
				got[l.GetValue()] = true
			}
		}
	}
	return got
}

func dnsResponse(t *testing.T, name, ip string) *l7.RequestData {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: netaddr.MustParseIP(ip).As4()}); err != nil {
		t.Fatal(err)
	}
	payload, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return &l7.RequestData{Protocol: l7.ProtocolDNS, Payload: payload, Duration: time.Millisecond}
}

// clientHello returns a TLS ClientHello event for serverName, as crypto/tls
// writes it.
func clientHello(t *testing.T, serverName string) *l7.RequestData {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	hello := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		hello <- buf[:n]
	}()
	tc := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(time.Second))
	go func() { _ = tc.Handshake() }()
	select {
	case payload := <-hello:
		return &l7.RequestData{Protocol: l7.ProtocolTLSClientHello, Payload: payload}
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello written")
	}
	return nil
}

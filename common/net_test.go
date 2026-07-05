package common

import (
	"testing"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

// setCollapse sets the CollapseInternalDestinations flag for the duration of a
// test and restores the previous value afterwards.
func setCollapse(t *testing.T, v bool) {
	prev := *flags.CollapseInternalDestinations
	*flags.CollapseInternalDestinations = v
	t.Cleanup(func() { *flags.CollapseInternalDestinations = prev })
}

func internalHP(ip string, port uint16) HostPort {
	return HostPortFromIPPort(netaddr.IPPortFrom(netaddr.MustParseIP(ip), port))
}

func TestConnectionFilter(t *testing.T) {
	f := connectionFilter{whitelist: map[string]netaddr.IPPrefix{}}
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("127.0.0.1"), netaddr.MustParseIP("127.0.0.1")))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("192.168.1.1"), netaddr.MustParseIP("127.0.0.1")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("2.2.2.2")))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("192.168.1.1")))
	// because the actual dest is allowed, the dest is added to whitelist
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("2.2.2.2")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("2.2.2.2"), netaddr.MustParseIP("2.2.2.2")))
	f.WhitelistPrefix(netaddr.MustParseIPPrefix("2.2.2.0/24"))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("2.2.2.2"), netaddr.MustParseIP("2.2.2.2")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("3.3.3.3"), netaddr.MustParseIP("3.3.3.3")))
	f.WhitelistPrefix(netaddr.MustParseIPPrefix("4.4.4.4/32"))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("3.3.3.3"), netaddr.MustParseIP("4.4.4.4")))
}

func TestDestinationKey(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("1.1.1.1"), 443)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("2.2.2.2"), 443)

	assert.Equal(t, "1.1.1.1:443 (2.2.2.2:443)", NewDestinationKey(d, ad, nil, Workload{}, Workload{}).String())

	assert.Equal(t,
		"aa.bb.s3.amazonaws.com:443 (2.2.2.2:443)",
		NewDestinationKey(d, ad, &Domain{FQDN: "aa.bb.s3.amazonaws.com", SpecifyIP: false}, Workload{}, Workload{}).String(),
	)
	assert.Equal(t,
		"1.1.1.1:443 (2.2.2.2:443)",
		NewDestinationKey(d, ad, &Domain{FQDN: "aa.bb.s3.amazonaws.com", SpecifyIP: true}, Workload{}, Workload{}).String(),
	)
}
func TestDomain(t *testing.T) {
	assert.Equal(t, "Domain(fqdn,false)", NewDomain("fqdn", []netaddr.IP{netaddr.MustParseIP("127.0.0.1")}).String())
	assert.Equal(t, "Domain(fqdn,false)", NewDomain("fqdn", []netaddr.IP{netaddr.MustParseIP("192.168.1.1")}).String())
	assert.Equal(t, "Domain(fqdn,false)", NewDomain("fqdn", []netaddr.IP{
		netaddr.MustParseIP("1.1.1.1"),
		netaddr.MustParseIP("192.168.1.1"),
	}).String())
	assert.Equal(t, "Domain(fqdn,false)", NewDomain("fqdn", []netaddr.IP{
		netaddr.MustParseIP("1.1.1.1"),
	}).String())
	assert.Equal(t, "Domain(fqdn,false)", NewDomain("fqdn", []netaddr.IP{
		netaddr.MustParseIP("1.1.1.1"),
		netaddr.MustParseIP("1.1.1.2"),
	}).String())
}

func TestNormalizeFQDN(t *testing.T) {
	assert.Equal(t, "IP.in-addr.arpa", NormalizeFQDN("4.3.2.1.in-addr.arpa", "TypePTR"))
	assert.Equal(t, "coroot.com", NormalizeFQDN("coroot.com", "TypeA"))
	assert.Equal(t, "IP.ec2.internal", NormalizeFQDN("ip-172-1-2-3.ec2.internal", "TypeA"))
	assert.Equal(t, "IP.ec2", NormalizeFQDN("ip-172-1-2-3.ec2", "TypeA"))

	assert.Equal(t, "example.com", NormalizeFQDN("example.com", "TypeA"))
	assert.Equal(t, "example.com.search_path_suffix", NormalizeFQDN("example.com.cluster.local", "TypeA"))
	assert.Equal(t, "example.com.search_path_suffix", NormalizeFQDN("example.com.svc.cluster.local", "TypeA"))
	assert.Equal(t, "example.com.search_path_suffix", NormalizeFQDN("example.com.svc.default.cluster.local", "TypeA"))

	assert.Equal(t, "example.net.search_path_suffix", NormalizeFQDN("example.net.svc.default.cluster.local", "TypeA"))
	assert.Equal(t, "example.org.search_path_suffix", NormalizeFQDN("example.org.svc.default.cluster.local", "TypeA"))
	assert.Equal(t, "example.io.search_path_suffix", NormalizeFQDN("example.io.svc.default.cluster.local", "TypeA"))
}

func TestDestinationLabelValue(t *testing.T) {
	fqdn := HostPortWithEmptyIP("api.openai.com", 443)
	internal := internalHP("10.64.3.17", 8080)
	resolved := Workload{Name: "api-server", Namespace: "nudgebee", Kind: "Deployment"}
	noNamespace := Workload{Name: "kube-dns"}
	unresolved := Workload{} // ResolveIP fell through, no name

	t.Run("collapse on", func(t *testing.T) {
		setCollapse(t, true)
		// External FQDN destinations are kept as-is regardless of workload.
		assert.Equal(t, "api.openai.com:443", destinationLabelValue(fqdn, unresolved))
		// Internal resolved -> stable workload identity (no churning IP:port).
		assert.Equal(t, "nudgebee/api-server", destinationLabelValue(internal, resolved))
		// Internal resolved without namespace -> bare name.
		assert.Equal(t, "kube-dns", destinationLabelValue(internal, noNamespace))
		// Internal unresolved -> bare IP, port dimension dropped.
		assert.Equal(t, "10.64.3.17", destinationLabelValue(internal, unresolved))
	})

	t.Run("collapse off", func(t *testing.T) {
		setCollapse(t, false)
		// Legacy behaviour: raw IP:port for internal, FQDN untouched.
		assert.Equal(t, "10.64.3.17:8080", destinationLabelValue(internal, resolved))
		assert.Equal(t, "api.openai.com:443", destinationLabelValue(fqdn, resolved))
	})
}

func TestDestinationIPLabelValue(t *testing.T) {
	private := netaddr.MustParseIP("10.64.3.17")
	public := netaddr.MustParseIP("1.1.1.1")
	resolved := Workload{Name: "api-server", Namespace: "nudgebee", Kind: "Deployment"}

	t.Run("collapse on", func(t *testing.T) {
		setCollapse(t, true)
		// Private + resolved -> workload identity.
		assert.Equal(t, "nudgebee/api-server", DestinationIPLabelValue(private, resolved))
		// Private but unresolved (workload name == the IP) -> keep the IP.
		assert.Equal(t, "10.64.3.17", DestinationIPLabelValue(private, Workload{Name: "10.64.3.17"}))
		// Private with empty workload -> keep the IP.
		assert.Equal(t, "10.64.3.17", DestinationIPLabelValue(private, Workload{}))
		// Public IP -> never collapsed.
		assert.Equal(t, "1.1.1.1", DestinationIPLabelValue(public, Workload{Name: "api.openai.com", Namespace: "external"}))
	})

	t.Run("collapse off", func(t *testing.T) {
		setCollapse(t, false)
		assert.Equal(t, "10.64.3.17", DestinationIPLabelValue(private, resolved))
	})
}

func BenchmarkNormalizeFQDN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NormalizeFQDN("ip-172-1-2-3.ec2.internal", "TypeA")
		NormalizeFQDN("example.io.svc.default.cluster.local", "TypeA")
	}
}

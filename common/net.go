package common

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/gobwas/glob"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	ConnectionFilter = connectionFilter{
		whitelist: map[string]netaddr.IPPrefix{},
	}
	PortFilter *portFilter

	HttpFilter *httpFilter
)

func init() {
	klog.Infoln("whitelisted public IPs:", *flags.ExternalNetworksWhitelist)
	for _, prefix := range *flags.ExternalNetworksWhitelist {
		if prefix == "" {
			continue
		}
		p, err := netaddr.ParseIPPrefix(prefix)
		if err != nil {
			klog.Exitf("invalid network %s: %s", prefix, err)
		}
		ConnectionFilter.WhitelistPrefix(p)
	}
	if r := flags.EphemeralPortRange; r != nil && *r != "" {
		klog.Infoln("ephemeral-port-range:", *r)
		parts := strings.Split(*r, "-")
		if len(parts) != 2 {
			klog.Exitf("invalid port range: %s", *r)
		}
		from, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			klog.Exitf("invalid port range: %s", *r)
		}
		to, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			klog.Exitf("invalid port range: %s", *r)
		}
		if from > to {
			klog.Exitf("invalid port range: %s", *r)
		}
		PortFilter = &portFilter{
			from: uint16(from),
			to:   uint16(to),
		}
	}
	var err error
	if HttpFilter, err = newHttpFilter(*flags.ExcludeHTTPMetricsByPath); err != nil {
		klog.Exitf("invalid HTTP filter: %s", err)
	}
}

func IsIpPrivate(ip netaddr.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if ip.Is4() {
		parts := ip.As4()
		return parts[0] == 100 && parts[1]&0xc0 == 64 // 100.64.0.0/10
	}
	return false
}

func IsIpExternal(ip netaddr.IP) bool {
	return !ip.IsLoopback() && !IsIpPrivate(ip)
}

type connectionFilter struct {
	whitelist map[string]netaddr.IPPrefix
}

func (f connectionFilter) WhitelistIP(ip netaddr.IP) {
	var bits uint8 = 32
	if ip.Is6() {
		bits = 128
	}
	f.WhitelistPrefix(netaddr.IPPrefixFrom(ip, bits))
}

func (f connectionFilter) WhitelistPrefix(p netaddr.IPPrefix) {
	if _, ok := f.whitelist[p.String()]; ok {
		return
	}
	f.whitelist[p.String()] = p
}

func (f connectionFilter) ShouldBeSkipped(dst, actualDst netaddr.IP) bool {
	if dst.IsLinkLocalUnicast() {
		return true
	}
	if IsIpPrivate(dst) || dst.IsLoopback() {
		return false
	}
	for _, prefix := range f.whitelist {
		if prefix.Contains(dst) {
			return false
		}
	}
	if IsIpPrivate(actualDst) || actualDst.IsLoopback() {
		f.WhitelistIP(dst)
		return false
	}
	for _, prefix := range f.whitelist {
		if prefix.Contains(actualDst) {
			f.WhitelistIP(dst)
			return false
		}
	}
	return true
}

type portFilter struct {
	from uint16
	to   uint16
}

func (f *portFilter) ShouldBeSkipped(port uint16) bool {
	if f == nil {
		return false
	}
	return port >= f.from && port <= f.to
}

type HostPort struct {
	host string
	ip   netaddr.IP
	port uint16
}

func HostPortFromIPPort(ipPort netaddr.IPPort) HostPort {
	return HostPort{ip: ipPort.IP(), port: ipPort.Port()}
}

func HostPortWithEmptyIP(host string, port uint16) HostPort {
	return HostPort{host: host, port: port}
}

func (hp HostPort) String() string {
	if hp.Port() == 0 {
		return ""
	}
	return net.JoinHostPort(hp.Host(), strconv.Itoa(int(hp.port)))
}

func (hp HostPort) IPPort() netaddr.IPPort {
	return netaddr.IPPortFrom(hp.ip, hp.port)
}

func (hp HostPort) Port() uint16 {
	return hp.port
}

func (hp HostPort) IP() netaddr.IP {
	return hp.ip
}

func (hp HostPort) Host() string {
	if !hp.ip.IsZero() {
		return hp.ip.String()
	}
	return hp.host
}

type DestinationKey struct {
	destination               HostPort
	actualDestination         HostPort
	destinationWorkload       Workload
	actualDestinationWorkload Workload
}

func (dk DestinationKey) Destination() HostPort {
	return dk.destination
}

func (dk DestinationKey) ActualDestination() HostPort {
	return dk.actualDestination
}

func (dk DestinationKey) ActualDestinationIfKnown() HostPort {
	if dk.actualDestination.Port() != 0 {
		return dk.actualDestination
	}
	return dk.destination
}

func (dk DestinationKey) DestinationLabelValue() string {
	return destinationLabelValue(dk.destination, dk.destinationWorkload)
}

func (dk DestinationKey) ActualDestinationLabelValue() string {
	return destinationLabelValue(dk.actualDestination, dk.actualDestinationWorkload)
}

// destinationLabelValue produces the destination/actual_destination label value.
//
// External destinations resolved to an FQDN (host set, no IP) are returned as-is
// — they are already bounded and meaningful.
//
// Internal destinations carry a raw IP:port. Pod IPs churn and recycle
// constantly, so emitting IP:port creates a brand-new series on every reconnect,
// which is the dominant driver of TSDB churn/cardinality. When
// CollapseInternalDestinations is enabled (default), we substitute the resolved
// workload identity (namespace/name), which stays stable across pod-IP changes.
// The *_workload_* labels already carry this identity, and backend queries key on
// them rather than the raw destination, so this is transparent to consumers.
// When the workload is resolved to a real name (not just the IP echoed back),
// we use its identity. Otherwise we fall back per destination type: private
// (internal) IPs drop the churning port dimension; external IPs keep IP:port
// since their cardinality is low and the port is useful.
func destinationLabelValue(hp HostPort, wl Workload) string {
	// FQDN destinations (external, resolved by DNS) have no IP set — keep them.
	if hp.ip.IsZero() {
		return hp.String()
	}
	if flags.CollapseInternalDestinations == nil || !*flags.CollapseInternalDestinations {
		return hp.String()
	}
	// Resolved workload identity (guard against the IP-echoed-back fallback that
	// ResolveIP returns for unresolved endpoints).
	if wl.Name != "" && wl.Name != hp.ip.String() {
		if wl.Namespace != "" {
			return wl.Namespace + "/" + wl.Name
		}
		return wl.Name
	}
	if IsIpPrivate(hp.ip) {
		// Unresolved internal endpoint: drop the churning port dimension.
		return hp.ip.String()
	}
	// Unresolved external endpoint: low cardinality, keep the port.
	return hp.String()
}

// DestinationIPLabelValue collapses a raw destination IP to the resolved workload
// identity for the container_net_latency_seconds destination_ip label, mirroring
// destinationLabelValue. The pinger works with bare IPs (no port), so this variant
// takes a netaddr.IP. Internal pod IPs churn/recycle; keying the RTT series on
// workload identity keeps it stable. External and unresolved IPs are kept as-is.
func DestinationIPLabelValue(ip netaddr.IP, wl Workload) string {
	if flags.CollapseInternalDestinations == nil || !*flags.CollapseInternalDestinations {
		return ip.String()
	}
	if IsIpPrivate(ip) && wl.Name != "" && wl.Name != ip.String() {
		if wl.Namespace != "" {
			return wl.Namespace + "/" + wl.Name
		}
		return wl.Name
	}
	return ip.String()
}

func (dk DestinationKey) String() string {
	return fmt.Sprintf("%s (%s)", dk.Destination(), dk.actualDestination.String())
}

type Domain struct {
	FQDN      string
	SpecifyIP bool
}

func (d *Domain) String() string {
	return fmt.Sprintf("Domain(%s,%t)", d.FQDN, d.SpecifyIP)
}

func NewDomain(fqdn string, ips []netaddr.IP) *Domain {
	// For external domains, prefer showing domain names over IP addresses in traces
	// This allows external API calls to show meaningful service names instead of IPs
	d := &Domain{FQDN: fqdn, SpecifyIP: false}
	return d
}

// isKubernetesResolved reports whether a Workload carries a real in-cluster
// identity rather than the "external" placeholder the resolvers return for IPs
// they could not map to a pod, service or node. Empty Kind means unresolved.
func isKubernetesResolved(w Workload) bool {
	return w.Kind != "" && w.Kind != "external"
}

func NewDestinationKey(dst, actualDst netaddr.IPPort, domain *Domain, dstWorkload Workload, actualDestWorkload Workload) DestinationKey {
	if IsIpExternal(actualDst.IP()) && domain != nil && !domain.SpecifyIP {
		// Substitute the FQDN for the workload name ONLY when we have no better,
		// k8s-resolved identity. A cluster-internal Service reached via a route
		// whose actual destination looks external still resolves to a real
		// workload (kind=Deployment/StatefulSet, real namespace); overwriting its
		// name with the FQDN produced mixed-provenance labels such as
		//   destination_workload_name      = "temporal-frontend.nudgebee.svc.cluster.local"
		//   destination_workload_namespace = "nudgebee"
		//   destination_workload_kind      = "Deployment"
		// which splits one workload into an extra series that no query matches.
		// The FQDN is still carried by the `destination` label, so nothing is lost.
		if !isKubernetesResolved(dstWorkload) {
			dstWorkload.Name = domain.FQDN
		}
		if !isKubernetesResolved(actualDestWorkload) {
			actualDestWorkload.Name = domain.FQDN
		}
		return DestinationKey{
			destination:               HostPortWithEmptyIP(domain.FQDN, dst.Port()),
			actualDestination:         HostPortFromIPPort(actualDst),
			destinationWorkload:       dstWorkload,
			actualDestinationWorkload: actualDestWorkload,
		}
	} else if IsIpExternal(actualDst.IP()) && domain != nil && domain.SpecifyIP {
		// Note: This case should rarely happen now that we default SpecifyIP to false
		klog.V(5).Infof("ip %q is external, but domain %q specifies IP, using IP as destination", actualDst.IP(), domain.FQDN)
	}
	return DestinationKey{
		destination:               HostPortFromIPPort(dst),
		actualDestination:         HostPortFromIPPort(actualDst),
		destinationWorkload:       dstWorkload,
		actualDestinationWorkload: actualDestWorkload,
	}
}

func NormalizeFQDN(fqdn string, requestType string) string {
	if requestType == "TypePTR" {
		return "IP.in-addr.arpa"
	}
	if strings.HasPrefix(fqdn, "ip-") {
		if idx := strings.Index(fqdn, "."); idx > 0 && strings.HasPrefix(fqdn[idx+1:], "ec2") {
			return "IP.ec2" + fqdn[idx+4:]
		}
	}
	buf := bytes.NewBuffer(nil)
	partsCount := 0
	for i, r := range fqdn {
		if r != '.' {
			buf.WriteRune(r)
		} else {
			if partsCount > 0 && len(fqdn) > i {
				switch string(buf.Bytes()) {
				case "com", "net", "org", "io":
					return fqdn[:i] + ".search_path_suffix"
				}
			}
			buf.Reset()
			partsCount++
		}
	}
	return fqdn
}

func (dk DestinationKey) WithResolvedDomain(fqdn string) DestinationKey {
	dk.destination = HostPortWithEmptyIP(fqdn, dk.destination.Port())
	dk.destinationWorkload.Name = fqdn
	dk.actualDestinationWorkload.Name = fqdn
	return dk
}

func (dk DestinationKey) GetDestinationWorkload() Workload {
	return dk.destinationWorkload
}

func (dk DestinationKey) GetActualDestinationWorkload() Workload {
	return dk.actualDestinationWorkload
}

type httpFilter struct {
	globs []glob.Glob
}

func newHttpFilter(patterns []string) (*httpFilter, error) {
	f := &httpFilter{}
	if len(patterns) == 0 {
		return f, nil
	}
	klog.Infof("HTTP paths to exclude: %v", patterns)
	for _, p := range patterns {
		g, err := glob.Compile(p)
		if err != nil {
			return nil, err
		}
		f.globs = append(f.globs, g)
	}
	return f, nil
}

func (f *httpFilter) ShouldBeSkipped(path string) bool {
	for _, g := range f.globs {
		if g.Match(path) {
			return true
		}
	}
	return false
}

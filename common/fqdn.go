package common

import (
	"net"
	"strings"
)

// StripPort removes a trailing :port from a host.
//
// net.SplitHostPort does the work, including bracketed IPv6 ("[::1]:8080" ->
// "::1") and rejecting bare IPv6, which has no port to strip. The bracketed
// form without a port ("[::1]") is not a valid host:port, so it is unwrapped
// separately. Anything else malformed is returned untouched rather than
// repaired — a half-bracketed "[::1" should stay unparseable, not quietly
// become a valid address.
func StripPort(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	if strings.HasPrefix(hostPort, "[") && strings.HasSuffix(hostPort, "]") {
		return hostPort[1 : len(hostPort)-1]
	}
	return hostPort
}

// IsIPAddress reports whether host (with an optional :port) is a bare IP rather
// than a name.
func IsIPAddress(host string) bool {
	return net.ParseIP(StripPort(host)) != nil
}

// NeedsFQDN reports whether a destination workload name still lacks a usable
// hostname and should be replaced when one is observed.
//
// The empty case matters: the IP resolver leaves the name blank for endpoints it
// cannot map to a workload. Guarding only on IsIPAddress skipped those, so a
// destination that had a perfectly good Host header, :authority or SNI available
// went on reporting a bare IP indefinitely.
func NeedsFQDN(name string) bool {
	return name == "" || IsIPAddress(name)
}

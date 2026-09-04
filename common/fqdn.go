package common

import (
	"net"
	"strings"
)

// StripPort removes a trailing :port from a host, handling the bracketed IPv6
// form ("[::1]:8080" -> "::1").
func StripPort(hostPort string) string {
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.LastIndex(hostPort, "]:"); idx != -1 {
			return hostPort[1:idx]
		}
		return strings.Trim(hostPort, "[]")
	}
	// Bare IPv6 without brackets has several colons and carries no port.
	if strings.Count(hostPort, ":") > 1 {
		return hostPort
	}
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx]
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

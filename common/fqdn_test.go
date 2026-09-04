package common

import "testing"

func TestStripPort(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"10.0.0.1:8080", "10.0.0.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"", ""},
		// Bracketed IPv6 with no port is not a valid host:port; unwrap it.
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"::", "::"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		// Malformed input is returned untouched, not repaired. A half-bracketed
		// address must stay unparseable so IsIPAddress rejects it rather than
		// accepting a value that was never a valid address.
		{"[::1", "[::1"},
	} {
		if got := StripPort(tc.in); got != tc.want {
			t.Errorf("StripPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsIPAddress(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"142.250.115.95", true},
		{"142.250.115.95:443", true},
		{"::1", true},
		{"[2001:db8::1]:443", true},
		{"monitoring.googleapis.com", false},
		{"monitoring.googleapis.com:443", false},
		{"", false},
		{"[::1]", true},
		{"[::1", false}, // malformed, not silently accepted as an address
	} {
		if got := IsIPAddress(tc.in); got != tc.want {
			t.Errorf("IsIPAddress(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The empty case is the regression this guards. The IP resolver leaves the
// workload name blank for endpoints it cannot map; guarding only on IsIPAddress
// skipped those, so a destination with a usable Host header, :authority or SNI
// kept reporting a bare IP indefinitely.
func TestNeedsFQDN(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"empty name is unresolved", "", true},
		{"bare IPv4 is unresolved", "142.250.115.95", true},
		{"IPv4 with port is unresolved", "142.250.115.95:443", true},
		{"bare IPv6 is unresolved", "2001:db8::1", true},
		{"real hostname is resolved", "monitoring.googleapis.com", false},
		{"hostname with port is resolved", "api.pagerduty.com:443", false},
		{"k8s workload name is resolved", "temporal-frontend", false},
	} {
		if got := NeedsFQDN(tc.in); got != tc.want {
			t.Errorf("%s: NeedsFQDN(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

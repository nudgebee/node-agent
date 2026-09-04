package common

import "testing"

// Loopback must not be reported as an external destination. IsIpExternal already
// excludes it, but the resolvers could not map it to a workload and fell through
// to the "external" placeholder, putting host-netns health probes into every
// external-destination view as a 127.0.0.1 -> 127.0.0.1 self-loop.
func TestIsLoopbackIP(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"127.1.2.3", true}, // all of 127.0.0.0/8 is loopback
		{"::1", true},
		{"[::1]:8080", true},
		{"10.0.0.1", false},
		{"142.250.115.95", false},
		{"192.168.1.1", false},
		{"", false},
		{"not-an-ip", false},
		{"localhost", false}, // a name, not an address
	} {
		if got := isLoopbackIP(tc.in); got != tc.want {
			t.Errorf("isLoopbackIP(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLoopbackWorkloadIsNotExternal(t *testing.T) {
	w := LoopbackWorkload()
	if w.Namespace == "external" || w.Kind == "external" {
		t.Errorf("loopback reported as external: %+v", w)
	}
	if w.Name == "" || w.Namespace == "" || w.Kind == "" {
		t.Errorf("loopback workload has empty fields: %+v", w)
	}
	// isKubernetesResolved treats "external" as unresolved; loopback must not be
	// mistaken for a real in-cluster workload either.
	if isKubernetesResolved(w) && w.Kind != "localhost" {
		t.Errorf("unexpected kind for loopback: %+v", w)
	}
}

func TestHttpFilterMatchesProbePaths(t *testing.T) {
	f, err := newHttpFilter([]string{"/readiness", "/liveness", "/healthz*"})
	if err != nil {
		t.Fatalf("newHttpFilter: %v", err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/readiness", true},
		{"/liveness", true},
		{"/healthz", true},
		{"/healthz/ready", true},
		{"/api/v1/users", false},
		{"/", false},
	} {
		if got := f.ShouldBeSkipped(tc.path); got != tc.want {
			t.Errorf("ShouldBeSkipped(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestHttpFilterEmptyPatternsSkipsNothing(t *testing.T) {
	f, err := newHttpFilter(nil)
	if err != nil {
		t.Fatalf("newHttpFilter: %v", err)
	}
	for _, p := range []string{"/readiness", "/api/v1/users", ""} {
		if f.ShouldBeSkipped(p) {
			t.Errorf("unconfigured filter skipped %q", p)
		}
	}
}

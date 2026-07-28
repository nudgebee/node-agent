package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

// A genuinely external destination has no in-cluster identity, so the FQDN is
// the best name available and must still be substituted. This is the behaviour
// the external-service discovery queries depend on: they select on
// actual_destination_workload_kind="external" and read
// actual_destination_workload_name, expecting the FQDN.
func TestNewDestinationKey_ExternalKeepsFQDNName(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("1.1.1.1"), 5432)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("2.2.2.2"), 5432)
	domain := &Domain{FQDN: "db.example.rds.amazonaws.com", SpecifyIP: false}

	external := Workload{Name: "2.2.2.2", Namespace: "external", Kind: "external"}

	key := NewDestinationKey(d, ad, domain, external, external)

	assert.Equal(t, "db.example.rds.amazonaws.com", key.destinationWorkload.Name)
	assert.Equal(t, "db.example.rds.amazonaws.com", key.actualDestinationWorkload.Name)
	assert.Equal(t, "external", key.actualDestinationWorkload.Kind)
}

// An unresolved workload (zero value, empty Kind) also has nothing better than
// the FQDN.
func TestNewDestinationKey_UnresolvedKeepsFQDNName(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("1.1.1.1"), 443)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("2.2.2.2"), 443)
	domain := &Domain{FQDN: "aa.bb.s3.amazonaws.com", SpecifyIP: false}

	key := NewDestinationKey(d, ad, domain, Workload{}, Workload{})

	assert.Equal(t, "aa.bb.s3.amazonaws.com", key.destinationWorkload.Name)
}

// Regression: a cluster-internal Service whose actual destination looks external
// still resolves to a real workload. Its name must NOT be replaced by the FQDN,
// which previously produced mixed-provenance labels (FQDN name + real namespace
// + real kind) and split the workload into an extra series.
func TestNewDestinationKey_ResolvedWorkloadKeepsItsName(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("1.1.1.1"), 7233)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("2.2.2.2"), 7233)
	domain := &Domain{FQDN: "temporal-frontend.nudgebee.svc.cluster.local", SpecifyIP: false}

	resolved := Workload{Name: "temporal-frontend", Namespace: "nudgebee", Kind: "Deployment"}

	key := NewDestinationKey(d, ad, domain, resolved, resolved)

	assert.Equal(t, "temporal-frontend", key.destinationWorkload.Name,
		"a k8s-resolved workload must keep its own name")
	assert.Equal(t, "nudgebee", key.destinationWorkload.Namespace)
	assert.Equal(t, "Deployment", key.destinationWorkload.Kind)

	// The FQDN is still available via the destination label, so nothing is lost.
	assert.Equal(t, "temporal-frontend.nudgebee.svc.cluster.local:7233", key.Destination().String())
}

// Mixed case: destination resolved in-cluster, actual destination genuinely
// external. Each side is decided independently.
func TestNewDestinationKey_MixedResolution(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("1.1.1.1"), 6379)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("2.2.2.2"), 6379)
	domain := &Domain{FQDN: "redis-master.redis.svc.cluster.local", SpecifyIP: false}

	resolved := Workload{Name: "redis-master", Namespace: "redis", Kind: "StatefulSet"}
	external := Workload{Name: "2.2.2.2", Namespace: "external", Kind: "external"}

	key := NewDestinationKey(d, ad, domain, resolved, external)

	assert.Equal(t, "redis-master", key.destinationWorkload.Name)
	assert.Equal(t, "redis-master.redis.svc.cluster.local", key.actualDestinationWorkload.Name)
}

func TestIsKubernetesResolved(t *testing.T) {
	assert.False(t, isKubernetesResolved(Workload{}), "empty Kind is unresolved")
	assert.False(t, isKubernetesResolved(Workload{Kind: "external"}))
	assert.True(t, isKubernetesResolved(Workload{Kind: "Deployment"}))
	assert.True(t, isKubernetesResolved(Workload{Kind: "StatefulSet"}))
	assert.True(t, isKubernetesResolved(Workload{Kind: "Service"}))
	assert.True(t, isKubernetesResolved(Workload{Kind: "pod"}))
	assert.True(t, isKubernetesResolved(Workload{Kind: "node"}))
}

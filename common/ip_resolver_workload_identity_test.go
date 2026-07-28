package common

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// disableEphemeralAggregation pins AggregateEphemeralWorkloads off so these
// tests exercise the owner-resolution path only.
func disableEphemeralAggregation(t *testing.T) {
	t.Helper()
	orig := flags.AggregateEphemeralWorkloads
	disabled := false
	flags.AggregateEphemeralWorkloads = &disabled
	t.Cleanup(func() { flags.AggregateEphemeralWorkloads = orig })
}

func controllerRef(name string, uid types.UID, kind string) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{Name: name, UID: uid, Kind: kind, Controller: &yes}
}

func TestStripPodTemplateHash(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantName string
		wantOk   bool
	}{
		// Deployment-generated ReplicaSet names — the case that caused the
		// duplicate llm-server / llm-server-779f867dc9 series.
		{"real replicaset name", "llm-server-779f867dc9", "llm-server", true},
		{"second revision", "llm-server-78c94f7dfd", "llm-server", true},
		{"shorter hash", "services-server-6f476f6f79", "services-server", true},
		{"hyphenated deployment", "my-long-app-name-5b8d9fcc7", "my-long-app-name", true},

		// Must NOT be rewritten: a bare ReplicaSet has no pod-template-hash, so
		// stripping would invent a Deployment that does not exist.
		{"bare replicaset, no suffix", "replicaset1", "replicaset1", false},
		{"no hyphen at all", "myapp", "myapp", false},
		{"suffix contains vowels", "my-app-frontend", "my-app-frontend", false},
		{"suffix too short", "my-app-abc", "my-app-abc", false},
		{"suffix too long", "my-app-bcdfghjklmnpqrstvwxz", "my-app-bcdfghjklmnpqrstvwxz", false},
		{"trailing hyphen", "my-app-", "my-app-", false},
		{"leading hyphen only", "-bcdfgh", "-bcdfgh", false},
		{"uppercase not a k8s hash", "my-app-ABCDEF", "my-app-ABCDEF", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := stripPodTemplateHash(tt.in)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.wantName, got)
		})
	}
}

// A pod whose ReplicaSet is already cached must resolve all the way to the
// Deployment, and that result is safe to memoize.
func TestResolvePodDescriptor_FullChainIsCached(t *testing.T) {
	disableEphemeralAggregation(t)

	rsUID := types.UID(uuid.NewString())
	deployUID := types.UID(uuid.NewString())
	podUID := types.UID(uuid.NewString())

	r := &K8sIPResolver{}
	r.snapshot.ReplicaSets.Store(rsUID, MinimalOwnerInfo{
		OwnerReferences: []metav1.OwnerReference{controllerRef("llm-server", deployUID, "Deployment")},
	})
	r.snapshot.Deployments.Store(deployUID, MinimalOwnerInfo{})

	pod := &MinimalPod{
		UID:             podUID,
		Name:            "llm-server-779f867dc9-abcde",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("llm-server-779f867dc9", rsUID, "ReplicaSet")},
	}

	got := r.resolvePodDescriptor(pod)
	assert.Equal(t, "llm-server", got.Name)
	assert.Equal(t, "Deployment", got.Kind)
	assert.Equal(t, "nudgebee", got.Namespace)

	_, cached := r.snapshot.PodDescriptors.Load(podUID)
	assert.True(t, cached, "a fully-resolved chain should be memoized")
}

// Regression for the primary bug: when the owning ReplicaSet is missing from
// the informer snapshot the climb cannot complete, so the result must NOT be
// memoized. Previously a shadowed `err` left the outer error nil, the partial
// (ReplicaSet) identity was cached, and the pod kept that identity forever.
func TestResolvePodDescriptor_TransientMissIsNotCached(t *testing.T) {
	disableEphemeralAggregation(t)

	rsUID := types.UID(uuid.NewString())
	podUID := types.UID(uuid.NewString())

	r := &K8sIPResolver{} // ReplicaSet deliberately absent from the snapshot

	pod := &MinimalPod{
		UID:             podUID,
		Name:            "llm-server-779f867dc9-abcde",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("llm-server-779f867dc9", rsUID, "ReplicaSet")},
	}

	r.resolvePodDescriptor(pod)

	_, cached := r.snapshot.PodDescriptors.Load(podUID)
	assert.False(t, cached, "an unresolved owner chain must not be memoized")
}

// The whole point of not caching: once informers sync, the very next call must
// return the Deployment rather than a stale ReplicaSet identity.
func TestResolvePodDescriptor_RecoversAfterInformerSync(t *testing.T) {
	disableEphemeralAggregation(t)

	rsUID := types.UID(uuid.NewString())
	deployUID := types.UID(uuid.NewString())
	podUID := types.UID(uuid.NewString())

	r := &K8sIPResolver{}
	pod := &MinimalPod{
		UID:             podUID,
		Name:            "llm-server-779f867dc9-abcde",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("llm-server-779f867dc9", rsUID, "ReplicaSet")},
	}

	// First call: ReplicaSet not cached yet. Falls back to the hash-stripped
	// Deployment name and must not poison the cache.
	first := r.resolvePodDescriptor(pod)
	assert.Equal(t, "llm-server", first.Name, "fallback should strip the pod-template-hash")

	// Informers catch up.
	r.snapshot.ReplicaSets.Store(rsUID, MinimalOwnerInfo{
		OwnerReferences: []metav1.OwnerReference{controllerRef("llm-server", deployUID, "Deployment")},
	})
	r.snapshot.Deployments.Store(deployUID, MinimalOwnerInfo{})

	second := r.resolvePodDescriptor(pod)
	assert.Equal(t, "llm-server", second.Name)
	assert.Equal(t, "Deployment", second.Kind, "must resolve to Deployment once the RS is cached")

	_, cached := r.snapshot.PodDescriptors.Load(podUID)
	assert.True(t, cached, "resolved chain should now be memoized")
}

// An owner kind we do not track (e.g. Argo Rollouts) is a terminal condition,
// not a transient one: retrying can never help, so the identity we already have
// must still be cached to avoid re-walking the chain on every scrape.
func TestResolvePodDescriptor_UnsupportedOwnerKindIsCached(t *testing.T) {
	disableEphemeralAggregation(t)

	podUID := types.UID(uuid.NewString())
	r := &K8sIPResolver{}

	pod := &MinimalPod{
		UID:             podUID,
		Name:            "rollout-pod-1",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("my-rollout", types.UID(uuid.NewString()), "Rollout")},
	}

	got := r.resolvePodDescriptor(pod)
	assert.Equal(t, "my-rollout", got.Name)
	assert.Equal(t, "Rollout", got.Kind)

	_, cached := r.snapshot.PodDescriptors.Load(podUID)
	assert.True(t, cached, "terminal (unsupported kind) resolution should be memoized")
}

// OwnerReferences are client-settable, so a circular chain is possible via a
// buggy controller or a hand-edited ref. Without a depth bound the climb loops
// forever and wedges the collector goroutine. This test deadlocks on timeout if
// the bound is ever removed.
func TestResolvePodDescriptor_CircularOwnerChainTerminates(t *testing.T) {
	disableEphemeralAggregation(t)

	aUID := types.UID(uuid.NewString())
	bUID := types.UID(uuid.NewString())
	podUID := types.UID(uuid.NewString())

	r := &K8sIPResolver{}
	// A is owned by B, B is owned by A.
	r.snapshot.ReplicaSets.Store(aUID, MinimalOwnerInfo{
		OwnerReferences: []metav1.OwnerReference{controllerRef("b", bUID, "Deployment")},
	})
	r.snapshot.Deployments.Store(bUID, MinimalOwnerInfo{
		OwnerReferences: []metav1.OwnerReference{controllerRef("a", aUID, "ReplicaSet")},
	})

	pod := &MinimalPod{
		UID:             podUID,
		Name:            "cyclic-pod",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("a", aUID, "ReplicaSet")},
	}

	done := make(chan Workload, 1)
	go func() { done <- r.resolvePodDescriptor(pod) }()

	select {
	case got := <-done:
		// Terminates with whichever identity the bounded climb reached.
		assert.Contains(t, []string{"a", "b"}, got.Name)
		_, cached := r.snapshot.PodDescriptors.Load(podUID)
		assert.True(t, cached, "a malformed chain is terminal and should be cached, not re-walked every scrape")
	case <-time.After(5 * time.Second):
		t.Fatal("resolvePodDescriptor did not terminate on a circular owner chain")
	}
}

// A bare ReplicaSet with no pod-template-hash must keep its own name; inventing
// a Deployment for it would be wrong.
func TestResolvePodDescriptor_BareReplicaSetKeepsItsName(t *testing.T) {
	disableEphemeralAggregation(t)

	rsUID := types.UID(uuid.NewString())
	podUID := types.UID(uuid.NewString())

	r := &K8sIPResolver{}
	// Present in cache, but owned by nothing — the chain terminates here.
	r.snapshot.ReplicaSets.Store(rsUID, MinimalOwnerInfo{})

	pod := &MinimalPod{
		UID:             podUID,
		Name:            "standalone-rs-xyz",
		Namespace:       "nudgebee",
		OwnerReferences: []metav1.OwnerReference{controllerRef("standalone-rs", rsUID, "ReplicaSet")},
	}

	got := r.resolvePodDescriptor(pod)
	assert.Equal(t, "standalone-rs", got.Name)
	assert.Equal(t, "ReplicaSet", got.Kind)
}

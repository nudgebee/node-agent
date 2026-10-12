package common

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// client-go delivers a cache.DeletedFinalStateUnknown tombstone instead of the
// object when a watch is interrupted and the final delete is missed. The
// informer DeleteFuncs used to assert the payload directly, so a tombstone
// panicked on the shared informer goroutine — fatal to the process. A customer
// cluster crashlooped node-agent 15 times on exactly this:
//
//	panic: interface conversion: interface {} is cache.DeletedFinalStateUnknown, not *v1.Pod
func TestDeletedObjectUnwrapsTombstone(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: "uid-1"}}

	t.Run("plain object", func(t *testing.T) {
		got, ok := deletedObject[*v1.Pod](pod)
		if !ok || got != pod {
			t.Fatalf("plain object not returned: got=%v ok=%v", got, ok)
		}
	})

	t.Run("tombstone", func(t *testing.T) {
		got, ok := deletedObject[*v1.Pod](cache.DeletedFinalStateUnknown{Key: "ns/p", Obj: pod})
		if !ok {
			t.Fatal("tombstone not unwrapped — this is the crash-loop bug")
		}
		if got != pod {
			t.Fatalf("wrong object from tombstone: %v", got)
		}
	})
}

// A payload we cannot make sense of must be skipped, never panic: a tombstone
// wrapping the wrong type or nil, or an unrelated object.
func TestDeletedObjectRejectsBadPayloads(t *testing.T) {
	cases := []struct {
		name string
		obj  interface{}
	}{
		{"nil", nil},
		{"wrong type", &v1.Service{}},
		{"tombstone wrapping wrong type", cache.DeletedFinalStateUnknown{Key: "k", Obj: &v1.Service{}}},
		{"tombstone wrapping nil", cache.DeletedFinalStateUnknown{Key: "k", Obj: nil}},
		{"unrelated value", 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %s: %v", tc.name, r)
				}
			}()
			if got, ok := deletedObject[*v1.Pod](tc.obj); ok {
				t.Fatalf("accepted bad payload %s: %v", tc.name, got)
			}
		})
	}
}

// The same tombstone path must hold for every object type with a DeleteFunc,
// not just pods — Service and Node take the same shape.
func TestDeletedObjectOtherTypes(t *testing.T) {
	svc := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "s", UID: "uid-s"}}
	if got, ok := deletedObject[*v1.Service](cache.DeletedFinalStateUnknown{Obj: svc}); !ok || got != svc {
		t.Error("service tombstone not unwrapped")
	}
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n", UID: "uid-n"}}
	if got, ok := deletedObject[*v1.Node](cache.DeletedFinalStateUnknown{Obj: node}); !ok || got != node {
		t.Error("node tombstone not unwrapped")
	}
}

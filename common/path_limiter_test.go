package common

import (
	"fmt"
	"sync"
	"testing"

	"github.com/coroot/coroot-node-agent/flags"
)

// withPathCap sets the cap for the duration of a test. Flags are not parsed in
// test binaries (flags.init bails out on the .test suffix), so the pointer holds
// a zero value rather than the declared default.
func withPathCap(t *testing.T, limit int) {
	t.Helper()
	prev := *flags.MaxHttpPathsPerContainer
	*flags.MaxHttpPathsPerContainer = limit
	t.Cleanup(func() { *flags.MaxHttpPathsPerContainer = prev })
}

func TestPathLimiterAdmitsUpToCapThenCollapses(t *testing.T) {
	withPathCap(t, 3)
	l := NewPathLimiter("/k8s/test/pod/app")

	for _, p := range []string{"/a", "/b", "/c"} {
		if got := l.Limit(p); got != p {
			t.Fatalf("Limit(%q) = %q, want it admitted", p, got)
		}
	}

	if got := l.Limit("/d"); got != OtherPath {
		t.Errorf("Limit(%q) = %q, want %q once the cap is reached", "/d", got, OtherPath)
	}

	// Paths admitted before the cap keep reporting under their real value — a
	// steady application must not lose its routes to scanner traffic that arrives
	// later.
	if got := l.Limit("/b"); got != "/b" {
		t.Errorf("Limit(%q) = %q, want the already-admitted path", "/b", got)
	}
}

func TestPathLimiterUnlimitedWhenCapIsZero(t *testing.T) {
	withPathCap(t, 0)
	l := NewPathLimiter("/k8s/test/pod/app")

	for i := 0; i < 500; i++ {
		p := fmt.Sprintf("/p%d", i)
		if got := l.Limit(p); got != p {
			t.Fatalf("Limit(%q) = %q, want no cap when the flag is 0", p, got)
		}
	}
}

func TestPathLimiterPassesEmptyPathThrough(t *testing.T) {
	withPathCap(t, 1)
	l := NewPathLimiter("/k8s/test/pod/app")

	// Non-HTTP protocols and invalid-UTF8 requests report "", which must neither
	// consume a cap slot nor be rewritten to OtherPath.
	for i := 0; i < 10; i++ {
		if got := l.Limit(""); got != "" {
			t.Fatalf("Limit(\"\") = %q, want \"\"", got)
		}
	}
	if got := l.Limit("/real"); got != "/real" {
		t.Errorf("Limit(%q) = %q, want it admitted — empty paths must not fill the cap", "/real", got)
	}
}

func TestPathLimiterIsBoundedUnderConcurrency(t *testing.T) {
	const cap = 50
	withPathCap(t, cap)
	l := NewPathLimiter("/k8s/test/pod/app")

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Limit(fmt.Sprintf("/w%d/p%d", worker, i))
			}
		}(w)
	}
	wg.Wait()

	// The whole point of the cap: concurrent admission must never overshoot it,
	// otherwise the series bound is not actually a bound.
	if n := l.Len(); n > cap {
		t.Errorf("admitted %d distinct paths, want at most %d", n, cap)
	}
}

func TestPathLimiterNilReceiverIsSafe(t *testing.T) {
	withPathCap(t, 1)
	var l *PathLimiter

	// Limit runs on every HTTP request; a zero-value L7Stats must degrade to
	// unbounded rather than panic.
	if got := l.Limit("/a"); got != "/a" {
		t.Errorf("(*PathLimiter)(nil).Limit(%q) = %q, want it returned unchanged", "/a", got)
	}
	if got := l.Limit("/b"); got != "/b" {
		t.Errorf("(*PathLimiter)(nil).Limit(%q) = %q, want it returned unchanged", "/b", got)
	}
}

func TestPathLimiterIsPerInstance(t *testing.T) {
	withPathCap(t, 1)
	a, b := NewPathLimiter("container-a"), NewPathLimiter("container-b")

	// One noisy container filling its cap must not silence another's routes.
	a.Limit("/only")
	if got := a.Limit("/second"); got != OtherPath {
		t.Errorf("a.Limit(%q) = %q, want %q", "/second", got, OtherPath)
	}
	if got := b.Limit("/second"); got != "/second" {
		t.Errorf("b.Limit(%q) = %q, want it admitted on an independent limiter", "/second", got)
	}
}

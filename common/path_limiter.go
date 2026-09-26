package common

import (
	"sync"

	"github.com/coroot/coroot-node-agent/flags"
	"k8s.io/klog/v2"
)

// OtherPath is the bucket every path beyond the per-container cap collapses
// into. Requests are still counted, they just stop minting new series.
const OtherPath = "{other}"

// PathLimiter bounds the number of distinct HTTP `path` label values a single
// container may contribute to container_http_requests_total.
//
// `path` is the only L7 label an outside party controls. An internet-facing
// ingress is probed for vulnerabilities around the clock, and every unique junk
// path (/axds.php, /HNAP1, ...) becomes a permanent series. Normalization cannot
// collapse them because they are genuinely distinct literals, so the series count
// grows without bound for as long as the scanners keep scanning.
//
// Paths seen before the cap is reached always pass through, so a steady
// application keeps reporting its real routes; only paths first observed after
// the cap fills are folded into OtherPath. Real applications serve far fewer
// routes than the default cap, which should only ever engage on scanner traffic.
//
// The zero value is not usable; construct with NewPathLimiter.
type PathLimiter struct {
	mu   sync.RWMutex
	seen map[string]struct{}
	full bool // latched once the cap is hit, so the hot path skips the map entirely

	owner string // container_id, for the one-shot warning
}

func NewPathLimiter(owner string) *PathLimiter {
	return &PathLimiter{seen: make(map[string]struct{}), owner: owner}
}

// Limit returns path if it may be reported as-is, or OtherPath if admitting it
// would push this container past flags.MaxHttpPathsPerContainer. Callers should
// normalize the path first so that a parameterized route consumes one slot
// rather than one per parameter value.
// A nil receiver is tolerated (returns path unchanged) so that an L7Stats built
// as a zero value rather than through its constructor degrades to the old
// unbounded behaviour instead of panicking in the L7 hot path.
func (l *PathLimiter) Limit(path string) string {
	limit := flags.GetInt(flags.MaxHttpPathsPerContainer)
	// An empty path is what non-HTTP protocols and invalid-UTF8 requests report;
	// it must not consume a slot.
	if l == nil || limit <= 0 || path == "" {
		return path
	}

	l.mu.RLock()
	_, seen := l.seen[path]
	full := l.full
	l.mu.RUnlock()
	if seen {
		return path
	}
	if full {
		return OtherPath
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-check: another request may have admitted this path, or filled the cap,
	// while we waited for the write lock.
	if _, seen := l.seen[path]; seen {
		return path
	}
	if len(l.seen) >= limit {
		if !l.full {
			l.full = true
			klog.Warningf("HTTP path cardinality cap (%d) reached for %s, further unseen paths reported as %s",
				limit, l.owner, OtherPath)
		}
		return OtherPath
	}
	l.seen[path] = struct{}{}
	return path
}

// Len reports how many distinct paths have been admitted. For tests and
// diagnostics.
func (l *PathLimiter) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.seen)
}

package common

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func labelsFor(status string) func(string) []string {
	return func(path string) []string { return []string{status, path, "GET"} }
}

func TestHTTPPathSeriesAdmitsRecurringPathsPerDestination(t *testing.T) {
	h := NewHTTPPathSeries(2, "~other")
	now := time.Now()

	v, _ := h.Observe("shop/web", "/api/users", now, labelsFor("200"))
	assert.Equal(t, "~other", v[1], "a path's first request is not labelled")
	v, _ = h.Observe("shop/web", "/api/users", now, labelsFor("200"))
	assert.Equal(t, "/api/users", v[1])

	for i := 0; i < 20; i++ {
		v, _ = h.Observe("shop/web", fmt.Sprintf("/probe-%d.php", i), now, labelsFor("404"))
		assert.Equal(t, "~other", v[1], "one-off probes never get a label")
	}

	_, _ = h.Observe("shop/web", "/api/orders", now, labelsFor("200"))
	_, _ = h.Observe("shop/web", "/api/orders", now, labelsFor("200"))
	_, _ = h.Observe("shop/web", "/api/carts", now, labelsFor("200"))
	v, full := h.Observe("shop/web", "/api/carts", now, labelsFor("200"))
	assert.Equal(t, "~other", v[1], "no third path for this destination")
	assert.True(t, full)

	_, _ = h.Observe("shop/docs", "/guide", now, labelsFor("200"))
	v, full = h.Observe("shop/docs", "/guide", now, labelsFor("200"))
	assert.Equal(t, "/guide", v[1], "another destination has its own limit")
	assert.False(t, full)
}

func TestHTTPPathSeriesEvictsIdleSeriesAndFreesTheSlot(t *testing.T) {
	h := NewHTTPPathSeries(1, "~other")
	t0 := time.Now()

	_, _ = h.Observe("shop/web", "/old", t0, labelsFor("200"))
	_, _ = h.Observe("shop/web", "/old", t0, labelsFor("200"))
	_, _ = h.Observe("shop/web", "/old", t0, labelsFor("500"))
	_, _ = h.Observe("shop/web", "/old", t0.Add(30*time.Minute), labelsFor("500"))

	var removed [][]string
	n := h.Evict(t0.Add(70*time.Minute), time.Hour, func(l []string) { removed = append(removed, l) })
	// The first-request ~other series and the 200 series are idle; the 500 series
	// of the same path was seen 40 minutes ago and keeps the path admitted.
	assert.Equal(t, 2, n)
	assert.ElementsMatch(t, [][]string{{"200", "~other", "GET"}, {"200", "/old", "GET"}}, removed)
	_, _ = h.Observe("shop/web", "/new", t0.Add(70*time.Minute), labelsFor("200"))
	v, _ := h.Observe("shop/web", "/new", t0.Add(70*time.Minute), labelsFor("200"))
	assert.Equal(t, "~other", v[1], "the slot is still held by the live 500 series")

	n = h.Evict(t0.Add(3*time.Hour), time.Hour, func(l []string) {})
	assert.Equal(t, 2, n)
	_, _ = h.Observe("shop/web", "/new", t0.Add(3*time.Hour), labelsFor("200"))
	v, _ = h.Observe("shop/web", "/new", t0.Add(3*time.Hour), labelsFor("200"))
	assert.Equal(t, "/new", v[1], "with every series of /old gone, its slot is free")
	assert.NotContains(t, h.admitted["shop/web"], "/old")
}

func TestHTTPPathSeriesEmptyPathIsNotAdmitted(t *testing.T) {
	h := NewHTTPPathSeries(1, "~other")
	v, full := h.Observe("shop/web", "", time.Now(), labelsFor("200"))
	assert.Equal(t, "", v[1], "HTTP/2 records no path")
	assert.False(t, full)
}

func TestHTTPPathSeriesForgetsADestinationWithItsLastSeries(t *testing.T) {
	h := NewHTTPPathSeries(5, "~other")
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		_, _ = h.Observe("203.0.113.7:443", fmt.Sprintf("/probe-%d", i), t0, labelsFor("404"))
	}
	assert.Len(t, h.candidates, 3)

	h.Evict(t0.Add(2*time.Hour), time.Hour, func([]string) {})
	assert.Empty(t, h.admitted, "a destination with only one-off paths is not kept forever")
	assert.Empty(t, h.destRefs)
	assert.Empty(t, h.series)
}

func TestHTTPPathSeriesBoundsPathsSeenOnceAcrossDestinations(t *testing.T) {
	h := NewHTTPPathSeries(10, "~other")
	now := time.Now()
	for d := 0; d < 200; d++ {
		dst := fmt.Sprintf("203.0.113.%d:443", d)
		for i := 0; i < 10; i++ {
			// The destination is part of a series' labels, as in L7Stats.
			_, _ = h.Observe(dst, fmt.Sprintf("/probe-%d", i), now, func(path string) []string { return []string{"404", dst, path, "GET"} })
		}
	}
	assert.LessOrEqual(t, len(h.candidates), 10, "paths seen once stay within the limit however many destinations there are")

	h.Evict(now.Add(2*time.Hour), time.Hour, func([]string) {})
	assert.Empty(t, h.admitted)
	assert.Empty(t, h.destRefs)
}

// A destination with one recurring path is not starved by another that floods
// the shared set: the set empties for everyone at once, and a path still needs
// only two requests that are not separated by a flood.
func TestHTTPPathSeriesSharedCandidatesAreFair(t *testing.T) {
	h := NewHTTPPathSeries(3, "~other")
	now := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = h.Observe("scanned", fmt.Sprintf("/probe-%d", i), now, labelsFor("404"))
	}
	_, _ = h.Observe("quiet", "/health", now, labelsFor("200"))
	v, _ := h.Observe("quiet", "/health", now, labelsFor("200"))
	assert.Equal(t, "/health", v[1])
}

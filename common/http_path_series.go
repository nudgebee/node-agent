package common

import (
	"strings"
	"sync"
	"time"
)

// HTTPPathSeries decides the path label of each HTTP request counter series and
// tracks every series it labelled, so series idle for longer than a TTL can be
// deleted.
//
// A counter series lives until it is deleted, and nothing deleted HTTP series:
// a path requested once (a scanner's /red.php) was exported until the container
// or the agent restarted. On one cluster 73,398 request series were exported
// while 347 had a request in the last hour.
//
// A path gets its own label from its second request, so one-off paths stay
// under the overflow label. Each destination labels at most limit paths, so an
// ingress that fronts many services does not share one limit across them all.
// Paths seen once are remembered across all destinations, up to limit, and all
// forgotten together when that fills: an external address is a destination of
// its own, so a per-destination bound would grow with the number of addresses.
//
// Labelling, recording and eviction share one mutex: a path cannot be forgotten
// between being labelled and its series being recorded.
type HTTPPathSeries struct {
	mu         sync.Mutex
	limit      int
	overflow   string
	admitted   map[string]map[string]struct{} // destination -> labelled paths
	candidates map[destinationPath]struct{}   // paths seen once, all destinations
	series     map[string]*httpSeries         // joined label values -> series
	refs       map[destinationPath]int        // series per labelled path
	destRefs   map[string]int                 // series per destination
}

type destinationPath struct{ destination, path string }

type httpSeries struct {
	labels   []string
	key      destinationPath // path is empty unless the series carries its own path
	lastSeen time.Time
}

func NewHTTPPathSeries(limit int, overflow string) *HTTPPathSeries {
	return &HTTPPathSeries{
		limit:      limit,
		overflow:   overflow,
		admitted:   make(map[string]map[string]struct{}),
		candidates: make(map[destinationPath]struct{}),
		series:     make(map[string]*httpSeries),
		refs:       make(map[destinationPath]int),
		destRefs:   make(map[string]int),
	}
}

// Observe returns the label values for one request: labelValues builds them
// from the path label chosen for (destination, path). The series is recorded as
// seen now. full reports that the path was refused because destination already
// labels the limit of paths.
func (h *HTTPPathSeries) Observe(destination, path string, now time.Time, labelValues func(pathLabel string) []string) (values []string, full bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var label string
	label, full = h.pathLabel(destination, path)
	values = labelValues(label)
	k := strings.Join(values, "\x00")
	if s, ok := h.series[k]; ok {
		s.lastSeen = now
		return values, full
	}
	s := &httpSeries{labels: values, lastSeen: now, key: destinationPath{destination: destination}}
	if path != "" && label == path {
		s.key.path = path
		h.refs[s.key]++
	}
	h.series[k] = s
	h.destRefs[destination]++
	return values, full
}

func (h *HTTPPathSeries) pathLabel(destination, path string) (string, bool) {
	if path == "" {
		return path, false
	}
	paths := h.admitted[destination]
	if _, ok := paths[path]; ok {
		return path, false
	}
	if len(paths) >= h.limit {
		return h.overflow, true
	}
	key := destinationPath{destination, path}
	if _, ok := h.candidates[key]; ok {
		delete(h.candidates, key)
		if paths == nil {
			paths = make(map[string]struct{})
			h.admitted[destination] = paths
		}
		paths[path] = struct{}{}
		return path, false
	}
	if len(h.candidates) >= h.limit {
		clear(h.candidates)
	}
	h.candidates[key] = struct{}{}
	return h.overflow, false
}

// Evict calls remove with the label values of every series not seen for longer
// than ttl and stops tracking it. A path whose last series goes is no longer
// labelled, which frees its slot, and a destination whose last series goes is
// forgotten. remove runs under the mutex, so a request for the same series waits
// until it is gone and then starts a new one.
func (h *HTTPPathSeries) Evict(now time.Time, ttl time.Duration, remove func(labelValues []string)) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	evicted := 0
	for k, s := range h.series {
		if now.Sub(s.lastSeen) <= ttl {
			continue
		}
		remove(s.labels)
		delete(h.series, k)
		evicted++
		if s.key.path != "" {
			if h.refs[s.key]--; h.refs[s.key] <= 0 {
				delete(h.refs, s.key)
				delete(h.admitted[s.key.destination], s.key.path)
			}
		}
		if h.destRefs[s.key.destination]--; h.destRefs[s.key.destination] <= 0 {
			delete(h.destRefs, s.key.destination)
			delete(h.admitted, s.key.destination)
		}
	}
	return evicted
}

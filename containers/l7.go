package containers

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

// String interning to reduce memory usage for repeated label values
type stringInterner struct {
	mu    sync.RWMutex
	cache map[string]string
}

var labelInterner = &stringInterner{
	cache: make(map[string]string),
}

func (si *stringInterner) intern(s string) string {
	if s == "" {
		return ""
	}
	
	si.mu.RLock()
	if interned, ok := si.cache[s]; ok {
		si.mu.RUnlock()
		return interned
	}
	si.mu.RUnlock()
	
	si.mu.Lock()
	defer si.mu.Unlock()
	
	// Double-check after acquiring write lock
	if interned, ok := si.cache[s]; ok {
		return interned
	}
	
	// Limit cache size to prevent unbounded growth
	if len(si.cache) > 10000 {
		// Clear half the cache when it gets too large
		newCache := make(map[string]string, 5000)
		for k, v := range si.cache {
			if len(newCache) >= 5000 {
				break
			}
			newCache[k] = v
		}
		si.cache = newCache
	}
	
	si.cache[s] = s
	return s
}

type pathNormalizationRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var (
	httpPathNormalizationRules []pathNormalizationRule
	rulesInitialized           bool
	rulesMutex                 sync.Mutex
)

func initializePathNormalizationRules() {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()
	
	if rulesInitialized {
		return
	}
	
	// Default built-in rules
	defaultRules := []pathNormalizationRule{
		// Generic API resource IDs - matches common ID patterns in REST APIs
		// e.g., /api/users/123, /api/products/ABC123, /v1/orders/uuid-123-abc
		{regexp.MustCompile(`(/api/[^/]+/)[A-Za-z0-9\-_]{3,}`), "${1}{id}"},
		{regexp.MustCompile(`(/v[0-9]+/[^/]+/)[A-Za-z0-9\-_]{3,}`), "${1}{id}"},
		
		// UUIDs in any path segment
		{regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), "/{uuid}"},
		
		// Numeric IDs (3+ digits to avoid false positives like /v1, /api)
		{regexp.MustCompile(`/\d{3,}`), "/{id}"},
		
		// ACME challenge paths
		{regexp.MustCompile(`/\.well-known/acme-challenge/[A-Za-z0-9_-]+`), "/.well-known/acme-challenge/{token}"},
		// Next.js specific pages, e.g., /_next/static/chunks/pages/cart-4042ca3ed7b203d7.js
		{regexp.MustCompile(`/_next/static/chunks/pages/.*-[a-f0-9]{16,}\.js`), "/_next/static/chunks/pages/{page}.js"},
		// Next.js specific chunks, e.g., /_next/static/chunks/framework-123abc.js
		{regexp.MustCompile(`/_next/static/chunks/.*-[a-f0-9]{8,}\.js`), "/_next/static/chunks/{chunk}.js"},
		// Next.js build manifests, e.g., /_next/static/aBcDeF/_buildManifest.js
		{regexp.MustCompile(`/_next/static/[^/]+/_buildManifest\.js`), "/_next/static/{buildID}/_buildManifest.js"},
		{regexp.MustCompile(`/_next/static/[^/]+/_ssgManifest\.js`), "/_next/static/{buildID}/_ssgManifest.js"},
		// Next.js CSS chunks, e.g., /_next/static/css/a1b2c3d4.css
		{regexp.MustCompile(`/_next/static/css/.*\.css`), "/_next/static/css/{stylesheet}.css"},
		// Generic rules for other dynamic paths
		{regexp.MustCompile(`\b[a-fA-F0-9]{8,}\b`), ":hex"},
		{regexp.MustCompile(`\b\d{4,}\b`), ":number"},
	}
	
	httpPathNormalizationRules = defaultRules
	
	// Add custom rules from environment variable
	if customRulesStr := flags.GetString(flags.HttpPathNormalizationRules); customRulesStr != "" {
		for _, ruleStr := range strings.Split(customRulesStr, ",") {
			parts := strings.SplitN(strings.TrimSpace(ruleStr), ":", 2)
			if len(parts) == 2 {
				pattern := strings.TrimSpace(parts[0])
				replacement := strings.TrimSpace(parts[1])
				if compiled, err := regexp.Compile(pattern); err == nil {
					httpPathNormalizationRules = append(httpPathNormalizationRules, pathNormalizationRule{
						pattern:     compiled,
						replacement: replacement,
					})
					klog.Infof("Added custom HTTP path normalization rule: %s -> %s", pattern, replacement)
				} else {
					klog.Warningf("Invalid regex pattern in HTTP path normalization rule: %s", pattern)
				}
			}
		}
	}
	
	rulesInitialized = true
}

func normalizeHttpPath(path string) string {
	// Initialize rules on first use
	if !rulesInitialized {
		initializePathNormalizationRules()
	}
	
	if i := strings.Index(path, "?"); i != -1 {
		path = path[:i]
	}
	for _, rule := range httpPathNormalizationRules {
		path = rule.pattern.ReplaceAllString(path, rule.replacement)
	}
	return path
}

type L7Stats struct {
	requests    map[l7.Protocol]*prometheus.CounterVec
	latency     map[l7.Protocol]*prometheus.HistogramVec
	initialized map[l7.Protocol]bool
}

func NewL7Stats() L7Stats {
	return L7Stats{
		requests:    make(map[l7.Protocol]*prometheus.CounterVec),
		latency:     make(map[l7.Protocol]*prometheus.HistogramVec),
		initialized: make(map[l7.Protocol]bool),
	}
}

func (s L7Stats) observe(protocol l7.Protocol, status, method string, duration time.Duration, key common.DestinationKey, srcWorkload common.Workload, r *l7.RequestData, traceId string) {
	s.ensureInitialized(protocol)

	actualDestWorkload := key.GetActualDestinationWorkload()

	// Convert HTTP2 to HTTP for metrics (same as ensureInitialized)
	metricsProtocol := protocol
	if protocol == l7.ProtocolHTTP2 {
		metricsProtocol = l7.ProtocolHTTP
	}

	// Base labels that all protocols use (with string interning for memory optimization)
	labelValues := []string{
		labelInterner.intern(status),
		labelInterner.intern(key.DestinationLabelValue()),
		labelInterner.intern(key.ActualDestinationLabelValue()),
		labelInterner.intern(key.GetDestinationWorkload().Kind),
		labelInterner.intern(key.GetDestinationWorkload().Name),
		labelInterner.intern(key.GetDestinationWorkload().Namespace),
		labelInterner.intern(srcWorkload.Kind),
		labelInterner.intern(srcWorkload.Name),
		labelInterner.intern(srcWorkload.Namespace),
		labelInterner.intern(actualDestWorkload.Kind),
		labelInterner.intern(actualDestWorkload.Name),
		labelInterner.intern(actualDestWorkload.Namespace),
		labelInterner.intern(srcWorkload.Region),
		labelInterner.intern(srcWorkload.Zone),
		labelInterner.intern(actualDestWorkload.Region),
		labelInterner.intern(actualDestWorkload.Zone),
		labelInterner.intern(actualDestWorkload.Instance),
	}

	// Protocol-specific labels (use metricsProtocol, not original protocol)
	switch metricsProtocol {
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		labelValues = append(labelValues, labelInterner.intern(method))
	case l7.ProtocolHTTP:
		parsedMethod, path := l7.ParseHttp(r.Payload)
		if ValidUtf8([]byte(path)) {
			labelValues = append(labelValues, labelInterner.intern(normalizeHttpPath(path)))
		} else {
			labelValues = append(labelValues, "")
		}
		labelValues = append(labelValues, labelInterner.intern(parsedMethod))
	case l7.ProtocolDNS:
		requestType, domain, _ := l7.ParseDns(r.Payload)
		labelValues = append(labelValues, labelInterner.intern(requestType), labelInterner.intern(common.NormalizeFQDN(domain, requestType)))
	}

	// Update counter
	if counter := s.requests[protocol]; counter != nil {
		if c, err := counter.GetMetricWithLabelValues(labelValues...); err != nil {
			klog.Warningln("Error getting counter metric:", err)
		} else {
			c.Inc()
		}
	}

	// Update histogram
	if histogram := s.latency[protocol]; histogram != nil && duration != 0 {
		if h, err := histogram.GetMetricWithLabelValues(labelValues...); err != nil {
			klog.Warningln("Error getting histogram metric:", err)
		} else {
			h.Observe(duration.Seconds())
		}
	}
}

func (s L7Stats) ensureInitialized(protocol l7.Protocol) {
	if s.initialized[protocol] {
		return
	}

	// Convert HTTP2 to HTTP for metrics
	metricsProtocol := protocol
	if protocol == l7.ProtocolHTTP2 {
		metricsProtocol = l7.ProtocolHTTP
	}

	// Base labels for all protocols
	baseLabels := []string{
		"status",
		"destination",
		"actual_destination",
		"destination_workload_kind",
		"destination_workload_name",
		"destination_workload_namespace",
		"src_workload_kind",
		"src_workload_name",
		"src_workload_namespace",
		"actual_destination_workload_kind",
		"actual_destination_workload_name",
		"actual_destination_workload_namespace",
		"src_region",
		"src_az",
		"destination_region",
		"destination_az",
		"destination_instance",
	}

	// Initialize request counter
	requestLabels := make([]string, len(baseLabels))
	copy(requestLabels, baseLabels)

	// Add protocol-specific labels for requests
	switch metricsProtocol {
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		requestLabels = append(requestLabels, "method")
	case l7.ProtocolHTTP:
		requestLabels = append(requestLabels, "path", "method")
	case l7.ProtocolDNS:
		requestLabels = append(requestLabels, "request_type", "domain")
	}

	if cOpts, exists := L7Requests[metricsProtocol]; exists {
		s.requests[protocol] = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: cOpts.Name, Help: cOpts.Help},
			requestLabels,
		)
	}

	// Initialize latency histogram
	histogramLabels := make([]string, len(baseLabels))
	copy(histogramLabels, baseLabels)

	// For HTTP and DNS, add extra labels to histogram
	switch metricsProtocol {
	case l7.ProtocolHTTP:
		histogramLabels = append(histogramLabels, "path", "method")
	case l7.ProtocolDNS:
		histogramLabels = append(histogramLabels, "request_type", "domain")
	}

	if hOpts, exists := L7Latency[metricsProtocol]; exists {
		s.latency[protocol] = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help},
			histogramLabels,
		)
	}

	s.initialized[protocol] = true
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	for _, counterVec := range s.requests {
		if counterVec != nil {
			counterVec.Collect(ch)
		}
	}
	for _, histogramVec := range s.latency {
		if histogramVec != nil {
			histogramVec.Collect(ch)
		}
	}
}

func (s L7Stats) delete(dst common.HostPort) {
	// With the new architecture, we don't need to delete per-destination metrics
	// since all metrics are shared across destinations with different label values
	// This method can be kept for interface compatibility but doesn't need to do anything
}

func ValidUtf8(payload []byte) bool {
	return utf8.Valid(payload)
}

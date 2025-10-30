package containers

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
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

var (
	uuidRegex       = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	hexRegex        = regexp.MustCompile(`[a-fA-F0-9]{8,}`)
	numericRegex    = regexp.MustCompile(`\d`)
	alphaNumericMix = regexp.MustCompile(`[a-zA-Z].*\d|\d.*[a-zA-Z]`)
)

func normalizeHttpPath(path string) string {
	if i := strings.Index(path, "?"); i != -1 {
		path = path[:i]
	}
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if uuidRegex.MatchString(p) {
			parts[i] = "{uuid}"
			continue
		}
		if _, err := strconv.Atoi(p); err == nil {
			parts[i] = "{id}"
			continue
		}
		if hexRegex.MatchString(p) && len(p) >= 8 {
			parts[i] = "{hex}"
			continue
		}
		if alphaNumericMix.MatchString(p) && len(p) >= 10 {
			parts[i] = "{id}"
			continue
		}
	}
	return strings.Join(parts, "/")
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

	// Protocol-specific labels for counters (keep all labels including path for HTTP)
	counterLabelValues := make([]string, len(labelValues))
	copy(counterLabelValues, labelValues)

	switch metricsProtocol {
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		counterLabelValues = append(counterLabelValues, labelInterner.intern(method))
	case l7.ProtocolHTTP:
		parsedMethod, path := l7.ParseHttp(r.Payload)
		if ValidUtf8([]byte(path)) {
			counterLabelValues = append(counterLabelValues, labelInterner.intern(normalizeHttpPath(path)))
		} else {
			counterLabelValues = append(counterLabelValues, "")
		}
		counterLabelValues = append(counterLabelValues, labelInterner.intern(parsedMethod))
	case l7.ProtocolDNS:
		requestType, domain, _ := l7.ParseDns(r.Payload)
		counterLabelValues = append(counterLabelValues, labelInterner.intern(requestType), labelInterner.intern(common.NormalizeFQDN(domain, requestType)))
	}

	// Protocol-specific labels for histograms (exclude path and method for HTTP, use grouped status to reduce cardinality)
	histogramLabelValues := make([]string, len(labelValues))
	copy(histogramLabelValues, labelValues)
	// Use grouped status codes (2xx, 4xx, etc.) for histograms to reduce cardinality
	histogramLabelValues[0] = labelInterner.intern(groupHttpStatus(labelValues[0]))

	switch metricsProtocol {
	case l7.ProtocolDNS:
		requestType, domain, _ := l7.ParseDns(r.Payload)
		histogramLabelValues = append(histogramLabelValues, labelInterner.intern(requestType), labelInterner.intern(common.NormalizeFQDN(domain, requestType)))
	}

	// Update counter
	if counter := s.requests[protocol]; counter != nil {
		if c, err := counter.GetMetricWithLabelValues(counterLabelValues...); err != nil {
			klog.Warningln("Error getting counter metric:", err)
		} else {
			c.Inc()
		}
	}

	// Update histogram
	if histogram := s.latency[protocol]; histogram != nil && duration != 0 {
		if h, err := histogram.GetMetricWithLabelValues(histogramLabelValues...); err != nil {
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

	// For DNS only, add extra labels to histogram (exclude path and method for HTTP to reduce cardinality)
	switch metricsProtocol {
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

func groupHttpStatus(status string) string {
	if len(status) == 0 {
		return "unknown"
	}

	// Handle HTTP status codes
	if len(status) >= 1 {
		switch status[0] {
		case '2':
			return "2xx"
		case '3':
			return "3xx"
		case '4':
			return "4xx"
		case '5':
			return "5xx"
		default:
			return "other"
		}
	}

	return "unknown"
}

func ValidUtf8(payload []byte) bool {
	return utf8.Valid(payload)
}

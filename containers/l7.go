package containers

import (
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type L7Stats struct {
	requests     map[l7.Protocol]*prometheus.CounterVec
	latency      map[l7.Protocol]*prometheus.HistogramVec
	initialized  map[l7.Protocol]bool
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

	// Base labels that all protocols use
	labelValues := []string{
		status,
		key.DestinationLabelValue(),
		key.ActualDestinationLabelValue(),
		key.GetDestinationWorkload().Kind,
		key.GetDestinationWorkload().Name,
		key.GetDestinationWorkload().Namespace,
		srcWorkload.Kind,
		srcWorkload.Name,
		srcWorkload.Namespace,
		actualDestWorkload.Kind,
		actualDestWorkload.Name,
		actualDestWorkload.Namespace,
	}

	// Add trace_id if present
	if traceId != "" {
		labelValues = append(labelValues, traceId)
	} else {
		labelValues = append(labelValues, "")
	}

	// Protocol-specific labels (use metricsProtocol, not original protocol)
	switch metricsProtocol {
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		labelValues = append(labelValues, method)
	case l7.ProtocolHTTP:
		parsedMethod, path := l7.ParseHttp(r.Payload)
		if ValidUtf8([]byte(path)) {
			labelValues = append(labelValues, path)
		} else {
			labelValues = append(labelValues, "")
		}
		labelValues = append(labelValues, parsedMethod)
	case l7.ProtocolDNS:
		requestType, domain, _ := l7.ParseDns(r.Payload)
		labelValues = append(labelValues, requestType, common.NormalizeFQDN(domain, requestType))
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
		"trace_id",
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
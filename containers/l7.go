package containers

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// path normalization rules are applied in order
	httpPathNormalizationRules = []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
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
)

func normalizeHttpPath(path string) string {
	if i := strings.Index(path, "?"); i != -1 {
		path = path[:i]
	}
	for _, rule := range httpPathNormalizationRules {
		path = rule.pattern.ReplaceAllString(path, rule.replacement)
	}
	return path
}

type L7Stats struct {
	requests *prometheus.CounterVec
	latency  *prometheus.HistogramVec
}

func NewL7Stats() L7Stats {
	return L7Stats{
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "container_l7_requests_total", Help: "L7 requests total"},
			[]string{
				"protocol",
				"status",
				"method",                 // for rabbitmq/nats
				"path",                   // for http
				"request_type", "domain", // for dns
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
			},
		),
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "container_l7_requests_latency_seconds", Help: "L7 requests latency"},
			[]string{
				"protocol",
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
			},
		),
	}
}

func (s L7Stats) observe(protocol l7.Protocol, status, method string, duration time.Duration, key common.DestinationKey, srcWorkload common.Workload, r *l7.RequestData, traceId string) {
	actualDestWorkload := key.GetActualDestinationWorkload()

	protocolStr := protocol.String()
	path, requestType, domain := "", "", ""

	switch protocol {
	case l7.ProtocolHTTP, l7.ProtocolHTTP2:
		protocolStr = l7.ProtocolHTTP.String()
		method, path = l7.ParseHttp(r.Payload)
		if ValidUtf8([]byte(path)) {
			path = normalizeHttpPath(path)
		} else {
			path = ""
		}
	case l7.ProtocolDNS:
		requestType, domain, _ = l7.ParseDns(r.Payload)
		domain = common.NormalizeFQDN(domain, requestType)
	}

	labels := prometheus.Labels{
		"protocol":                              protocolStr,
		"status":                                status,
		"method":                                method,
		"path":                                  path,
		"request_type":                          requestType,
		"domain":                                domain,
		"destination":                           key.DestinationLabelValue(),
		"actual_destination":                    key.ActualDestinationLabelValue(),
		"destination_workload_kind":             key.GetDestinationWorkload().Kind,
		"destination_workload_name":             key.GetDestinationWorkload().Name,
		"destination_workload_namespace":        key.GetDestinationWorkload().Namespace,
		"src_workload_kind":                     srcWorkload.Kind,
		"src_workload_name":                     srcWorkload.Name,
		"src_workload_namespace":                srcWorkload.Namespace,
		"actual_destination_workload_kind":      actualDestWorkload.Kind,
		"actual_destination_workload_name":      actualDestWorkload.Name,
		"actual_destination_workload_namespace": actualDestWorkload.Namespace,
		"src_region":                            srcWorkload.Region,
		"src_az":                                srcWorkload.Zone,
		"destination_region":                    actualDestWorkload.Region,
		"destination_az":                        actualDestWorkload.Zone,
		"destination_instance":                  actualDestWorkload.Instance,
	}
	s.requests.With(labels).Inc()

	if duration > 0 {
		delete(labels, "method")
		delete(labels, "path")
		delete(labels, "request_type")
		delete(labels, "domain")
		s.latency.With(labels).Observe(duration.Seconds())
	}
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	s.requests.Collect(ch)
	s.latency.Collect(ch)
}

func (s L7Stats) delete(dst common.HostPort) {
	// With the new architecture, we don't need to delete per-destination metrics
	// since all metrics are shared across destinations with different label values
	// This method can be kept for interface compatibility but doesn't need to do anything
}

func ValidUtf8(payload []byte) bool {
	return utf8.Valid(payload)
}

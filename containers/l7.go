package containers

import (
	"log"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type L7Metrics struct {
	Requests *prometheus.CounterVec
	Latency  prometheus.Histogram
}

func (m *L7Metrics) observe(status, method string, duration time.Duration) {
	if m.Requests != nil {
		var err error
		var c prometheus.Counter
		if method != "" {
			c, err = m.Requests.GetMetricWithLabelValues(status, method)
		} else {
			c, err = m.Requests.GetMetricWithLabelValues(status)
		}
		if err != nil {
			klog.Warningln(err)
		} else {
			c.Inc()
		}
	}
	if m.Latency != nil && duration != 0 {
		m.Latency.Observe(duration.Seconds())
	}
}

type L7Stats map[l7.Protocol]map[common.DestinationKey]*L7Metrics // protocol -> dst:actual_dst -> metrics

func (s L7Stats) get(protocol l7.Protocol, key common.DestinationKey, r *l7.RequestData, srcWorkload common.Workload, traceId string) *L7Metrics {
	if protocol == l7.ProtocolHTTP2 {
		protocol = l7.ProtocolHTTP
	}
	protoStats := s[protocol]
	if protoStats == nil {
		protoStats = map[common.DestinationKey]*L7Metrics{}
		s[protocol] = protoStats
	}
	m := protoStats[key]
	if m == nil {
		m = &L7Metrics{}
		protoStats[key] = m
		actualDestWorkload := key.GetActualDestinationWorkload()
		
		constLabels := map[string]string{"destination": key.DestinationLabelValue(),
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
		}
		if traceId != "" {
			constLabels["trace_id"] = traceId
		}
		labels := []string{"status"}
		switch protocol {
		case l7.ProtocolRabbitmq, l7.ProtocolNats:
			labels = append(labels, "method")
		case l7.ProtocolHTTP:
			method, path := l7.ParseHttp(r.Payload)
			if ValidUtf8([]byte(path)) {
				constLabels["path"] = path
			} else {
				log.Printf("Failed to parse path %s", path)
			}
			constLabels["method"] = method
			hOpts := L7Latency[protocol]
			m.Latency = prometheus.NewHistogram(
				prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help, ConstLabels: constLabels},
			)
		default:
			hOpts := L7Latency[protocol]
			m.Latency = prometheus.NewHistogram(
				prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help, ConstLabels: constLabels},
			)
		}
		cOpts := L7Requests[protocol]
		m.Requests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: cOpts.Name, Help: cOpts.Help, ConstLabels: constLabels}, labels,
		)
	}
	return m
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	for _, protoStats := range s {
		for _, m := range protoStats {
			if m.Requests != nil {
				m.Requests.Collect(ch)
			}
			if m.Latency != nil {
				m.Latency.Collect(ch)
			}
		}
	}
}

func (s L7Stats) delete(dst common.HostPort) {
	for _, protoStats := range s {
		for d := range protoStats {
			if d.Destination() == dst {
				delete(protoStats, d)
			}
		}
	}
}

func ValidUtf8(payload []byte) bool {
	return utf8.Valid(payload)
}

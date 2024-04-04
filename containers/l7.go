package containers

import (
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	"inet.af/netaddr"
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

type L7Stats map[l7.Protocol]map[AddrPair]*L7Metrics // protocol -> dst:actual_dst -> metrics

func (s L7Stats) get(protocol l7.Protocol, destination, actualDestination netaddr.IPPort, r *l7.RequestData, srcWorkload common.Workload, dstWorkload common.Workload, actualDstWorkload common.Workload) *L7Metrics {
	if protocol == l7.ProtocolHTTP2 {
		protocol = l7.ProtocolHTTP
	}
	protoStats := s[protocol]
	if protoStats == nil {
		protoStats = map[AddrPair]*L7Metrics{}
		s[protocol] = protoStats
	}
	dest := AddrPair{src: destination, dst: actualDestination, srcWorkload: srcWorkload, dstWorkload: dstWorkload, actualDestWorkload: actualDstWorkload}
	m := protoStats[dest]
	if m == nil {
		m = &L7Metrics{}
		protoStats[dest] = m
		constLabels := map[string]string{"destination": destination.String(),
			"actual_destination":                    actualDestination.String(),
			"destination_workload_kind":             dstWorkload.Kind,
			"destination_workload_name":             dstWorkload.Name,
			"destination_workload_namespace":        dstWorkload.Namespace,
			"src_kind":                              srcWorkload.Kind,
			"src_workload_name":                     srcWorkload.Name,
			"src_workload_namespace":                srcWorkload.Namespace,
			"actual_destination_workload_kind":      actualDstWorkload.Kind,
			"actual_destination_workload_name":      actualDstWorkload.Name,
			"actual_destination_workload_namespace": actualDstWorkload.Namespace,
		}
		labels := []string{"status"}
		switch protocol {
		case l7.ProtocolRabbitmq, l7.ProtocolNats:
			labels = append(labels, "method")
		case l7.ProtocolHTTP:
			method, path := l7.ParseHttp(r.Payload)
			constLabels["path"] = path
			constLabels["method"] = method
			if dstWorkload.Namespace == "external" {
				request, error := l7.ParseHttpRequest(string(r.Payload))
				if error == nil {
					constLabels["destination_workload_name"] = request.Host
				}
			}
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

func (s L7Stats) delete(dst netaddr.IPPort) {
	for _, protoStats := range s {
		for d := range protoStats {
			if d.src == dst {
				delete(protoStats, d)
			}
		}
	}
}

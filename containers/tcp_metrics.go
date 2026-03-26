package containers

import (
	"strings"
	"sync"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/prometheus/client_golang/prometheus"
)

// TCPMetrics holds pre-registered CounterVec/GaugeVec for TCP connection metrics.
// Event handlers update these directly (lock-free for scrapes).
// Collect() just forwards pre-built metrics without holding c.lock.
type TCPMetrics struct {
	mu sync.RWMutex // protects initialization and eviction vs collect

	successful  *prometheus.CounterVec
	totalTime   *prometheus.CounterVec
	failed      *prometheus.CounterVec
	retransmits *prometheus.CounterVec
	bytesSent   *prometheus.CounterVec
	bytesRecv   *prometheus.CounterVec
	active      *prometheus.GaugeVec
	restarts    prometheus.Counter
	oomKills    prometheus.Counter

	// knownLabels tracks label combinations pushed to the 11-label CounterVecs.
	// Key is null-byte-joined label values; value is the original slice for DeleteLabelValues.
	// Written only from the event handler goroutine (no extra lock needed for writes).
	knownLabels map[string][]string

	// knownFailedLabels tracks label combinations pushed to the 7-label failed CounterVec.
	knownFailedLabels map[string][]string

	constLabels prometheus.Labels
	initialized bool
}

// tcpVarLabels are shared across most TCP connection metrics (11 labels).
var tcpVarLabels = []string{
	"destination", "actual_destination",
	"src_workload_name", "src_workload_namespace", "src_workload_kind",
	"destination_workload_name", "destination_workload_namespace", "destination_workload_kind",
	"actual_destination_workload_name", "actual_destination_workload_namespace", "actual_destination_workload_kind",
}

// tcpFailedVarLabels are used for failed connection metrics (7 labels).
var tcpFailedVarLabels = []string{
	"destination",
	"destination_workload_name", "destination_workload_namespace", "destination_workload_kind",
	"actual_destination_workload_name", "actual_destination_workload_namespace", "actual_destination_workload_kind",
}

func NewTCPMetrics(constLabels prometheus.Labels) *TCPMetrics {
	return &TCPMetrics{
		constLabels: constLabels,
	}
}

func (t *TCPMetrics) ensureInitialized() {
	t.mu.RLock()
	if t.initialized {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initialized {
		return
	}

	cl := t.constLabels

	t.successful = newCounterVec("container_net_tcp_successful_connects_total", "Total number of successful TCP connects", cl, tcpVarLabels...)
	t.totalTime = newCounterVec("container_net_tcp_connection_time_seconds_total", "Time spent on TCP connections", cl, tcpVarLabels...)
	t.failed = newCounterVec("container_net_tcp_failed_connects_total", "Total number of failed TCP connects", cl, tcpFailedVarLabels...)
	t.retransmits = newCounterVec("container_net_tcp_retransmits_total", "Total number of retransmitted TCP segments", cl, tcpVarLabels...)
	t.bytesSent = newCounterVec("container_net_tcp_bytes_sent_total", "Total number of bytes sent to the peer", cl, tcpVarLabels...)
	t.bytesRecv = newCounterVec("container_net_tcp_bytes_received_total", "Total number of bytes received from the peer", cl, tcpVarLabels...)
	t.active = newGaugeVec("container_net_tcp_active_connections", "Number of active outbound connections used by the container", cl, tcpVarLabels...)
	t.restarts = newCounter("container_restarts_total", "Number of times the container was restarted", cl)
	t.oomKills = newCounter("container_oom_kills_total", "Total number of times the container was terminated by the OOM killer", cl)

	t.knownLabels = make(map[string][]string)
	t.knownFailedLabels = make(map[string][]string)
	t.initialized = true
}

// labelKey produces a map key from a label slice using null-byte separator.
func labelKey(labels []string) string {
	return strings.Join(labels, "\x00")
}

// trackLabels records a label combination for the 11-label CounterVecs.
// Only called from the event handler goroutine — no extra lock needed.
func (t *TCPMetrics) trackLabels(labels []string) {
	k := labelKey(labels)
	if _, exists := t.knownLabels[k]; !exists {
		t.knownLabels[k] = labels
	}
}

// trackFailedLabels records a label combination for the 7-label failed CounterVec.
func (t *TCPMetrics) trackFailedLabels(labels []string) {
	k := labelKey(labels)
	if _, exists := t.knownFailedLabels[k]; !exists {
		t.knownFailedLabels[k] = labels
	}
}

// tcpLabels builds the 11-label value slice for TCP metrics.
func tcpLabels(key common.DestinationKey, src common.Workload) []string {
	dest := key.GetDestinationWorkload()
	actualDest := key.GetActualDestinationWorkload()
	return []string{
		key.DestinationLabelValue(), key.ActualDestinationLabelValue(),
		src.Name, src.Namespace, src.Kind,
		dest.Name, dest.Namespace, dest.Kind,
		actualDest.Name, actualDest.Namespace, actualDest.Kind,
	}
}

// ObserveConnectionOpen records a successful connection open.
func (t *TCPMetrics) ObserveConnectionOpen(key common.DestinationKey, src common.Workload, durationSeconds float64) {
	t.ensureInitialized()
	labels := tcpLabels(key, src)
	t.trackLabels(labels)
	t.successful.WithLabelValues(labels...).Inc()
	t.totalTime.WithLabelValues(labels...).Add(durationSeconds)
}

// ObserveConnectionFailed records a failed connection attempt.
func (t *TCPMetrics) ObserveConnectionFailed(dst common.HostPort, workload common.Workload) {
	t.ensureInitialized()
	labels := []string{
		dst.String(),
		workload.Name, workload.Namespace, workload.Kind,
		workload.Name, workload.Namespace, workload.Kind,
	}
	t.trackFailedLabels(labels)
	t.failed.WithLabelValues(labels...).Inc()
}

// ObserveRetransmission records a TCP retransmission.
func (t *TCPMetrics) ObserveRetransmission(key common.DestinationKey, src common.Workload) {
	t.ensureInitialized()
	labels := tcpLabels(key, src)
	t.trackLabels(labels)
	t.retransmits.WithLabelValues(labels...).Inc()
}

// ObserveTraffic records byte count deltas for a connection.
func (t *TCPMetrics) ObserveTraffic(key common.DestinationKey, src common.Workload, sentDelta, recvDelta uint64) {
	t.ensureInitialized()
	labels := tcpLabels(key, src)
	t.trackLabels(labels)
	if sentDelta > 0 {
		t.bytesSent.WithLabelValues(labels...).Add(float64(sentDelta))
	}
	if recvDelta > 0 {
		t.bytesRecv.WithLabelValues(labels...).Add(float64(recvDelta))
	}
}

// resetAndSetActive replaces all active connection gauge values.
// Called from the event handler goroutine periodically.
func (t *TCPMetrics) resetAndSetActive(entries []activeEntry) {
	t.ensureInitialized()
	t.active.Reset()
	for _, e := range entries {
		t.active.WithLabelValues(e.labels...).Set(float64(e.count))
	}
}

// activeEntry holds pre-computed label values and count for active connections.
type activeEntry struct {
	labels []string
	count  int
}

// ObserveRestart increments the restart counter.
func (t *TCPMetrics) ObserveRestart() {
	t.ensureInitialized()
	t.restarts.Inc()
}

// ObserveOOMKill increments the OOM kill counter.
func (t *TCPMetrics) ObserveOOMKill() {
	t.ensureInitialized()
	t.oomKills.Inc()
}

// EvictStaleLabels removes CounterVec entries for label combinations that are
// no longer active. activeKeys contains labelKey() values for currently open
// connections. activeFailedDsts contains destination strings (labels[0]) for
// destinations still in lastConnectionAttempts.
// Must be called from the event handler goroutine. Takes mu.Lock to exclude
// concurrent collect() calls during eviction.
func (t *TCPMetrics) EvictStaleLabels(activeKeys map[string]struct{}, activeFailedDsts map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized {
		return
	}

	for k, labels := range t.knownLabels {
		if _, active := activeKeys[k]; !active {
			t.successful.DeleteLabelValues(labels...)
			t.totalTime.DeleteLabelValues(labels...)
			t.retransmits.DeleteLabelValues(labels...)
			t.bytesSent.DeleteLabelValues(labels...)
			t.bytesRecv.DeleteLabelValues(labels...)
			delete(t.knownLabels, k)
		}
	}

	for k, labels := range t.knownFailedLabels {
		// labels[0] is the destination string
		if _, active := activeFailedDsts[labels[0]]; !active {
			t.failed.DeleteLabelValues(labels...)
			delete(t.knownFailedLabels, k)
		}
	}
}

// collect forwards all pre-built metrics to the channel. No c.lock needed.
func (t *TCPMetrics) collect(ch chan<- prometheus.Metric) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.initialized {
		return
	}
	t.successful.Collect(ch)
	t.totalTime.Collect(ch)
	t.failed.Collect(ch)
	t.retransmits.Collect(ch)
	t.bytesSent.Collect(ch)
	t.bytesRecv.Collect(ch)
	t.active.Collect(ch)
	t.restarts.Collect(ch)
	t.oomKills.Collect(ch)
}

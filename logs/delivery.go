package logs

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// Delivery: the log files are the buffer. A reader reads on only while few records
// are waiting for the collector, and a file's position is saved only up to the lines
// whose records the collector has accepted, so an agent restart or a collector or
// ClickHouse outage delays lines rather than dropping them. Delivery is at least
// once: lines read again after a restart are sent again.
//
// The accounting relies on the batch processor exporting records in the order they
// were emitted, one batch at a time, never dropping one (WithBlocking) and never
// adding one (ForceFlush, which enqueues a marker, is never called): the n-th record
// exported is the n-th emitted. Records emitted after its Shutdown are dropped
// without being counted, which only happens as the agent exits, after the final save.

const (
	// A reader waits while this many records, or bytes of message text, are waiting.
	// The queue holds 4x as many records, so the overshoot (a line per reader plus a
	// message per parser) never fills it, and emitting, which the parser does while
	// holding the lock its metrics are read under, never blocks.
	maxPendingRecords = 2048
	maxPendingBytes   = 16 << 20
	queueSize         = 4 * maxPendingRecords
	// Records from a source no reader can pause (journald) are dropped past this
	// many pending records, which keeps the queue from filling while the collector
	// is down: such a source was at most once before and has no saved position.
	maxPendingUnpaused = 2 * maxPendingRecords

	maxRetryInterval = 30 * time.Second
)

var dlv *delivery

type pendingRecord struct {
	src    *Source
	offset int64
	bytes  int
}

type delivery struct {
	emitMu sync.Mutex // orders emits: the queue order is the order of pending

	mu       sync.Mutex
	pending  []pendingRecord
	bytes    int
	stopping bool
	changed  chan struct{} // closed and replaced whenever pending shrinks or stopping is set

	dropped atomic.Uint64
	dropLog rate.Sometimes
}

func newDelivery() *delivery {
	return &delivery{changed: make(chan struct{}), dropLog: rate.Sometimes{Interval: time.Minute}}
}

// Why a record is dropped: from a source no reader can pause while many records
// are pending, or once the agent is stopping; or the collector rejected it, or
// answered in a way resending would not change (see transient).
const (
	dropBackpressure = "backpressure"
	dropShutdown     = "shutdown"
	dropRejected     = "rejected"
)

// RecordsDroppedTotal counts the log records dropped without being delivered, by
// reason (see dropBackpressure).
var RecordsDroppedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "node_agent_log_records_dropped_total",
		Help: "Log records dropped without being delivered to the logs collector, by reason",
	},
	[]string{"reason"},
)

// drop counts n records dropped for reason and returns how many were dropped so far.
func (d *delivery) drop(reason string, n int) uint64 {
	RecordsDroppedTotal.WithLabelValues(reason).Add(float64(n))
	return d.dropped.Add(uint64(n))
}

// emit records a message from src whose last line ends at offset (see Source), then
// calls send, which emits its record, in the same order. A message from no file
// (src nil) is dropped instead while many records are pending, and once the agent
// is stopping: no reader pauses it, so the drain would otherwise wait for records
// that keep arriving.
func (d *delivery) emit(src *Source, offset int64, bytes int, send func()) {
	d.emitMu.Lock()
	defer d.emitMu.Unlock()
	d.mu.Lock()
	if src == nil && (d.stopping || len(d.pending) >= maxPendingUnpaused) {
		stopping, pending := d.stopping, len(d.pending)
		d.mu.Unlock()
		if stopping {
			d.drop(dropShutdown, 1)
			return
		}
		dropped := d.drop(dropBackpressure, 1)
		d.dropLog.Do(func() {
			klog.Warningf("dropping journald log records while %d records wait for the logs collector (%d log records dropped so far)", pending, dropped)
		})
		return
	}
	d.pending = append(d.pending, pendingRecord{src: src, offset: offset, bytes: bytes})
	d.bytes += bytes
	d.mu.Unlock()
	send()
}

// done marks the oldest n pending records as delivered or permanently rejected and
// acknowledges their sources' offsets.
func (d *delivery) done(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n = min(n, len(d.pending))
	for _, r := range d.pending[:n] {
		d.bytes -= r.bytes
		if r.src != nil {
			r.src.ack(r.offset)
		}
	}
	d.pending = d.pending[n:]
	if len(d.pending) == 0 {
		d.pending = nil // let the backing array go
	}
	close(d.changed)
	d.changed = make(chan struct{})
}

// wait blocks until a reader may read another line. It returns false when ctx is
// done; while the agent is stopping it blocks until then.
func (d *delivery) wait(ctx context.Context) bool {
	for {
		d.mu.Lock()
		ok := !d.stopping && len(d.pending) < maxPendingRecords && d.bytes < maxPendingBytes
		changed := d.changed
		d.mu.Unlock()
		if ok {
			return true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

// stopReading stops every reader at its next line.
func (d *delivery) stopReading() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopping = true
	close(d.changed)
	d.changed = make(chan struct{})
}

// drain waits until every pending record is done or ctx ends, and reports whether
// everything was done.
func (d *delivery) drain(ctx context.Context) bool {
	for {
		d.mu.Lock()
		empty := len(d.pending) == 0
		changed := d.changed
		d.mu.Unlock()
		if empty {
			return true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

func (d *delivery) pendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

// retryingExporter retries a batch until the collector accepts it or the agent
// stops, when resending it may succeed (see transient). The OTLP client itself
// retries 429 and 503, with no time limit (see newExporter). Any other failure
// drops the batch: resending it would fail the same way, sending it each time.
// Either way the batch is then done.
type retryingExporter struct {
	next  sdk.LogRecordExporter
	d     *delivery
	stopC chan struct{}
	stopO sync.Once
}

func newRetryingExporter(next sdk.LogRecordExporter, d *delivery) *retryingExporter {
	return &retryingExporter{next: next, d: d, stopC: make(chan struct{})}
}

func (e *retryingExporter) Export(ctx context.Context, batch []sdk.ReadableLogRecord) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-e.stopC:
			cancel()
		case <-ctx.Done():
		}
	}()
	interval := time.Second
	for attempt := 1; ; attempt++ {
		err := e.next.Export(ctx, batch)
		if err == nil {
			if attempt > 1 {
				klog.Infof("delivered %d log records after %d attempts", len(batch), attempt)
			}
			e.d.done(len(batch))
			return nil
		}
		if ctx.Err() != nil { // stopping: the records stay pending, their lines unacknowledged
			return err
		}
		if !transient(err) {
			dropped := e.d.drop(dropRejected, len(batch))
			klog.Errorf("the logs collector did not accept %d log records and resending them would fail the same way, dropping them (%d dropped so far): %s", len(batch), dropped, err)
			e.d.done(len(batch))
			return err
		}
		if attempt == 1 || attempt%10 == 0 {
			klog.Warningf("failed to send %d log records (attempt %d), retrying: %s", len(batch), attempt, err)
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return err
		}
		interval = min(2*interval, maxRetryInterval)
	}
}

// httpStatus finds the status in the OTLP client's error for a response it does not
// retry itself: "failed to send to <url>: <status code> <status text>", where the
// status text is missing if the collector's status line has no reason phrase.
var httpStatus = regexp.MustCompile(`^failed to send to \S+: (\d{3})\b`)

// clientRetryable is the text of the error the OTLP client wraps when its own retries
// of a 429 or 503 give up (its type is not exported).
const clientRetryable = "retry-able request failure"

// transient reports whether resending a batch that failed with err may succeed: the
// request failed (the collector refused, reset or timed out the connection, or its
// name did not resolve), or the collector answered 408, 429 or a 5xx (a proxy's 502
// or 504 while it restarts). Any other error, including one not recognised, such as
// a 200 whose body is not an OTLP response (the endpoint is another server), is not.
func transient(err error) bool {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return true
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == clientRetryable {
			return true
		}
	}
	m := httpStatus.FindStringSubmatch(err.Error())
	if m == nil {
		return false
	}
	code, _ := strconv.Atoi(m[1])
	return code >= 500 || code == http.StatusRequestTimeout || code == http.StatusTooManyRequests
}

// stop makes a running Export return without delivering its batch.
func (e *retryingExporter) stop() { e.stopO.Do(func() { close(e.stopC) }) }

func (e *retryingExporter) Shutdown(ctx context.Context) error {
	e.stop()
	return e.next.Shutdown(ctx)
}

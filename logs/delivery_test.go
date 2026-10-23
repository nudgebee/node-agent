package logs

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/nudgebee/logparser"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// heldExporter records the bodies it exports; while held, Export waits.
type heldExporter struct {
	mu     sync.Mutex
	bodies []string
	held   chan struct{} // closed: not held
	calls  atomic.Int64
}

func newHeldExporter(held bool) *heldExporter {
	e := &heldExporter{held: make(chan struct{})}
	if !held {
		close(e.held)
	}
	return e
}

func (e *heldExporter) release() { close(e.held) }

func (e *heldExporter) Export(ctx context.Context, records []sdk.ReadableLogRecord) error {
	e.calls.Add(1)
	select {
	case <-e.held:
	case <-ctx.Done():
		return ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.bodies = append(e.bodies, bodyOf(r))
	}
	return nil
}

func (e *heldExporter) Shutdown(context.Context) error { return nil }

func (e *heldExporter) got() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.bodies...)
}

func bodyOf(r sdk.ReadableLogRecord) string {
	switch b := r.Body().(type) {
	case *string:
		return *b
	case string:
		return b
	}
	return fmt.Sprint(r.Body())
}

// withDelivery sets up delivery through exporter as Init does, keeping positions in
// positionsFile unless it is "".
func withDelivery(t *testing.T, exporter sdk.LogRecordExporter, positionsFile string) {
	t.Helper()
	prevDlv, prevRetrying, prevPositions, prevLogger, prevPoll := dlv, retrying, savedPositions, otelLogger, tailPollInterval
	t.Setenv("OTEL_BLRP_SCHEDULE_DELAY", "100") // batches every 100 ms instead of 5 s
	savedPositions = nil
	if positionsFile != "" {
		p, err := loadPositions(positionsFile, 0)
		require.NoError(t, err)
		savedPositions = p
	}
	provider := startDelivery(exporter, resource.Empty())
	otelLogger = provider.Logger("test")
	tailPollInterval = 50 * time.Millisecond
	t.Cleanup(func() {
		retrying.stop()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = provider.Shutdown(ctx)
		dlv, retrying, savedPositions, otelLogger, tailPollInterval = prevDlv, prevRetrying, prevPositions, prevLogger, prevPoll
	})
}

// pipeline reads path the way a container's stdout is read: a TailReader into a
// parser whose messages OtelLogEmitter exports.
func pipeline(t *testing.T, path string, multilineTimeout time.Duration) *logparser.Parser {
	t.Helper()
	ch := make(chan logparser.LogEntry)
	r, err := NewTailReader(path, ch)
	require.NoError(t, err)
	p := logparser.NewParser(ch, nil, OtelLogEmitter("/k8s/ns/pod/app", nil, r.Source()), multilineTimeout, 256, false, rate.NewLimiter(rate.Inf, 1), logparser.SensitiveConfig{})
	t.Cleanup(func() {
		r.Stop()
		p.Stop()
	})
	return p
}

func numberedLines(from, to int) string {
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(s)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// While the collector does not accept records, readers stop reading (the lines wait
// in the file) before the queue fills, so emitting never blocks the parser, whose
// counters the metrics endpoint reads under the same lock. Once the collector is
// back every line is delivered, once and in order.
func TestReadersWaitWhileCollectorIsDown(t *testing.T) {
	exp := newHeldExporter(true)
	withDelivery(t, exp, "")
	path := filepath.Join(t.TempDir(), "0.log")
	writeFile(t, path, "")
	p := pipeline(t, path, 20*time.Millisecond)

	const n = 3 * maxPendingRecords
	writeFile(t, path, numberedLines(1, n))
	assert.Eventually(t, func() bool { return dlv.pendingCount() >= maxPendingRecords }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	pending := dlv.pendingCount()
	assert.Less(t, pending, queueSize, "the queue never fills, so emitting never blocks")
	assert.Less(t, pending, n, "lines past the limit wait in the file")

	counters := make(chan []logparser.LogCounter, 1)
	go func() { counters <- p.GetCounters() }()
	select {
	case <-counters:
	case <-time.After(time.Second):
		t.Fatal("the parser's counters are blocked")
	}

	exp.release()
	assert.Eventually(t, func() bool { return len(exp.got()) == n }, 10*time.Second, 20*time.Millisecond)
	got := exp.got()
	for i, body := range got {
		require.Equal(t, fmt.Sprintf("line %d", i+1), body)
	}
	assert.Equal(t, 0, dlv.pendingCount())
}

// A position is saved only up to lines whose records were delivered: not past
// records the collector has not accepted, nor past a message still collecting lines.
func TestSavedPositionIsDelivered(t *testing.T) {
	exp := newHeldExporter(true)
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	withDelivery(t, exp, positionsFile)
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, "")
	pipeline(t, path, 300*time.Millisecond)

	first := "first message\n"
	writeFile(t, path, first)
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	require.NoError(t, savedPositions.save())
	assert.Equal(t, int64(0), savedOffset(t, positionsFile, path), "nothing delivered yet")

	exp.release()
	assert.Eventually(t, func() bool { return len(exp.got()) == 1 }, 2*time.Second, 5*time.Millisecond)
	require.NoError(t, savedPositions.save())
	assert.Equal(t, int64(len(first)), savedOffset(t, positionsFile, path))

	// A stack trace still being written is not delivered, so not saved past.
	writeFile(t, path, "panic: boom\n\tat a\n")
	time.Sleep(150 * time.Millisecond) // read, but within the multiline timeout
	require.NoError(t, savedPositions.save())
	assert.Equal(t, int64(len(first)), savedOffset(t, positionsFile, path))
	writeFile(t, path, "\tat b\nnext message\n")
	assert.Eventually(t, func() bool { return len(exp.got()) == 3 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, savedPositions.save())
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, info.Size(), savedOffset(t, positionsFile, path))
	assert.Equal(t, []string{"first message", "panic: boom\n\tat a\n\tat b", "next message"}, exp.got())
}

// A saved position without a reader is kept while its file is there, and dropped
// once the file is gone, also when it was replaced and then removed.
func TestSaveDropsPositionsOfGoneFiles(t *testing.T) {
	dir := t.TempDir()
	kept, gone, replaced := filepath.Join(dir, "kept.log"), filepath.Join(dir, "gone.log"), filepath.Join(dir, "replaced.log")
	p, err := loadPositions(filepath.Join(dir, "positions.json"), 0)
	require.NoError(t, err)
	for _, path := range []string{kept, gone, replaced} {
		writeFile(t, path, "a line\n")
		dev, ino, _, err := fileID(path)
		require.NoError(t, err)
		p.saved[path] = savedPosition{Dev: dev, Ino: ino, Offset: 7}
	}
	require.NoError(t, os.Remove(gone))
	// Rotated away: the old file still exists, so the new one cannot reuse its inode.
	require.NoError(t, os.Rename(replaced, replaced+".1"))
	writeFile(t, replaced, "a new file\n")
	_, ino, _, err := fileID(replaced)
	require.NoError(t, err)
	require.NotEqual(t, p.saved[replaced].Ino, ino)
	require.NoError(t, os.Remove(replaced+".1")) // gzipped at the next rotation

	require.NoError(t, p.save())
	reloaded, err := loadPositions(p.file, 0)
	require.NoError(t, err)
	assert.Equal(t, map[string]savedPosition{kept: p.saved[kept]}, reloaded.saved)
}

// A file rotated while the agent was down keeps its saved position until a reader
// for its path starts, however long the agent takes to find the container: the
// saves meanwhile do not take it for gone, so the reader reads its last lines.
func TestSaveKeepsRotatedFileForItsReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, numberedLines(1, 10))
	dev, ino, _, err := fileID(path)
	require.NoError(t, err)
	p, err := loadPositions(filepath.Join(dir, "positions.json"), 0)
	require.NoError(t, err)
	delivered := int64(len(numberedLines(1, 2)))
	p.saved[path] = savedPosition{Dev: dev, Ino: ino, Offset: delivered}

	require.NoError(t, os.Rename(path, path+".20261023-124435"))
	writeFile(t, path, numberedLines(11, 12))
	require.NoError(t, p.save()) // every 10 s while the agent finds the containers
	require.NoError(t, p.save())
	reloaded, err := loadPositions(p.file, 0)
	require.NoError(t, err)
	assert.Equal(t, savedPosition{Dev: dev, Ino: ino, Offset: delivered}, reloaded.saved[path])

	newDev, newIno, _, err := fileID(path)
	require.NoError(t, err)
	f, _, offset := p.rotatedFile(path, newDev, newIno)
	require.NotNil(t, f, "the rotated file is found again")
	defer f.Close()
	assert.Equal(t, delivered, offset)
	rest, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, numberedLines(3, 10), string(rest))
}

func savedOffset(t *testing.T, positionsFile, path string) int64 {
	t.Helper()
	p, err := loadPositions(positionsFile, 0)
	require.NoError(t, err)
	sp, ok := p.saved[path]
	require.True(t, ok, "no saved position for %s", path)
	return sp.Offset
}

// After a restart the agent resumes where delivery stopped: lines written while it
// was down are delivered, lines delivered before are not sent again.
func TestRestartResumesFromSavedPosition(t *testing.T) {
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, numberedLines(1, 10))

	// First run on the node (no positions file): only new lines.
	exp := newHeldExporter(false)
	withDelivery(t, exp, positionsFile)
	ch := make(chan logparser.LogEntry)
	r, err := NewTailReader(path, ch)
	require.NoError(t, err)
	p := logparser.NewParser(ch, nil, OtelLogEmitter("/k8s/ns/pod/app", nil, r.Source()), 20*time.Millisecond, 256, false, nil, logparser.SensitiveConfig{})
	writeFile(t, path, numberedLines(11, 20))
	assert.Eventually(t, func() bool { return len(exp.got()) == 10 }, 3*time.Second, 10*time.Millisecond)
	assert.Equal(t, "line 11", exp.got()[0])
	Shutdown(5 * time.Second) // what SIGTERM does
	r.Stop()
	p.Stop()

	writeFile(t, path, numberedLines(21, 30)) // while the agent is down

	exp2 := newHeldExporter(false)
	withDelivery(t, exp2, positionsFile)
	pipeline(t, path, 20*time.Millisecond)
	assert.Eventually(t, func() bool { return len(exp2.got()) == 10 }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	got := exp2.got()
	require.Len(t, got, 10)
	assert.Equal(t, "line 21", got[0])
	assert.Equal(t, "line 30", got[9])

	// A file the agent has not seen before, once it has run on the node, is read
	// from its start: a container that started while the agent was down.
	other := filepath.Join(dir, "1.log")
	writeFile(t, other, numberedLines(1, 3))
	exp2.mu.Lock()
	exp2.bodies = nil
	exp2.mu.Unlock()
	pipeline(t, other, 20*time.Millisecond)
	assert.Eventually(t, func() bool { return len(exp2.got()) == 3 }, 3*time.Second, 10*time.Millisecond)
}

func TestStartOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, numberedLines(1, 10))
	dev, ino, size, err := fileID(path)
	require.NoError(t, err)

	var none *positions
	assert.Equal(t, size, none.startOffset(path, dev, ino, size), "positions off: new lines only, as before")

	none.initialScanDone()
	assert.Equal(t, size, none.startOffset(path, dev, ino, size), "positions off: new lines only, also after the initial scan")

	firstRun := &positions{saved: map[string]savedPosition{}}
	assert.Equal(t, size, firstRun.startOffset(path, dev, ino, size), "first run on the node: new lines only")
	firstRun.initialScanDone()
	assert.Equal(t, int64(0), firstRun.startOffset(filepath.Join(dir, "1.log"), dev, ino+2, size), "first run, found after the initial scan: from its start")

	ran := &positions{existed: true, saved: map[string]savedPosition{path: {Dev: dev, Ino: ino, Offset: 7}}}
	for _, scanned := range []bool{false, true} {
		if scanned {
			ran.initialScanDone()
		}
		assert.Equal(t, int64(7), ran.startOffset(path, dev, ino, size))
		assert.Equal(t, int64(0), ran.startOffset(path, dev, ino+1, size), "another file at the path: from its start")
		assert.Equal(t, int64(0), ran.startOffset(path, dev, ino, 5), "truncated: from its start")
		assert.Equal(t, int64(0), ran.startOffset(filepath.Join(dir, "1.log"), dev, ino+2, size), "unknown file: from its start")
	}
}

// On the agent's first run on a node the files there when it starts are read from
// their end, so lines from before it was installed are not sent, but files found
// after its initial container scan (a container started since, or a crash-looping
// container's next log file) from their start, as once it has run on the node.
func TestFirstRunReadsFilesFoundAfterTheInitialScanFromTheirStart(t *testing.T) {
	dir := t.TempDir()
	exp := newHeldExporter(false)
	withDelivery(t, exp, filepath.Join(dir, "positions.json"))
	present := filepath.Join(dir, "0.log")
	writeFile(t, present, "before 1\nbefore 2\n")
	pipeline(t, present, 20*time.Millisecond)
	InitialScanDone()

	started := filepath.Join(dir, "1.log")
	writeFile(t, started, "startup 1\nstartup 2\n")
	pipeline(t, started, 20*time.Millisecond)
	writeFile(t, present, "after 1\n")
	assert.Eventually(t, func() bool { return len(exp.got()) == 3 }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	assert.ElementsMatch(t, []string{"startup 1", "startup 2", "after 1"}, exp.got())
}

// A positions file saved longer ago than the maximum age is ignored, as on the
// agent's first run on the node: after a long downtime, or the logs endpoint
// disabled for a while, the files' old lines are not sent in a burst.
func TestStalePositionsFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "positions.json")
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, numberedLines(1, 10))
	dev, ino, size, err := fileID(path)
	require.NoError(t, err)
	p, err := loadPositions(file, time.Hour)
	require.NoError(t, err)
	p.saved[path] = savedPosition{Dev: dev, Ino: ino, Offset: 7}
	require.NoError(t, p.save())

	var pf positionsFile
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &pf))
	assert.WithinDuration(t, time.Now(), pf.SavedAt, time.Minute, "the file carries when it was saved")

	fresh, err := loadPositions(file, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(7), fresh.startOffset(path, dev, ino, size))

	pf.SavedAt = time.Now().Add(-2 * time.Hour)
	data, err = json.Marshal(pf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, data, 0o644))
	stale, err := loadPositions(file, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, size, stale.startOffset(path, dev, ino, size), "stale: new lines only")
	stale.initialScanDone()
	assert.Equal(t, int64(0), stale.startOffset(filepath.Join(dir, "1.log"), dev, ino+1, size), "then as on a first run")

	unchecked, err := loadPositions(file, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(7), unchecked.startOffset(path, dev, ino, size), "0: no maximum age")
}

// A positions file written before it carried when it was saved is aged by its
// modification time.
func TestStalePositionsFileWithoutSaveTime(t *testing.T) {
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, numberedLines(1, 10))
	dev, ino, size, err := fileID(path)
	require.NoError(t, err)
	writeFile(t, positionsFile, fmt.Sprintf(`{"files":{%q:{"dev":%d,"ino":%d,"offset":7}}}`, path, dev, ino))

	fresh, err := loadPositions(positionsFile, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(7), fresh.startOffset(path, dev, ino, size))

	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(positionsFile, old, old))
	stale, err := loadPositions(positionsFile, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, size, stale.startOffset(path, dev, ino, size), "stale: new lines only")
}

// When the runtime moves to a new file (log rotation), the lines it wrote to the old
// one after the last read are read before the new file's.
func TestRotationReadsTheOldFileToItsEnd(t *testing.T) {
	exp := newHeldExporter(false)
	withDelivery(t, exp, "")
	path := filepath.Join(t.TempDir(), "0.log")
	writeFile(t, path, "")
	pipeline(t, path, 20*time.Millisecond)

	old, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	defer old.Close()
	_, err = old.WriteString("a\n")
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return len(exp.got()) == 1 }, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, os.Rename(path, path+".1"))
	_, err = old.WriteString("b\nc\n") // still writing to the rotated file
	require.NoError(t, err)
	writeFile(t, path, "d\n")
	assert.Eventually(t, func() bool { return len(exp.got()) == 4 }, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"a", "b", "c", "d"}, exp.got())
}

// rotateAs renames path as the kubelet rotates a container log file, after gzipping
// the files rotated before, and writes the new file's lines.
func rotateAs(t *testing.T, path, timestamp, lines string) {
	t.Helper()
	rotated, err := filepath.Glob(path + ".*")
	require.NoError(t, err)
	for _, old := range rotated {
		if strings.HasSuffix(old, ".gz") {
			continue
		}
		data, err := os.ReadFile(old)
		require.NoError(t, err)
		f, err := os.Create(old + ".gz")
		require.NoError(t, err)
		w := gzip.NewWriter(f)
		_, err = w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		require.NoError(t, f.Close())
		require.NoError(t, os.Remove(old))
	}
	require.NoError(t, os.Rename(path, path+"."+timestamp))
	writeFile(t, path, lines)
}

// receive returns the next n lines the reader sends.
func receive(t *testing.T, ch <-chan logparser.LogEntry, n int) []string {
	t.Helper()
	var got []string
	for len(got) < n {
		select {
		case e := <-ch:
			got = append(got, e.Content)
		case <-time.After(3 * time.Second):
			t.Fatalf("got %d lines of %d: %q", len(got), n, got)
		}
	}
	return got
}

// A reader paused for long (the collector is down) while the kubelet rotates its file
// twice reads, once it resumes, the rest of its file, then the file rotated after it,
// which the kubelet has not gzipped yet, then the new one.
func TestPausedReaderReadsFilesRotatedMeanwhile(t *testing.T) {
	withDelivery(t, newHeldExporter(false), "")
	path := filepath.Join(t.TempDir(), "0.log")
	writeFile(t, path, "")
	ch := make(chan logparser.LogEntry)
	r, err := NewTailReader(path, ch)
	require.NoError(t, err)
	defer r.Stop()

	writeFile(t, path, numberedLines(1, 3))
	assert.Equal(t, []string{"line 1"}, receive(t, ch, 1)) // then it waits to send line 2
	rotateAs(t, path, "20261023-123805", numberedLines(4, 6))
	rotateAs(t, path, "20261023-124015", numberedLines(7, 9)) // gzips the reader's file
	want := strings.Split(strings.TrimSuffix(numberedLines(2, 9), "\n"), "\n")
	assert.Equal(t, want, receive(t, ch, len(want)))
}

// Files rotated while the reader is paused that the kubelet gzipped before the reader
// got to them are not read: the loss is logged.
func TestPausedReaderWarnsAboutGzippedFiles(t *testing.T) {
	var logged strings.Builder
	var logMu sync.Mutex
	klog.LogToStderr(false)
	klog.SetOutput(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logged.Write(b)
	}))
	t.Cleanup(func() {
		klog.SetOutput(os.Stderr)
		klog.LogToStderr(true)
	})

	withDelivery(t, newHeldExporter(false), "")
	path := filepath.Join(t.TempDir(), "0.log")
	writeFile(t, path, "")
	ch := make(chan logparser.LogEntry)
	r, err := NewTailReader(path, ch)
	require.NoError(t, err)
	defer r.Stop()

	writeFile(t, path, numberedLines(1, 2))
	assert.Equal(t, []string{"line 1"}, receive(t, ch, 1))
	rotateAs(t, path, "20261023-123805", numberedLines(3, 4))
	rotateAs(t, path, "20261023-124015", numberedLines(5, 6))
	rotateAs(t, path, "20261023-124225", numberedLines(7, 8)) // gzips lines 3-4 unread
	assert.Equal(t, []string{"line 2", "line 5", "line 6", "line 7", "line 8"}, receive(t, ch, 5))
	klog.Flush()
	logMu.Lock()
	defer logMu.Unlock()
	assert.Contains(t, logged.String(), "1 log files rotated at "+path+" while its reader was paused were gzipped or removed before it read them")
}

// A collector that cannot be reached (refused, then restarted) gets the batch once
// it is back; a rejected batch is dropped rather than retried forever.
func TestExporterRetriesUnreachableCollector(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close()) // nothing listens: connections are refused

	var accepted atomic.Int64
	var status atomic.Int64
	status.Store(http.StatusOK)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s := status.Load(); s != http.StatusOK {
			w.WriteHeader(int(s))
			return
		}
		accepted.Add(1)
	}))
	u, err := url.Parse("http://" + addr + "/v1/logs")
	require.NoError(t, err)
	withDelivery(t, newExporter(u), "")

	emit := OtelLogEmitter("/k8s/ns/pod/app", nil, nil)
	emit(time.Now(), logparser.LevelInfo, "", "while the collector is down", nil, "stdout", 0)
	time.Sleep(time.Second) // the batch is sent, refused, retried
	go func() {
		time.Sleep(2 * time.Second)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		srv.Listener = l
		srv.Start()
	}()
	defer srv.Close()
	assert.Eventually(t, func() bool { return accepted.Load() == 1 }, 30*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 0 }, time.Second, 10*time.Millisecond)

	// A proxy's 502 while the collector restarts is retried too.
	status.Store(http.StatusBadGateway)
	emit(time.Now(), logparser.LevelInfo, "", "through a restarting proxy", nil, "stdout", 0)
	time.Sleep(1500 * time.Millisecond)
	assert.Equal(t, 1, dlv.pendingCount(), "still pending while the proxy answers 502")
	status.Store(http.StatusOK)
	assert.Eventually(t, func() bool { return accepted.Load() == 2 }, 15*time.Second, 50*time.Millisecond)
	assert.Equal(t, uint64(0), dlv.dropped.Load())

	status.Store(http.StatusBadRequest)
	rejected := droppedTotal(t, dropRejected)
	emit(time.Now(), logparser.LevelInfo, "", "rejected", nil, "stdout", 0)
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 0 }, 15*time.Second, 50*time.Millisecond)
	assert.Equal(t, uint64(1), dlv.dropped.Load())
	assert.Equal(t, rejected+1, droppedTotal(t, dropRejected))
	assert.Equal(t, int64(2), accepted.Load())
}

// Only errors that resending can get past are retried; anything else, including an
// error not recognised, drops the batch.
func TestTransient(t *testing.T) {
	for msg, want := range map[string]bool{
		"failed to send to http://c:4318/v1/logs: 400 Bad Request\nbad proto":     false,
		"failed to send to http://c:4318/v1/logs: 413 Request Entity Too Large\n": false,
		"failed to send to http://c:4318/v1/logs: 404 Not Found":                  false,
		"failed to send to http://c:4318/v1/logs: 408 Request Timeout\n":          true,
		"failed to send to http://c:4318/v1/logs: 429 Too Many Requests\n":        true,
		"failed to send to http://c:4318/v1/logs: 502 Bad Gateway\n":              true,
		"failed to send to http://c:4318/v1/logs: 500 Internal Server Error\n":    true,
		"failed to send to http://c:4318/v1/logs: 502\n":                          true, // a status line with no reason phrase
		"failed to send to http://c:4318/v1/logs: 400\n":                          false,
		"proto: cannot parse invalid wire-format data":                            false,
		"an error not recognised":                                                 false,
	} {
		assert.Equal(t, want, transient(errors.New(msg)), msg)
	}
	for _, err := range []error{
		&url.Error{Op: "Post", URL: "http://c", Err: errors.New("connection refused")},
		&url.Error{Op: "Post", URL: "http://c", Err: &net.DNSError{Err: "no such host", Name: "c", IsNotFound: true}},
		fmt.Errorf("max retry time elapsed: %w", errors.New("retry-able request failure")), // the client's own 429/503 retries gave up
	} {
		assert.True(t, transient(err), err.Error())
	}
}

// A source no reader can pause (journald) is dropped while many records are
// pending, so it cannot fill the queue and block every parser's emit.
func TestUnpausedSourceIsDroppedWhenBackedUp(t *testing.T) {
	before := droppedTotal(t, dropBackpressure)
	d := newDelivery()
	sent := 0
	for i := 0; i < maxPendingUnpaused+10; i++ {
		d.emit(nil, 0, 1, func() { sent++ })
	}
	assert.Equal(t, maxPendingUnpaused, sent)
	assert.Equal(t, uint64(10), d.dropped.Load())
	assert.Equal(t, before+10, droppedTotal(t, dropBackpressure))
	d.emit(&Source{}, 0, 1, func() { sent++ }) // a file's reader is paused instead
	assert.Equal(t, maxPendingUnpaused+1, sent)
}

// A source no reader can pause (journald) keeps emitting while the agent stops.
// Its records are dropped once stopping, so the drain ends as soon as the records
// emitted before are delivered, instead of waiting out the timeout for records
// that keep arriving.
func TestDrainEndsWhileUnpausedSourceKeepsEmitting(t *testing.T) {
	before := droppedTotal(t, dropShutdown)
	d := newDelivery()
	d.emit(&Source{}, 1, 1, func() {})
	d.emit(nil, 0, 1, func() {})
	d.stopReading()
	stop := make(chan struct{})
	defer close(stop)
	go func() { // exports every pending record; a journald line arrives during each export
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			n := d.pendingCount()
			d.emit(nil, 0, 1, func() {})
			d.done(n)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	assert.True(t, d.drain(ctx), "%d records still pending", d.pendingCount())
	assert.Less(t, time.Since(start), 500*time.Millisecond)
	assert.Positive(t, d.dropped.Load())
	assert.Greater(t, droppedTotal(t, dropShutdown), before)
}

func droppedTotal(t *testing.T, reason string) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, RecordsDroppedTotal.WithLabelValues(reason).Write(&m))
	return m.GetCounter().GetValue()
}

// A file rotated while the agent was down is found again by its inode, and its last
// lines are read before the new file's.
func TestRestartAfterRotationWhileDown(t *testing.T) {
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, "")

	exp := newHeldExporter(false)
	withDelivery(t, exp, positionsFile)
	ch := make(chan logparser.LogEntry)
	r, err := NewTailReader(path, ch)
	require.NoError(t, err)
	p := logparser.NewParser(ch, nil, OtelLogEmitter("/k8s/ns/pod/app", nil, r.Source()), 20*time.Millisecond, 256, false, nil, logparser.SensitiveConfig{})
	writeFile(t, path, numberedLines(1, 10))
	assert.Eventually(t, func() bool { return len(exp.got()) == 10 }, 3*time.Second, 10*time.Millisecond)
	Shutdown(5 * time.Second)
	r.Stop()
	p.Stop()

	// While the agent is down the runtime writes on, then the kubelet rotates.
	writeFile(t, path, numberedLines(11, 15))
	require.NoError(t, os.Rename(path, path+".20261022-101010"))
	writeFile(t, path, numberedLines(16, 20))

	exp2 := newHeldExporter(false)
	withDelivery(t, exp2, positionsFile)
	pipeline(t, path, 20*time.Millisecond)
	assert.Eventually(t, func() bool { return len(exp2.got()) == 10 }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	want := strings.Split(strings.TrimSuffix(numberedLines(11, 20), "\n"), "\n")
	assert.Equal(t, want, exp2.got())
}

// After a rotation the saved position stays in the old file until its lines are
// delivered, so a restart in between still finds them.
func TestRotationKeepsOldPositionUntilDelivered(t *testing.T) {
	exp := newHeldExporter(true)
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	withDelivery(t, exp, positionsFile)
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, "")
	oldDev, oldIno, _, err := fileID(path)
	require.NoError(t, err)
	pipeline(t, path, 20*time.Millisecond)

	writeFile(t, path, numberedLines(1, 3))
	require.NoError(t, os.Rename(path, path+".1"))
	writeFile(t, path, numberedLines(4, 5))
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 5 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, savedPositions.save())
	p, err := loadPositions(positionsFile, 0)
	require.NoError(t, err)
	assert.Equal(t, savedPosition{Dev: oldDev, Ino: oldIno, Offset: 0}, p.saved[path], "nothing delivered: the old file from its start")

	exp.release()
	assert.Eventually(t, func() bool { return len(exp.got()) == 5 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, savedPositions.save())
	p, err = loadPositions(positionsFile, 0)
	require.NoError(t, err)
	newDev, newIno, newSize, err := fileID(path)
	require.NoError(t, err)
	assert.Equal(t, savedPosition{Dev: newDev, Ino: newIno, Offset: newSize}, p.saved[path])
}

// A reader can move on through several files (A, B, C) before any of their lines
// are delivered, e.g. while the collector is down. Every one of them is acknowledged,
// and the position stays in the oldest file with undelivered lines.
func TestSeveralRotationsBeforeDelivery(t *testing.T) {
	s := &Source{path: "0.log"}
	a := s.newFile(1, 10, 0)
	s.ack(a<<genShift | 5)
	b := s.newFile(1, 11, 0)
	c := s.newFile(1, 12, 0)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 10, Offset: 5, Skipped: 1}, s.position(), "B and C not delivered yet")

	s.ack(a<<genShift | 9)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 10, Offset: 9, Skipped: 1}, s.position())
	s.ack(b<<genShift | 7) // B's lines are delivered after C was opened
	assert.Equal(t, savedPosition{Dev: 1, Ino: 11, Offset: 7}, s.position(), "A is delivered")
	s.ack(a<<genShift | 20)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 11, Offset: 7}, s.position(), "A is done with")
	s.ack(c<<genShift | 3)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 12, Offset: 3}, s.position())

	// A truncated file starts over: acknowledgements for its old lines are ignored.
	d := s.newFile(1, 12, 0)
	s.ack(c<<genShift | 30)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 12, Offset: 0}, s.position())
	s.ack(d<<genShift | 2)
	assert.Equal(t, savedPosition{Dev: 1, Ino: 12, Offset: 2}, s.position())
}

// After a restart only the oldest file with undelivered lines is found again (by its
// inode), so the saved position counts the files rotated after it that are not read
// again, for the agent to warn that their undelivered lines are lost.
func TestSavedPositionCountsSkippedFiles(t *testing.T) {
	exp := newHeldExporter(true)
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	withDelivery(t, exp, positionsFile)
	path := filepath.Join(dir, "0.log")
	writeFile(t, path, "")
	aDev, aIno, _, err := fileID(path)
	require.NoError(t, err)
	pipeline(t, path, 20*time.Millisecond)

	writeFile(t, path, numberedLines(1, 3))
	require.NoError(t, os.Rename(path, path+".1"))
	writeFile(t, path, numberedLines(4, 5)) // B
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 5 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, os.Rename(path, path+".2"))
	writeFile(t, path, numberedLines(6, 7)) // C
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 7 }, 3*time.Second, 10*time.Millisecond)

	require.NoError(t, savedPositions.save())
	p, err := loadPositions(positionsFile, 0)
	require.NoError(t, err)
	assert.Equal(t, savedPosition{Dev: aDev, Ino: aIno, Offset: 0, Skipped: 1}, p.saved[path])

	exp.release()
	assert.Eventually(t, func() bool { return len(exp.got()) == 7 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, savedPositions.save())
	p, err = loadPositions(positionsFile, 0)
	require.NoError(t, err)
	cDev, cIno, cSize, err := fileID(path)
	require.NoError(t, err)
	assert.Equal(t, savedPosition{Dev: cDev, Ino: cIno, Offset: cSize}, p.saved[path])
}

// A restart resumes in the oldest file with undelivered lines (A), then the current
// one (C). The files rotated in between (B) are not read again: the loss is logged.
func TestRestartWarnsAboutSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	positionsFile := filepath.Join(dir, "positions.json")
	path := filepath.Join(dir, "0.log")
	writeFile(t, path+".1", numberedLines(1, 3))
	writeFile(t, path+".2", numberedLines(4, 5))
	writeFile(t, path, numberedLines(6, 7))
	dev, ino, _, err := fileID(path + ".1")
	require.NoError(t, err)
	// As saved by a reader in A, while B and C have undelivered lines.
	writeFile(t, positionsFile, fmt.Sprintf(`{"files":{%q:{"dev":%d,"ino":%d,"offset":7,"skipped":1}}}`, path, dev, ino))

	var logged strings.Builder
	var logMu sync.Mutex
	klog.LogToStderr(false)
	klog.SetOutput(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logged.Write(b)
	}))
	t.Cleanup(func() {
		klog.SetOutput(os.Stderr)
		klog.LogToStderr(true)
	})

	exp := newHeldExporter(false)
	withDelivery(t, exp, positionsFile)
	pipeline(t, path, 20*time.Millisecond)
	assert.Eventually(t, func() bool { return len(exp.got()) == 4 }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, []string{"line 2", "line 3", "line 6", "line 7"}, exp.got())
	klog.Flush()
	logMu.Lock()
	defer logMu.Unlock()
	assert.Contains(t, logged.String(), "1 log files rotated at "+path+" before the agent restarted may have lines that were not delivered")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// A collector that answers with a response the client cannot read (a 200 from a
// server that does not speak OTLP) would fail the same way every time, each time
// sending the batch again: it is dropped, not retried.
func TestExporterDropsBatchOnUnreadableResponse(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("<html>not an OTLP collector</html>"))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL + "/v1/logs")
	require.NoError(t, err)
	withDelivery(t, newExporter(u), "")

	rejected := droppedTotal(t, dropRejected)
	OtelLogEmitter("/k8s/ns/pod/app", nil, nil)(time.Now(), logparser.LevelInfo, "", "to the wrong server", nil, "stdout", 0)
	assert.Eventually(t, func() bool { return dlv.pendingCount() == 0 }, 5*time.Second, 20*time.Millisecond)
	time.Sleep(1500 * time.Millisecond) // a retry would have been sent by now
	assert.Equal(t, int64(1), requests.Load(), "not resent")
	assert.Equal(t, uint64(1), dlv.dropped.Load())
	assert.Equal(t, rejected+1, droppedTotal(t, dropRejected))
}

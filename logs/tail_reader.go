package logs

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nudgebee/logparser"
	"k8s.io/klog/v2"
)

var (
	tailPollInterval = time.Second
)

type TailReader struct {
	fileName string
	ch       chan<- logparser.LogEntry
	src      *Source // nil when logs are not exported

	file   *os.File
	info   os.FileInfo
	reader *bufio.Reader
	next   []*os.File // the files that replaced file at fileName, oldest first, read once file is read to its end
	gen    int64      // src's generation of file
	pos    int64      // position in file after the last line read

	stop    context.CancelFunc
	stopped chan struct{}
}

func NewTailReader(fileName string, ch chan<- logparser.LogEntry) (*TailReader, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &TailReader{
		fileName: fileName,
		ch:       ch,
		stop:     cancel,
		stopped:  make(chan struct{}),
	}
	if dlv != nil {
		r.src = &Source{path: fileName}
	}
	var err error
	if r.file, err = os.Open(fileName); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if r.file == nil {
		klog.Infof("%s does not exist yet, waiting for it to appear", fileName)
	} else {
		info, err := r.file.Stat()
		if err != nil {
			_ = r.file.Close()
			return nil, err
		}
		start := info.Size() // without delivery tracking only new lines are read, as before
		if r.src != nil {
			dev, ino := statID(info)
			start = savedPositions.startOffset(fileName, dev, ino, info.Size())
		}
		if _, err = r.file.Seek(start, io.SeekStart); err != nil {
			_ = r.file.Close()
			return nil, err
		}
		dev, ino := statID(info)
		if old, oldInfo, offset := savedPositions.rotatedFile(fileName, dev, ino); old != nil {
			// Rotated while the agent was down: finish the old file first.
			r.next = []*os.File{r.file}
			r.useFile(old, oldInfo, offset)
		} else {
			r.useFile(r.file, info, start)
		}
	}
	if r.src != nil {
		savedPositions.track(r.src)
	}

	go func() {
		const maxPrefixLen = 64 * 1024 // 64KB cap on partial line buffer
		var prefix string
		defer close(r.stopped)
		for {
			if ctx.Err() != nil {
				return
			}
			// Read on only while the collector keeps up: unread lines wait in the file.
			if dlv != nil && !dlv.wait(ctx) {
				return
			}
			if r.reader == nil {
				r.poll(ctx)
				continue
			}
			line, err := r.reader.ReadString('\n')
			r.pos += int64(len(line))
			if err != nil {
				if len(prefix)+len(line) > maxPrefixLen {
					prefix = "" // drop oversized partial line
				} else {
					prefix += line
				}
				if len(r.next) > 0 {
					// The old file is read to its end: pass on its unterminated last
					// line, if any, and move to the next file.
					if prefix != "" && !r.send(ctx, prefix) {
						return
					}
					prefix = ""
					r.switchToNext()
					continue
				}
				r.poll(ctx)
				continue
			}
			if prefix != "" {
				line = prefix + line
				prefix = ""
			}
			if !r.send(ctx, line) {
				return
			}
		}
	}()

	return r, nil
}

func (r *TailReader) send(ctx context.Context, line string) bool {
	e := logparser.LogEntry{
		Timestamp: time.Now(),
		Content:   strings.TrimSuffix(line, "\n"),
		Level:     logparser.LevelUnknown,
	}
	if r.src != nil {
		e.Offset = r.gen<<genShift | r.pos
	}
	select {
	case r.ch <- e:
		return true
	case <-ctx.Done():
		return false
	}
}

// useFile reads f, described by info, from offset.
func (r *TailReader) useFile(f *os.File, info os.FileInfo, offset int64) {
	r.file, r.info, r.pos = f, info, offset
	r.reader = bufio.NewReader(f)
	if r.src != nil {
		dev, ino := statID(info)
		r.gen = r.src.newFile(dev, ino, offset)
	}
}

func (r *TailReader) switchToNext() {
	_ = r.file.Close()
	for len(r.next) > 0 {
		f := r.next[0]
		r.next = r.next[1:]
		if info, err := f.Stat(); err == nil {
			r.useFile(f, info, 0)
			return
		}
		_ = f.Close()
	}
	r.file, r.reader = nil, nil
}

// Source is what the reader's messages acknowledge (see OtelLogEmitter); nil when
// logs are not exported.
func (r *TailReader) Source() *Source { return r.src }

func (r *TailReader) Stop() {
	// handle panic
	defer func() {
		if r := recover(); r != nil {
			klog.Errorln("recovered from panic", r)
		}
	}()
	klog.Infoln("stopping tail reader for", r.fileName)
	r.stop()
	<-r.stopped
	if r.src != nil {
		savedPositions.untrack(r.src)
	}
	if r.file != nil {
		_ = r.file.Close()
	}
	for _, f := range r.next {
		_ = f.Close()
	}
}

func (r *TailReader) poll(ctx context.Context) {
	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if info, err := os.Stat(r.fileName); err != nil {
				if r.file != nil {
					_ = r.file.Close()
					r.file, r.reader = nil, nil
				}
			} else {
				if r.file == nil {
					f, err := os.Open(r.fileName)
					if err != nil {
						continue
					}
					r.useFile(f, info, 0)
					return
				}
				if r.moved(info) || r.truncated(info) || r.appended(info) {
					return
				}
			}
		}
	}
}

// moved opens the new file at the path, after the files rotated in between (see
// rotatedAfter). The old one is read to its end before the reader moves on, since
// the runtime may have written to it after the last read.
func (r *TailReader) moved(info os.FileInfo) bool {
	if os.SameFile(r.info, info) {
		return false
	}
	f, err := os.Open(r.fileName)
	if err != nil {
		return false
	}
	r.next = append(r.rotatedAfter(f), f)
	return true
}

// rotatedSuffix is the suffix the kubelet gives a container log file it rotates: a
// timestamp, so the names sort in rotation order. At each rotation it gzips the files
// rotated before (.gz), so only the newest stays readable, and removes the oldest past
// containerLogMaxFiles (kubernetes pkg/kubelet/logs/container_log_manager.go).
var rotatedSuffix = regexp.MustCompile(`^\.\d{8}-\d{6}(\.gz)?$`)

// rotatedAfter opens the files rotated at the path after the reader's file and before
// cur, the file now there, oldest first: the kubelet may rotate several while the
// reader is paused (see delivery). The reader's file is found among them by its
// inode or, gzipped, by its size; not found, it was removed as older than them all.
// The files after it that cannot be read, gzipped or removed, are logged: their
// lines are lost.
func (r *TailReader) rotatedAfter(cur *os.File) []*os.File {
	if r.src == nil {
		return nil // without delivery tracking only new lines are read, as before
	}
	dir, base := filepath.Split(r.fileName)
	entries, err := os.ReadDir(dir) // sorted by name
	if err != nil {
		return nil
	}
	var rotated []string // without .gz, oldest first
	for _, e := range entries {
		if suffix, ok := strings.CutPrefix(e.Name(), base); ok && rotatedSuffix.MatchString(suffix) {
			name := filepath.Join(dir, strings.TrimSuffix(e.Name(), ".gz"))
			if len(rotated) == 0 || rotated[len(rotated)-1] != name { // gzipping: both are there
				rotated = append(rotated, name)
			}
		}
	}
	oldDev, oldIno := statID(r.info)
	oldSize := int64(-2) // matches no gzipSize
	if info, err := r.file.Stat(); err == nil {
		oldSize = info.Size() % (1 << 32)
	}
	after := rotated
	for i, name := range rotated {
		if dev, ino, _, err := fileID(name); (err == nil && dev == oldDev && ino == oldIno) || gzipSize(name+".gz") == oldSize {
			after = rotated[i+1:]
			break
		}
	}
	curInfo, _ := cur.Stat()
	var files []*os.File
	skipped := 0
	for _, name := range after {
		f, err := os.Open(name)
		if err != nil {
			skipped++
			continue
		}
		if info, err := f.Stat(); err != nil || os.SameFile(info, curInfo) { // cur, rotated since: read last
			_ = f.Close()
			continue
		}
		files = append(files, f)
	}
	if skipped > 0 {
		klog.Warningf("%d log files rotated at %s while its reader was paused were gzipped or removed before it read them: their lines are lost", skipped, r.fileName)
	}
	return files
}

// gzipSize is the size of the content of the gzip file at path, mod 2^32, with which
// the file ends (RFC 1952); -1 if it cannot be read.
func gzipSize(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < 4 {
		return -1
	}
	var b [4]byte
	if _, err := f.ReadAt(b[:], info.Size()-4); err != nil {
		return -1
	}
	return int64(binary.LittleEndian.Uint32(b[:]))
}

func (r *TailReader) truncated(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() < r.info.Size() {
		if _, err := r.file.Seek(0, io.SeekStart); err == nil {
			r.useFile(r.file, info, 0)
			return true
		}
	}
	return false
}

func (r *TailReader) appended(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() > r.info.Size() {
		r.info = info
		return true
	}
	return false
}

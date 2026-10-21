package logs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/klog/v2"
)

// genShift splits an offset handed to the parser into the reader's file generation
// (high bits) and the position in that file (low bits, files up to 1 TiB). A reader
// starts a new generation whenever it moves to another file at its path (rotation,
// re-creation) or the file is truncated, so an acknowledgement for a line of the
// previous file is ignored instead of being taken as a position in the new one.
const genShift = 40

const posMask = 1<<genShift - 1

// Source is a file a TailReader reads, as delivery and the positions file see it.
type Source struct {
	path string

	mu  sync.Mutex
	gen int64
	// files are the files read at path that may have undelivered lines, oldest
	// first, then the current one. Since each file is read to its end before the
	// next and records are delivered in order, an acknowledgement for a line of one
	// means every line of the older ones is delivered. Several are kept when the
	// reader moves on more than once before a line is delivered (a collector outage).
	files []sourceFile
}

type sourceFile struct {
	gen int64
	savedPosition
}

// newFile starts a generation for the file (dev, ino), reading from pos. It returns
// the generation, which the reader puts in its offsets.
func (s *Source) newFile(dev, ino uint64, pos int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	f := sourceFile{gen: s.gen, savedPosition: savedPosition{Dev: dev, Ino: ino, Offset: pos}}
	if n := len(s.files); n > 0 && s.files[n-1].Dev == dev && s.files[n-1].Ino == ino {
		s.files[n-1] = f // truncated: its old lines are gone
	} else {
		s.files = append(s.files, f)
	}
	return s.gen
}

func (s *Source) ack(offset int64) {
	gen, pos := offset>>genShift, offset&posMask
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.files {
		if s.files[i].gen == gen {
			s.files[i].Offset = max(s.files[i].Offset, pos)
			s.files = s.files[i:] // the older ones are delivered
			return
		}
	}
}

// position is where to resume: in the oldest file that may have undelivered lines
// (when it was rotated away it is found again by its inode, see rotatedFile).
func (s *Source) position() savedPosition {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return savedPosition{}
	}
	sp := s.files[0].savedPosition
	sp.Skipped = max(len(s.files)-2, 0)
	return sp
}

type savedPosition struct {
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Offset int64  `json:"offset"`
	// Skipped counts the files rotated at the path after this one and before the
	// current one that may have undelivered lines. After a restart they are not read
	// (see rotatedFile).
	Skipped int `json:"skipped,omitempty"`
}

type positionsFile struct {
	SavedAt time.Time                `json:"saved_at"`
	Files   map[string]savedPosition `json:"files"`
}

// positions saves, per log file, how far it has been delivered, so that after a
// restart the agent resumes where delivery stopped (like promtail's positions file).
type positions struct {
	file    string
	existed bool // the file existed at startup: the agent ran on this node before

	mu      sync.Mutex
	saved   map[string]savedPosition // files without a reader: kept while they exist
	active  map[string]*Source
	scanned bool // the containers running when the agent started have been found

	saveMu sync.Mutex // one save at a time: they share the temporary file
}

var savedPositions *positions // nil: positions are not kept

// InitialScanDone is called once the agent has found the containers that were
// running when it started: log files found from then on are new (see startOffset).
func InitialScanDone() { savedPositions.initialScanDone() }

func (p *positions) initialScanDone() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scanned = true
}

// loadPositions reads the positions saved in file, unless they were saved more than
// maxAge ago (0: no limit): the lines written since would be sent in a burst, long
// after they were written, so the agent starts as on its first run on the node.
func loadPositions(file string, maxAge time.Duration) (*positions, error) {
	p := &positions{file: file, saved: map[string]savedPosition{}, active: map[string]*Source{}}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	p.existed = true
	var pf positionsFile
	if err := json.Unmarshal(data, &pf); err != nil {
		// Start over rather than not at all: unknown files are read from their start.
		return p, fmt.Errorf("ignoring unreadable positions file %s: %w", file, err)
	}
	savedAt := pf.SavedAt
	if savedAt.IsZero() { // saved by a version that did not record when
		if info, err := os.Stat(file); err == nil {
			savedAt = info.ModTime()
		}
	}
	if age := time.Since(savedAt); maxAge > 0 && !savedAt.IsZero() && age > maxAge {
		klog.Infof("ignoring positions file %s saved %s ago, more than %s: reading only new lines, as on the agent's first run on the node", file, age.Round(time.Second), maxAge)
		p.existed = false
		return p, nil
	}
	for path, sp := range pf.Files {
		p.saved[path] = sp
	}
	return p, nil
}

// startOffset is where to start reading the file at path, (dev, ino) of size bytes:
// where its delivery stopped; its start if it was replaced or truncated since, or
// appeared since the agent last ran on this node or since its initial container scan
// (a container started since, or a restarted container's next log file); else, for a
// file there when the agent first started on the node, its end, so lines from before
// the agent was installed are not sent.
func (p *positions) startOffset(path string, dev, ino uint64, size int64) int64 {
	if p == nil {
		return size
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sp, ok := p.saved[path]
	switch {
	case ok && sp.Dev == dev && sp.Ino == ino && sp.Offset <= size:
		return sp.Offset
	case ok || p.existed || p.scanned:
		return 0
	default:
		return size
	}
}

// rotatedFile opens the file whose delivery stopped at path's saved position when
// another file has replaced it at path since (log rotation renamed it, in the same
// directory), at that position, so its last lines are read before the new file's.
// It returns nil when there is no such file. Files rotated after that one are not
// read: their undelivered lines are lost (see savedPosition.Skipped).
func (p *positions) rotatedFile(path string, dev, ino uint64) (*os.File, os.FileInfo, int64) {
	if p == nil {
		return nil, nil, 0
	}
	p.mu.Lock()
	sp, ok := p.saved[path]
	p.mu.Unlock()
	if !ok || (sp.Dev == dev && sp.Ino == ino) {
		return nil, nil, 0
	}
	if sp.Skipped > 0 {
		klog.Warningf("%d log files rotated at %s before the agent restarted may have lines that were not delivered: they are not read again, so those lines are lost", sp.Skipped, path)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil, nil, 0
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if d, i := statID(info); d != sp.Dev || i != sp.Ino || info.Size() < sp.Offset {
			continue
		}
		f, err := os.Open(filepath.Join(filepath.Dir(path), e.Name()))
		if err != nil {
			return nil, nil, 0
		}
		if _, err := f.Seek(sp.Offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, nil, 0
		}
		return f, info, sp.Offset
	}
	return nil, nil, 0
}

func (p *positions) track(s *Source) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active[s.path] = s
}

// untrack keeps the stopped reader's position, for a reader opened on the same file.
func (p *positions) untrack(s *Source) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[s.path] == s {
		delete(p.active, s.path)
		if sp := s.position(); sp.Ino != 0 {
			p.saved[s.path] = sp
		}
	}
}

// save writes every file's delivered position, dropping files that are gone. A file
// replaced at its path (rotated) is not gone while it is there under its rotated
// name: the path's next reader, which may start long after the agent (containers are
// found as its eBPF programs load), reads its last lines first (see rotatedFile). It
// is gone once neither the path nor a file rotated from it has its inode: deleted
// with its container, or gzipped by the kubelet at the next rotation, when it cannot
// be read again anyway.
func (p *positions) save() error {
	if p == nil {
		return nil
	}
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	// Stat outside p.mu, which readers take: a slow disk must not stall them.
	p.mu.Lock()
	saved := maps.Clone(p.saved)
	p.mu.Unlock()
	var gone []string
	for path, sp := range saved {
		if !stillThere(path, sp.Dev, sp.Ino) {
			gone = append(gone, path)
		}
	}
	p.mu.Lock()
	for _, path := range gone {
		// Unless a reader stopped on it meanwhile and saved a new position.
		if p.saved[path] == saved[path] {
			delete(p.saved, path)
		}
	}
	pf := positionsFile{SavedAt: time.Now(), Files: make(map[string]savedPosition, len(p.saved)+len(p.active))}
	for path, sp := range p.saved {
		pf.Files[path] = sp
	}
	for path, s := range p.active {
		if sp := s.position(); sp.Ino != 0 {
			pf.Files[path] = sp
		}
	}
	p.mu.Unlock()

	data, err := json.Marshal(pf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.file), 0o755); err != nil {
		return err
	}
	tmp := p.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, p.file)
}

// stillThere reports whether the file (dev, ino) is at path or was rotated from it:
// renamed <path>.<suffix>, in the same directory.
func stillThere(path string, dev, ino uint64) bool {
	if d, i, _, err := fileID(path); err == nil && d == dev && i == ino {
		return true
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), filepath.Base(path)+".") {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			if d, i := statID(info); d == dev && i == ino {
				return true
			}
		}
	}
	return false
}

func fileID(path string) (dev, ino uint64, size int64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0, err
	}
	dev, ino = statID(info)
	return dev, ino, info.Size(), nil
}

func statID(info os.FileInfo) (dev, ino uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}

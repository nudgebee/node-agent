package llm

import (
	"bufio"
	"io"
	"sort"
	"sync"
)

// stream is one direction of a connection: the kernel appends captured
// chunks, a parser goroutine reads them as an ordinary io.Reader, and every
// byte offset can be mapped back to the kernel timestamp of the chunk that
// carried it. Timestamps are what durations and time-to-first-token are
// computed from, so they come from the kernel, not from when userspace got
// around to parsing.
type stream struct {
	mu   sync.Mutex
	cond *sync.Cond

	pending  [][]byte // unread chunks, oldest first
	buffered int      // bytes in pending
	limit    int      // max buffered bytes before the stream gives up
	readOff  uint64   // bytes handed to the reader so far
	writeOff uint64   // bytes appended so far
	closed   bool
	overflow bool

	// marks records where each chunk starts. Only the most recent ones are
	// kept: lookups are for bytes the parser has just consumed.
	marks []mark
}

type mark struct {
	off uint64
	ts  uint64
}

const maxMarks = 4096

func newStream(limit int) *stream {
	s := &stream{limit: limit}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// write appends a chunk captured at kernel time ts. It returns false once the
// reader has fallen too far behind; the stream is then closed.
func (s *stream) write(data []byte, ts uint64) bool {
	if len(data) == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.buffered+len(data) > s.limit {
		s.overflow = true
		s.closed = true
		s.cond.Broadcast()
		return false
	}
	s.pending = append(s.pending, append([]byte(nil), data...))
	s.buffered += len(data)
	if len(s.marks) >= maxMarks {
		s.marks = append(s.marks[:0], s.marks[maxMarks/2:]...)
	}
	s.marks = append(s.marks, mark{off: s.writeOff, ts: ts})
	s.writeOff += uint64(len(data))
	s.cond.Broadcast()
	return true
}

// Read blocks until data is available or the stream is closed.
func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.pending) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.pending[0])
	if n == len(s.pending[0]) {
		s.pending[0] = nil
		s.pending = s.pending[1:]
	} else {
		s.pending[0] = s.pending[0][n:]
	}
	s.buffered -= n
	s.readOff += uint64(n)
	return n, nil
}

func (s *stream) close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// offset is the number of bytes the reader has consumed.
func (s *stream) offset() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readOff
}

// consumed is the number of bytes a bufio.Reader over this stream has handed
// to its caller: what it read from the stream, less what it still buffers.
func (s *stream) consumed(br *bufio.Reader) uint64 {
	return s.offset() - uint64(br.Buffered())
}

// tsAt returns the kernel timestamp of the chunk containing byte off.
func (s *stream) tsAt(off uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.marks) == 0 {
		return 0
	}
	i := sort.Search(len(s.marks), func(i int) bool { return s.marks[i].off > off })
	if i == 0 {
		return s.marks[0].ts
	}
	return s.marks[i-1].ts
}

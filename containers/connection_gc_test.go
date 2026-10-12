package containers

import (
	"testing"
	"time"
)

// Connections created by createConnectionFromSocketInfo (the Go-TLS fallback)
// are registered only in connectionsByPidFd, never in activeConnections. The
// activeConnections sweep in gc() therefore never visits them and
// onConnectionClose only stamps Closed, so before reclaimStaleConnections
// existed nothing ever freed them — they accumulated for the container's whole
// lifetime and pinned their HTTP/2 parsers alive with them.
func TestReclaimStaleConnectionsDropsDeadPids(t *testing.T) {
	now := time.Now()
	live, dead := uint32(100), uint32(200)

	c := &Container{
		processes: map[uint32]*Process{live: {}},
		connectionsByPidFd: map[PidFd]*ActiveConnection{
			{Pid: live, Fd: 3}: {Pid: live, Fd: 3},
			{Pid: dead, Fd: 4}: {Pid: dead, Fd: 4},
			{Pid: dead, Fd: 5}: {Pid: dead, Fd: 5},
		},
	}

	c.reclaimStaleConnections(now)

	if _, ok := c.connectionsByPidFd[PidFd{Pid: live, Fd: 3}]; !ok {
		t.Error("connection for a live pid was reclaimed; it must be kept")
	}
	for _, fd := range []uint64{4, 5} {
		if _, ok := c.connectionsByPidFd[PidFd{Pid: dead, Fd: fd}]; ok {
			t.Errorf("connection for dead pid %d fd %d survived; this is the leak", dead, fd)
		}
	}
	if got := len(c.connectionsByPidFd); got != 1 {
		t.Errorf("connectionsByPidFd size = %d, want 1", got)
	}
}

// A connection whose process is still alive is kept until it has been closed
// for longer than gcInterval, matching how activeConnections entries age out.
func TestReclaimStaleConnectionsHonoursCloseGrace(t *testing.T) {
	now := time.Now()
	pid := uint32(100)

	c := &Container{
		processes: map[uint32]*Process{pid: {}},
		connectionsByPidFd: map[PidFd]*ActiveConnection{
			{Pid: pid, Fd: 3}: {Pid: pid, Fd: 3},                                   // open
			{Pid: pid, Fd: 4}: {Pid: pid, Fd: 4, Closed: now.Add(-gcInterval / 2)}, // recently closed
			{Pid: pid, Fd: 5}: {Pid: pid, Fd: 5, Closed: now.Add(-2 * gcInterval)}, // long closed
		},
	}

	c.reclaimStaleConnections(now)

	if _, ok := c.connectionsByPidFd[PidFd{Pid: pid, Fd: 3}]; !ok {
		t.Error("open connection was reclaimed")
	}
	if _, ok := c.connectionsByPidFd[PidFd{Pid: pid, Fd: 4}]; !ok {
		t.Error("connection closed within gcInterval was reclaimed too early")
	}
	if _, ok := c.connectionsByPidFd[PidFd{Pid: pid, Fd: 5}]; ok {
		t.Error("connection closed longer than gcInterval survived")
	}
}

// The fallback path must not grow connectionsByPidFd without bound. Legitimate
// entries are capped by the container's open socket fds, so a map already at
// maxConnectionsPerContainer refuses new keys — but must still accept a key it
// already holds, since replacing frees the previous entry.
func TestCanTrackConnectionCap(t *testing.T) {
	c := &Container{connectionsByPidFd: map[PidFd]*ActiveConnection{}}

	if !c.canTrackConnection(PidFd{Pid: 1, Fd: 1}) {
		t.Error("empty map refused a new connection")
	}

	for i := 0; i < maxConnectionsPerContainer; i++ {
		c.connectionsByPidFd[PidFd{Pid: uint32(i), Fd: 1}] = &ActiveConnection{}
	}

	if c.canTrackConnection(PidFd{Pid: 999999, Fd: 7}) {
		t.Error("map at cap accepted a new key; growth is unbounded")
	}
	if !c.canTrackConnection(PidFd{Pid: 0, Fd: 1}) {
		t.Error("map at cap refused a key it already holds; replacement must be allowed")
	}
}

package containers

import (
	lru "github.com/hashicorp/golang-lru/v2"
	"k8s.io/klog/v2"
)

// tlsDropHints explains each tls_plaintext_dropped reason in the log line.
var tlsDropHints = map[string]string{
	"go_fd_unknown":       "crypto/tls runs over a connection whose socket the probe cannot find: a net.Conn wrapped by the application or a library, or an in-memory one (net.Pipe, gRPC bufconn)",
	"ssl_read_fd_unknown": "SSL_read returned data before the connection's socket was seen, as in a server that reads before it writes through a memory BIO",
	"ssl_write_unclaimed": "SSL_write plaintext was never matched to a socket write, as in a memory-BIO application that buffers several writes before sending",
}

type tlsDropLogKey struct {
	exe    exeIdentity
	reason string
	// container is set only when the process is unknown, so that an unknown
	// process in one container does not silence those in every other.
	container ContainerID
}

// tlsDropLogged keeps the TLS-drop warning to one line per binary and reason,
// however many processes run that binary.
var tlsDropLogged, _ = lru.New[tlsDropLogKey, struct{}](4096)

// recordTLSDropsLocked adds TLS plaintext the kernel could not attribute to a
// socket to the container's count, and names the binary in the log the first
// time it happens for it. The caller holds c.lock.
func (c *Container) recordTLSDropsLocked(pid uint32, p *Process, byReason map[string]uint64) {
	if c.tlsDrops == nil {
		c.tlsDrops = map[string]float64{}
	}
	for reason, n := range byReason {
		c.tlsDrops[reason] += float64(n)
		key := tlsDropLogKey{reason: reason}
		name := ""
		if p != nil {
			key.exe, name = p.tlsExe, p.tlsExeName
		} else {
			key.container = c.id
		}
		if ok, _ := tlsDropLogged.ContainsOrAdd(key, struct{}{}); ok {
			continue
		}
		klog.Warningf("TLS plaintext of %s (pid %d, container %s) is not being captured: %d %s events. %s",
			name, pid, c.id, n, reason, tlsDropHints[reason])
	}
}

// recordTLSDrops is recordTLSDropsLocked for a process that may still be
// running, as found by the periodic read.
func (c *Container) recordTLSDrops(pid uint32, byReason map[string]uint64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.recordTLSDropsLocked(pid, c.processes[pid], byReason)
}

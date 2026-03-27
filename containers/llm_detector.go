package containers

import (
	"sync"

	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

// LLMConnectionTag holds the LLM provider info for a tagged connection.
// Once a connection is tagged, all L7 data on it is routed to the LLM parser.
type LLMConnectionTag struct {
	Provider LLMProvider
	Host     string // FQDN (e.g., "api.openai.com")
}

// LLMDetector detects LLM connections at the network level using DNS resolution.
//
// Architecture: detect early, parse late.
//   - DNS responses feed the IP→provider cache.
//   - TCP connections are checked against this cache at connect time.
//   - No dependency on HTTP/2 HPACK decoding or L7 payload parsing for detection.
type LLMDetector struct {
	mu sync.RWMutex
	// ipCache maps destination IP → LLM tag.
	// Populated from DNS responses where the FQDN matches a known LLM provider.
	ipCache map[string]*LLMConnectionTag // key: IP string (no port)

	// connCache maps pid:fd → LLM tag for connections already identified.
	// This avoids repeated IP lookups for the same connection.
	connCache map[PidFd]*LLMConnectionTag
}

// NewLLMDetector creates a new detector.
func NewLLMDetector() *LLMDetector {
	return &LLMDetector{
		ipCache:   make(map[string]*LLMConnectionTag),
		connCache: make(map[PidFd]*LLMConnectionTag),
	}
}

// OnDNS is called when a DNS response is captured.
// If the FQDN matches a known LLM provider, all resolved IPs are cached.
func (d *LLMDetector) OnDNS(fqdn string, ips []netaddr.IP) {
	provider := DetectLLMProvider(fqdn)
	if provider == ProviderUnknown {
		return
	}

	// Skip IP caching for Google APIs — Google uses shared anycast IPs across
	// ALL *.googleapis.com services (compute, billing, AI, etc.). Caching
	// generativelanguage.googleapis.com's IP would false-positive tag
	// compute.googleapis.com connections as LLM.
	// For Google, we rely entirely on late-tag from HTTP Host/:authority header.
	if provider == ProviderGoogle {
		klog.V(3).Infof("LLM_DETECTOR: skipping IP cache for %s (Google shared anycast)", fqdn)
		return
	}

	tag := &LLMConnectionTag{
		Provider: provider,
		Host:     fqdn,
	}

	d.mu.Lock()
	for _, ip := range ips {
		key := ip.String()
		d.ipCache[key] = tag
	}
	d.mu.Unlock()

	klog.V(3).Infof("LLM_DETECTOR: cached %d IPs for %s (%s)", len(ips), fqdn, provider)
}

// CheckIP checks if a destination IP belongs to a known LLM provider.
// Called at TCP connection time or when resolving L7 events.
func (d *LLMDetector) CheckIP(ip netaddr.IP) *LLMConnectionTag {
	d.mu.RLock()
	tag := d.ipCache[ip.String()]
	d.mu.RUnlock()
	return tag
}

// TagConnection associates a pid:fd with an LLM provider.
// Called when a connection to an LLM provider is confirmed (from DNS or :authority fallback).
func (d *LLMDetector) TagConnection(pidFd PidFd, tag *LLMConnectionTag) {
	d.mu.Lock()
	d.connCache[pidFd] = tag
	d.mu.Unlock()
}

// GetConnectionTag returns the LLM tag for a connection, or nil if untagged.
func (d *LLMDetector) GetConnectionTag(pidFd PidFd) *LLMConnectionTag {
	d.mu.RLock()
	tag := d.connCache[pidFd]
	d.mu.RUnlock()
	return tag
}

// LateTag handles the fallback case: an HTTP/2 :authority header or HTTP/1.1 Host
// header reveals an LLM provider after the connection was already established.
// Returns the tag if the host matches, nil otherwise.
func (d *LLMDetector) LateTag(pidFd PidFd, host string, destIP netaddr.IP) *LLMConnectionTag {
	provider := DetectLLMProvider(host)
	if provider == ProviderUnknown {
		return nil
	}

	tag := &LLMConnectionTag{
		Provider: provider,
		Host:     host,
	}

	d.mu.Lock()
	d.connCache[pidFd] = tag
	// Also cache the IP for future connections
	if !destIP.IsZero() {
		d.ipCache[destIP.String()] = tag
	}
	d.mu.Unlock()

	klog.V(3).Infof("LLM_DETECTOR: late-tagged pid=%d fd=%d as %s (%s)",
		pidFd.Pid, pidFd.Fd, provider, host)

	return tag
}

// RemoveConnection cleans up the connection cache when a connection closes.
func (d *LLMDetector) RemoveConnection(pidFd PidFd) {
	d.mu.Lock()
	delete(d.connCache, pidFd)
	d.mu.Unlock()
}

// RemoveProcess cleans up all connections for a dead process.
func (d *LLMDetector) RemoveProcess(pid uint32) {
	d.mu.Lock()
	for pidFd := range d.connCache {
		if pidFd.Pid == pid {
			delete(d.connCache, pidFd)
		}
	}
	d.mu.Unlock()
}

// GC removes stale IP cache entries older than maxAge.
// IP→provider mappings are stable (DNS for LLM providers rarely changes),
// so this is mainly to bound memory, not for correctness.
func (d *LLMDetector) GC(maxEntries int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// IP cache: cap size. LLM providers have a small set of IPs,
	// so this should rarely trigger.
	if len(d.ipCache) > maxEntries {
		// Simple eviction: clear and let DNS repopulate.
		// This is safe because DNS events keep flowing.
		klog.Warningf("LLM_DETECTOR: IP cache exceeded %d entries (%d), clearing",
			maxEntries, len(d.ipCache))
		d.ipCache = make(map[string]*LLMConnectionTag)
	}
}

// Stats returns current cache sizes for observability.
func (d *LLMDetector) Stats() (ipCacheSize, connCacheSize int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.ipCache), len(d.connCache)
}

// SeedFromDNSCache bulk-loads IP→provider mappings from an existing DNS cache.
// Called at startup to handle connections established before the detector was created.
func (d *LLMDetector) SeedFromDNSCache(entries map[netaddr.IP]string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	seeded := 0
	for ip, fqdn := range entries {
		provider := DetectLLMProvider(fqdn)
		if provider == ProviderUnknown {
			continue
		}
		d.ipCache[ip.String()] = &LLMConnectionTag{
			Provider: provider,
			Host:     fqdn,
		}
		seeded++
	}

	if seeded > 0 {
		klog.Infof("LLM_DETECTOR: seeded %d IPs from DNS cache", seeded)
	}
}

// IsLLMConnection checks if a connection (by pid:fd) or destination IP is LLM.
// Tries connection cache first (fast path), then IP cache (slower path).
// If the IP cache matches, the connection is auto-tagged for future lookups.
func (d *LLMDetector) IsLLMConnection(pidFd PidFd, destIP netaddr.IP) *LLMConnectionTag {
	// Fast path: already tagged
	d.mu.RLock()
	if tag, ok := d.connCache[pidFd]; ok {
		d.mu.RUnlock()
		return tag
	}
	// Try IP cache
	tag := d.ipCache[destIP.String()]
	d.mu.RUnlock()

	if tag != nil {
		// Auto-tag for future lookups
		d.mu.Lock()
		d.connCache[pidFd] = tag
		d.mu.Unlock()
	}

	return tag
}

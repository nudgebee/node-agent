package common

import (
	"sync"
	"time"

	"inet.af/netaddr"
)

var (
	// FQDNCacheTTL bounds how long an IP→FQDN mapping is trusted after it was
	// last observed. DNS TTLs for the CDN/anycast endpoints that dominate this
	// cache are short (60-300s), but the mapping itself stays useful far longer:
	// the edge IP keeps serving the same host, and a slightly stale name is a
	// much better destination label than a bare IP. Any fresh DNS answer, Host
	// header or SNI for the same IP overwrites the entry and restarts the clock.
	FQDNCacheTTL = time.Hour

	// FQDNCacheMaxEntries caps memory. Reaching it evicts expired entries first,
	// then the least recently used.
	FQDNCacheMaxEntries = 10000
)

// fqdnCacheRecencyResolution is how stale an entry's last-use stamp may get
// before a read refreshes it. Coarse recency is enough to order LRU eviction and
// keeps lookups on the read lock.
const fqdnCacheRecencyResolution = time.Minute

type fqdnCacheEntry struct {
	domain   *Domain
	expires  time.Time
	lastUsed time.Time
}

// FQDNCache maps destination IPs to the domain they were last observed to serve.
//
// It is a resolver cache with its own TTL, deliberately not scoped to the
// lifetime of the connections that populated it. A DNS answer outlives the
// connection that triggered it: applications cache DNS themselves (the Go
// resolver, glibc, urllib3), so a reconnect to the same IP usually emits no DNS
// packet at all. Dropping the mapping when the connection goes away therefore
// loses it permanently, and the next connection to that IP falls back to
// labelling the destination with a bare IP.
type FQDNCache struct {
	mu      sync.RWMutex
	entries map[netaddr.IP]*fqdnCacheEntry

	// now is overridable so tests can advance time without sleeping.
	now func() time.Time
}

func NewFQDNCache() *FQDNCache {
	return &FQDNCache{entries: map[netaddr.IP]*fqdnCacheEntry{}, now: time.Now}
}

// Get returns the domain for ip, or nil if absent or expired.
func (c *FQDNCache) Get(ip netaddr.IP) *Domain {
	now := c.now()

	c.mu.RLock()
	e := c.entries[ip]
	if e == nil || now.After(e.expires) {
		c.mu.RUnlock()
		return nil
	}
	domain := e.domain
	stale := now.Sub(e.lastUsed) > fqdnCacheRecencyResolution
	c.mu.RUnlock()

	if stale {
		c.mu.Lock()
		if e := c.entries[ip]; e != nil {
			e.lastUsed = now
		}
		c.mu.Unlock()
	}
	return domain
}

// Put stores or refreshes the mapping for ip.
func (c *FQDNCache) Put(ip netaddr.IP, domain *Domain) {
	if domain == nil {
		return
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[ip]; !exists && len(c.entries) >= FQDNCacheMaxEntries {
		c.evictLocked(now)
	}
	c.entries[ip] = &fqdnCacheEntry{domain: domain, expires: now.Add(FQDNCacheTTL), lastUsed: now}
}

// evictLocked frees room: expired entries first, then the least recently used.
// The caller must hold the write lock.
func (c *FQDNCache) evictLocked(now time.Time) {
	for ip, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, ip)
		}
	}
	if len(c.entries) < FQDNCacheMaxEntries {
		return
	}
	// Nothing expired — drop the oldest batch by last use. A batch keeps this
	// O(n) scan rare rather than running it on every insert once full.
	batch := FQDNCacheMaxEntries / 10
	if batch < 1 {
		batch = 1
	}
	type aged struct {
		ip       netaddr.IP
		lastUsed time.Time
	}
	all := make([]aged, 0, len(c.entries))
	for ip, e := range c.entries {
		all = append(all, aged{ip: ip, lastUsed: e.lastUsed})
	}
	// Partial selection of the oldest `batch` entries; a full sort would be
	// wasted work since only that many are needed.
	for i := 0; i < batch && i < len(all); i++ {
		oldest := i
		for j := i + 1; j < len(all); j++ {
			if all[j].lastUsed.Before(all[oldest].lastUsed) {
				oldest = j
			}
		}
		all[i], all[oldest] = all[oldest], all[i]
		delete(c.entries, all[i].ip)
	}
}

// GC drops expired entries. Called from the registry's periodic sweep so an idle
// agent does not hold mappings past their TTL.
func (c *FQDNCache) GC() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, ip)
		}
	}
}

// ForEach calls f for every live entry.
func (c *FQDNCache) ForEach(f func(ip netaddr.IP, domain *Domain)) {
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for ip, e := range c.entries {
		if now.After(e.expires) {
			continue
		}
		f(ip, e.domain)
	}
}

// Len returns the number of entries, including any not yet expired away.
func (c *FQDNCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

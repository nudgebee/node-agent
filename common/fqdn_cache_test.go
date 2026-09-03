package common

import (
	"fmt"
	"testing"
	"time"

	"inet.af/netaddr"
)

func testCache(t *testing.T) (*FQDNCache, func(time.Duration)) {
	t.Helper()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFQDNCache()
	c.now = func() time.Time { return clock }
	return c, func(d time.Duration) { clock = clock.Add(d) }
}

func ip(s string) netaddr.IP {
	return netaddr.MustParseIP(s)
}

func TestFQDNCacheGetPut(t *testing.T) {
	c, _ := testCache(t)

	if got := c.Get(ip("142.250.115.95")); got != nil {
		t.Fatalf("empty cache returned %v", got)
	}

	c.Put(ip("142.250.115.95"), &Domain{FQDN: "monitoring.googleapis.com"})
	got := c.Get(ip("142.250.115.95"))
	if got == nil || got.FQDN != "monitoring.googleapis.com" {
		t.Fatalf("got %v, want monitoring.googleapis.com", got)
	}
	if got := c.Get(ip("142.250.115.96")); got != nil {
		t.Fatalf("unrelated IP returned %v", got)
	}
}

// A mapping must survive well past the lifetime of the connection that produced
// it. Applications cache DNS themselves, so a reconnect to the same IP emits no
// DNS packet — if the entry were dropped when the connection went away, the
// destination would permanently degrade to a bare IP.
func TestFQDNCacheOutlivesConnection(t *testing.T) {
	c, advance := testCache(t)
	c.Put(ip("172.217.115.4"), &Domain{FQDN: "generativelanguage.googleapis.com"})

	// Survive several registry GC sweeps, which previously evicted every mapping
	// whose IP had no live connection — including, because a resolved
	// destination's HostPort carries a zero IP, the very entries that had just
	// been resolved successfully.
	for i := 0; i < 6; i++ {
		advance(5 * time.Minute)
		c.GC()
	}

	got := c.Get(ip("172.217.115.4"))
	if got == nil {
		t.Fatal("mapping was dropped while still within its TTL")
	}
	if got.FQDN != "generativelanguage.googleapis.com" {
		t.Fatalf("got %q", got.FQDN)
	}
}

// GC must expire on the TTL only. Sweeping on any other schedule is what made a
// resolved destination fall back to a bare IP on its next connection.
func TestFQDNCacheGCKeepsLiveEntries(t *testing.T) {
	c, advance := testCache(t)
	c.Put(ip("1.1.1.1"), &Domain{FQDN: "live.example.com"})
	c.Put(ip("2.2.2.2"), &Domain{FQDN: "expiring.example.com"})

	advance(time.Minute)
	c.GC()
	if c.Len() != 2 {
		t.Fatalf("GC dropped live entries: %d left, want 2", c.Len())
	}

	// Refresh only the first, then cross the original TTL.
	advance(FQDNCacheTTL - 2*time.Minute)
	c.Put(ip("1.1.1.1"), &Domain{FQDN: "live.example.com"})
	advance(3 * time.Minute)
	c.GC()

	if got := c.Get(ip("1.1.1.1")); got == nil {
		t.Error("GC dropped a refreshed entry")
	}
	if got := c.Get(ip("2.2.2.2")); got != nil {
		t.Errorf("GC kept an expired entry: %v", got)
	}
}

func TestFQDNCacheExpiry(t *testing.T) {
	c, advance := testCache(t)
	c.Put(ip("1.2.3.4"), &Domain{FQDN: "example.com"})

	advance(FQDNCacheTTL + time.Second)

	if got := c.Get(ip("1.2.3.4")); got != nil {
		t.Fatalf("expired entry returned %v", got)
	}
	c.GC()
	if n := c.Len(); n != 0 {
		t.Fatalf("GC left %d entries", n)
	}
}

func TestFQDNCachePutRefreshesTTL(t *testing.T) {
	c, advance := testCache(t)
	c.Put(ip("1.2.3.4"), &Domain{FQDN: "old.example.com"})

	advance(FQDNCacheTTL - time.Minute)
	c.Put(ip("1.2.3.4"), &Domain{FQDN: "new.example.com"})
	advance(2 * time.Minute) // past the original expiry, not the refreshed one

	got := c.Get(ip("1.2.3.4"))
	if got == nil {
		t.Fatal("re-observed mapping expired on the original schedule")
	}
	if got.FQDN != "new.example.com" {
		t.Fatalf("got %q, want the newer FQDN", got.FQDN)
	}
}

// Once full, inserts must evict rather than be silently dropped — otherwise a
// cache that fills once stops learning any new mapping forever.
func TestFQDNCacheEvictsWhenFullRatherThanDroppingInserts(t *testing.T) {
	c, _ := testCache(t)

	for i := 0; i < FQDNCacheMaxEntries; i++ {
		c.Put(ip(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)), &Domain{FQDN: "filler"})
	}
	if c.Len() != FQDNCacheMaxEntries {
		t.Fatalf("setup: %d entries, want %d", c.Len(), FQDNCacheMaxEntries)
	}

	c.Put(ip("203.0.113.7"), &Domain{FQDN: "late.example.com"})

	got := c.Get(ip("203.0.113.7"))
	if got == nil {
		t.Fatal("insert into a full cache was dropped")
	}
	if got.FQDN != "late.example.com" {
		t.Fatalf("got %q", got.FQDN)
	}
	if c.Len() > FQDNCacheMaxEntries {
		t.Fatalf("cache grew past its cap: %d", c.Len())
	}
}

func TestFQDNCacheEvictsExpiredBeforeLive(t *testing.T) {
	c, advance := testCache(t)

	// Fill to one short of the cap with entries that will expire.
	for i := 0; i < FQDNCacheMaxEntries-1; i++ {
		c.Put(ip(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)), &Domain{FQDN: "stale"})
	}
	advance(FQDNCacheTTL + time.Second)

	// A live entry added after the others expired, plus one more to hit the cap.
	c.Put(ip("198.51.100.1"), &Domain{FQDN: "live.example.com"})
	c.Put(ip("198.51.100.2"), &Domain{FQDN: "live2.example.com"})

	if got := c.Get(ip("198.51.100.1")); got == nil || got.FQDN != "live.example.com" {
		t.Fatalf("live entry evicted ahead of expired ones: %v", got)
	}
	if c.Len() >= FQDNCacheMaxEntries {
		t.Fatalf("expired entries were not reclaimed: %d", c.Len())
	}
}

func TestFQDNCacheForEachSkipsExpired(t *testing.T) {
	c, advance := testCache(t)
	c.Put(ip("1.1.1.1"), &Domain{FQDN: "a.example.com"})
	advance(FQDNCacheTTL - time.Minute)
	c.Put(ip("2.2.2.2"), &Domain{FQDN: "b.example.com"})
	advance(2 * time.Minute) // 1.1.1.1 expired, 2.2.2.2 still live

	seen := map[string]string{}
	c.ForEach(func(i netaddr.IP, d *Domain) { seen[i.String()] = d.FQDN })

	if _, ok := seen["1.1.1.1"]; ok {
		t.Error("ForEach yielded an expired entry")
	}
	if seen["2.2.2.2"] != "b.example.com" {
		t.Errorf("ForEach missed the live entry: %v", seen)
	}
}

func TestFQDNCachePutNilIsNoop(t *testing.T) {
	c, _ := testCache(t)
	c.Put(ip("1.2.3.4"), nil)
	if c.Len() != 0 {
		t.Fatalf("nil domain stored: %d entries", c.Len())
	}
}

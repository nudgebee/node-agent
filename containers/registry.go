package containers

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	MinTrafficStatsUpdateInterval = 5 * time.Second
	IgnoredContainersCacheTTL     = 15 * time.Second
)

var (
	selfNetNs                = netns.None()
	hostNetNsId              = netns.None().UniqueId()
	agentPid                 = uint32(os.Getpid())
	containerIdRegexp        = regexp.MustCompile(`[a-z0-9]{64}`)
	cronjobPodName           = regexp.MustCompile(`([a-z0-9-]+)-([0-9]{8})-[bcdfghjklmnpqrstvwxz2456789]{5}`)
	cronjobPodScheduleWindow = 7 * 24 * time.Hour
)

type ProcessInfo struct {
	Pid         uint32
	ContainerId ContainerID
	StartedAt   time.Time
	Flags       proc.Flags
}

type IPResolver interface {
	ResolveIP(string) common.Workload
	ResolveActualIP(string) common.Workload
	CacheDNS(string, string) common.Workload
	StartWatching() error
	StopWatching()
	ResolvePodOwner(string, string) common.Workload
}

type NodeConstLabels struct {
	MachineID  string
	SystemUUID string
	AZ         string
	Region     string
}

// Values returns the label values in the order matching constLabelNames.
func (n NodeConstLabels) Values() []string {
	return []string{n.MachineID, n.SystemUUID, n.AZ, n.Region}
}

type Registry struct {
	reg prometheus.Registerer // wrapped registerer for ip2fqdn and LLM metrics

	tracer *ebpftracer.Tracer
	events chan ebpftracer.Event

	containersById         map[ContainerID]*Container
	containersByCgroupId   map[string]*Container
	containersByPid        map[uint32]*Container
	containersByPidIgnored map[uint32]*time.Time
	containerLock          sync.RWMutex // Protects container maps and registration
	ip2fqdn                map[netaddr.IP]*common.Domain
	ip2fqdnLock            sync.RWMutex

	processInfoCh chan<- ProcessInfo
	ip_resolver   IPResolver

	gpuProcessUsageSampleChan chan gpu.ProcessUsageSample

	// nodeConstLabels holds node-level label values for embedding directly
	// in container metrics (avoids WrapRegistererWith overhead).
	nodeConstLabels NodeConstLabels

	// pendingL7Events stores L7 events that arrived before their connection was established
	// This handles the race condition between ring buffer (L7 events) and perf buffer (TCP events)
	pendingL7Events     []pendingL7Event
	pendingL7EventsLock sync.Mutex

	// llmDetector provides connection-level LLM detection from DNS cache.
	// Shared across all containers so DNS resolutions from one container
	// benefit LLM detection in others.
	llmDetector *LLMDetector
}

// pendingL7Event stores an L7 event that's waiting for its connection to be established
type pendingL7Event struct {
	event      ebpftracer.Event
	addedAt    time.Time
	retryCount int
}

func NewRegistry(reg prometheus.Registerer, rawReg prometheus.Registerer, processInfoCh chan<- ProcessInfo, ip_resolver *common.K8sIPResolver, gpuProcessUsageSampleChan chan gpu.ProcessUsageSample, machineId, systemUuid, az, region string) (*Registry, error) {
	ns, err := proc.GetSelfNetNs()
	if err != nil {
		return nil, err
	}
	selfNetNs = ns
	hostNetNs, err := proc.GetHostNetNs()
	if err != nil {
		return nil, err
	}
	defer hostNetNs.Close()
	hostNetNsId = hostNetNs.UniqueId()

	err = proc.ExecuteInNetNs(hostNetNs, selfNetNs, func() error {
		if err := TaskstatsInit(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = cgroup.Init(); err != nil {
		return nil, err
	}
	if err = DockerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err = ContainerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err = CrioInit(); err != nil {
		klog.Warningln(err)
	}
	if err = JournaldInit(); err != nil {
		klog.Warningln(err)
	}

	r := &Registry{
		reg:                    reg,
		events:                 make(chan ebpftracer.Event, 2000),
		containersById:         map[ContainerID]*Container{},
		containersByCgroupId:   map[string]*Container{},
		containersByPid:        map[uint32]*Container{},
		containersByPidIgnored: map[uint32]*time.Time{},
		ip2fqdn:                map[netaddr.IP]*common.Domain{},

		processInfoCh: processInfoCh,
		ip_resolver:   ip_resolver,
		tracer:        ebpftracer.NewTracer(hostNetNs, selfNetNs, *flags.DisableL7Tracing),

		gpuProcessUsageSampleChan: gpuProcessUsageSampleChan,
		nodeConstLabels:           NodeConstLabels{MachineID: machineId, SystemUUID: systemUuid, AZ: az, Region: region},
		llmDetector:               NewLLMDetector(),
	}
	// Register LLM metrics with the same registerer used for other container metrics
	RegisterLLMMetrics(reg)
	if err = reg.Register(r); err != nil {
		return nil, err
	}
	// Register a single collector for all containers on the raw registry.
	// Individual containers are NOT registered/unregistered because prometheus.Registry
	// does not support Unregister for unchecked collectors (empty Describe).
	if err = rawReg.Register(&containerCollector{registry: r}); err != nil {
		return nil, err
	}
	go r.handleEvents(r.events)
	if err = r.tracer.Run(r.events); err != nil {
		close(r.events)
		return nil, err
	}

	return r, nil
}

func (r *Registry) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.Ip2Fqdn
}

func (r *Registry) Collect(ch chan<- prometheus.Metric) {
	r.ip2fqdnLock.RLock()
	defer r.ip2fqdnLock.RUnlock()
	for ip, domain := range r.ip2fqdn {
		ch <- prometheus.MustNewConstMetric(metrics.Ip2Fqdn, prometheus.GaugeValue, 1, ip.String(), domain.FQDN)
	}
}

// containerCollector is registered on the raw Prometheus registry and collects
// metrics from all known containers. This avoids registering each Container as
// an individual unchecked collector, which is needed because prometheus.Registry
// does not support Unregister for unchecked collectors (Describe returns nothing).
type containerCollector struct {
	registry *Registry
}

func (cc *containerCollector) Describe(chan<- *prometheus.Desc) {
	// Unchecked collector: container metrics are dynamic
}

func (cc *containerCollector) Collect(ch chan<- prometheus.Metric) {
	cc.registry.containerLock.RLock()
	containers := make([]*Container, 0, len(cc.registry.containersById))
	for _, c := range cc.registry.containersById {
		containers = append(containers, c)
	}
	cc.registry.containerLock.RUnlock()

	for _, c := range containers {
		c.Collect(ch)
	}
}

func (r *Registry) Close() {
	r.tracer.Close()
	close(r.events)
}

func (r *Registry) handleEvents(ch <-chan ebpftracer.Event) {
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()
	ebpfStatsTicker := time.NewTicker(MinTrafficStatsUpdateInterval)
	defer ebpfStatsTicker.Stop()
	counterEvictTicker := time.NewTicker(gcInterval)
	defer counterEvictTicker.Stop()
	for {
		select {
		case <-ebpfStatsTicker.C:
			r.updateEbpfStatsAndActiveConns()
		case <-counterEvictTicker.C:
			r.evictStaleCounterLabels()
		case now := <-gcTicker.C:
			for pid, c := range r.containersByPid {
				cg, err := proc.ReadCgroup(pid)
				if err != nil {
					delete(r.containersByPid, pid)
					if c != nil {
						c.onProcessExit(pid, false)
					}
					continue
				}
				if c != nil && cg.Id != c.cgroup.Id {
					delete(r.containersByPid, pid)
					c.onProcessExit(pid, false)
				}
			}
			r.containersByPidIgnored = map[uint32]*time.Time{}
			activeIPs := map[netaddr.IP]struct{}{}
			deadContainers := []*Container{}

			// First pass: collect active IPs and identify dead containers with read lock
			r.containerLock.RLock()
			for _, c := range r.containersById {
				for dst := range c.lastConnectionAttempts {
					activeIPs[dst.IP()] = struct{}{}
				}
				if c.Dead(now) {
					deadContainers = append(deadContainers, c)
				}
			}
			r.containerLock.RUnlock()

			// Second pass: cleanup dead containers with write lock
			if len(deadContainers) > 0 {
				r.containerLock.Lock()
				for _, c := range deadContainers {
					// Double-check that container is still dead after acquiring write lock
					if !c.Dead(now) {
						continue
					}
					klog.Infoln("deleting dead container:", c.id)

					// Remove from all maps
					for cg, cc := range r.containersByCgroupId {
						if cc == c {
							delete(r.containersByCgroupId, cg)
						}
					}
					for pid, cc := range r.containersByPid {
						if cc == c {
							delete(r.containersByPid, pid)
						}
					}
					delete(r.containersById, c.id)
					c.Close()
				}
				r.containerLock.Unlock()
			}
			r.ip2fqdnLock.Lock()
			for ip := range r.ip2fqdn {
				if _, ok := activeIPs[ip]; !ok {
					delete(r.ip2fqdn, ip)
				}
			}
			r.ip2fqdnLock.Unlock()
			if r.llmDetector != nil {
				r.llmDetector.GC(llmDetectorMaxIPCache)
			}
		case sample := <-r.gpuProcessUsageSampleChan:
			r.containerLock.RLock()
			c := r.containersByPid[sample.Pid]
			r.containerLock.RUnlock()
			if c != nil {
				if p := c.processes[sample.Pid]; p != nil {
					p.addGpuUsageSample(sample)
				}
			}
		case e, more := <-ch:
			if !more {
				return
			}
			switch e.Type {
			case ebpftracer.EventTypeProcessStart:
				r.containerLock.RLock()
				c, seen := r.containersByPid[e.Pid]
				r.containerLock.RUnlock()
				switch { // possible pids wraparound + missed `process-exit` event
				case c == nil && seen: // ignored
					r.containerLock.Lock()
					delete(r.containersByPid, e.Pid)
					r.containerLock.Unlock()
				case c != nil: // revalidating by cgroup
					cg, err := proc.ReadCgroup(e.Pid)
					if err != nil || cg.Id != c.cgroup.Id {
						r.containerLock.Lock()
						delete(r.containersByPid, e.Pid)
						r.containerLock.Unlock()
						c.onProcessExit(e.Pid, false)
					}
				}
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					p := c.onProcessStart(e.Pid)
					if r.processInfoCh != nil && p != nil {
						r.processInfoCh <- ProcessInfo{Pid: p.Pid, ContainerId: c.id, StartedAt: p.StartedAt, Flags: p.Flags}
					}
				}
			case ebpftracer.EventTypeProcessExit:
				r.containerLock.RLock()
				c := r.containersByPid[e.Pid]
				r.containerLock.RUnlock()
				if c != nil {
					c.onProcessExit(e.Pid, e.Reason == ebpftracer.EventReasonOOMKill)
				}
				r.containerLock.Lock()
				delete(r.containersByPid, e.Pid)
				r.containerLock.Unlock()

			case ebpftracer.EventTypeFileOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onFileOpen(e.Pid, e.Fd, e.Mnt, e.Log)
				}

			case ebpftracer.EventTypeListenOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onListenOpen(e.Pid, e.SrcAddr, false)
					c.attachTlsUprobes(r.tracer, e.Pid)
				}
			case ebpftracer.EventTypeListenClose:
				r.containerLock.RLock()
				c := r.containersByPid[e.Pid]
				r.containerLock.RUnlock()
				if c != nil {
					c.onListenClose(e.Pid, e.SrcAddr)
				}

			case ebpftracer.EventTypeConnectionOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.ActualDstAddr, e.Timestamp, false, e.Duration)
					c.attachTlsUprobes(r.tracer, e.Pid)
				}
			case ebpftracer.EventTypeConnectionError:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.ActualDstAddr, 0, true, e.Duration)
				}
			case ebpftracer.EventTypeConnectionClose:
				r.containerLock.RLock()
				c := r.containersByPid[e.Pid]
				r.containerLock.RUnlock()
				if c != nil {
					c.onConnectionClose(e)
				}
			case ebpftracer.EventTypeTCPRetransmit:
				r.containerLock.RLock()
				containers := make([]*Container, 0, len(r.containersById))
				for _, c := range r.containersById {
					containers = append(containers, c)
				}
				r.containerLock.RUnlock()
				for _, c := range containers {
					if c.onRetransmission(e.SrcAddr, e.DstAddr) {
						break
					}
				}
			case ebpftracer.EventTypeL7Request:
				if e.L7Request == nil {
					continue
				}
				klog.V(5).Infof("L7_EVENT_REGISTRY: pid=%d fd=%d protocol=%d timestamp=%d",
					e.Pid, e.Fd, e.L7Request.Protocol, e.Timestamp)
				r.processL7Event(e)
			}
			// Process any pending L7 events after handling new events
			r.processPendingL7Events()
		}
	}
}

// processL7Event handles an L7 event, queueing it for retry if the connection isn't found yet
const maxIP2FQDNEntries = 10000

func (r *Registry) processL7Event(e ebpftracer.Event) {
	defer func() {
		if p := recover(); p != nil {
			klog.Errorf("recovered from panic in L7 event handler: pid=%d fd=%d protocol=%d: %v", e.Pid, e.Fd, e.L7Request.Protocol, p)
		}
	}()
	if c := r.containersByPid[e.Pid]; c != nil {
		klog.V(5).Infof("L7_EVENT_CONTAINER_FOUND: pid=%d container=%s", e.Pid, c.id)
		ip2fqdn, result := c.onL7RequestWithResult(e.Pid, e.Fd, e.Timestamp, e.L7Request, e.SocketInfo)
		if result == L7RequestConnNotFound {
			// Connection not found - queue for retry
			// This handles the race condition where L7 events (via ring buffer)
			// arrive before TCP connect events (via perf buffer)
			r.queueL7EventForRetry(e)
			return
		}
		r.ip2fqdnLock.Lock()
		for ip, domain := range ip2fqdn {
			if len(r.ip2fqdn) < maxIP2FQDNEntries {
				r.ip2fqdn[ip] = domain
			}
			r.ip_resolver.CacheDNS(ip.String(), domain.FQDN)
		}
		r.ip2fqdnLock.Unlock()
		// Feed DNS resolutions to LLM detector for connection-level detection
		r.feedDNSToLLMDetector(ip2fqdn)
	} else if e.L7Request.Protocol == l7.ProtocolTLSClientHello {
		// SNI events from pids not yet tracked in containersByPid (transient
		// processes, or the race where the main /app/services pid is sending
		// its first ClientHello before the agent's process detection has
		// indexed it). Queue for retry — by the time the agent processes
		// the next batch the pid is usually mapped.
		r.queueL7EventForRetry(e)
		return
	} else if e.L7Request.Protocol == l7.ProtocolDNS {
		// Handle DNS queries from non-monitored processes for global ip2fqdn mapping
		ip2fqdn := r.handleHostDNSRequest(e.L7Request)
		r.ip2fqdnLock.Lock()
		for ip, domain := range ip2fqdn {
			if len(r.ip2fqdn) < maxIP2FQDNEntries {
				r.ip2fqdn[ip] = domain
			}
			r.ip_resolver.CacheDNS(ip.String(), domain.FQDN)
		}
		r.ip2fqdnLock.Unlock()
		r.feedDNSToLLMDetector(ip2fqdn)
	}
}

// queueL7EventForRetry adds an L7 event to the pending queue for later retry
func (r *Registry) queueL7EventForRetry(e ebpftracer.Event) {
	r.pendingL7EventsLock.Lock()
	defer r.pendingL7EventsLock.Unlock()

	// Limit queue size to prevent memory issues
	const maxPendingEvents = 500
	if len(r.pendingL7Events) >= maxPendingEvents {
		klog.V(3).Infof("L7_EVENT_QUEUE_FULL: dropping event pid=%d fd=%d", e.Pid, e.Fd)
		return
	}

	klog.V(3).Infof("L7_EVENT_QUEUED: pid=%d fd=%d protocol=%d", e.Pid, e.Fd, e.L7Request.Protocol)
	r.pendingL7Events = append(r.pendingL7Events, pendingL7Event{
		event:      e,
		addedAt:    time.Now(),
		retryCount: 0,
	})
}

// processPendingL7Events retries pending L7 events
func (r *Registry) processPendingL7Events() {
	r.pendingL7EventsLock.Lock()
	if len(r.pendingL7Events) == 0 {
		r.pendingL7EventsLock.Unlock()
		return
	}

	// Process pending events (copy and clear to avoid holding lock during processing)
	pending := r.pendingL7Events
	r.pendingL7Events = nil
	r.pendingL7EventsLock.Unlock()

	const maxRetries = 3
	const maxAge = 5 * time.Second
	now := time.Now()

	var stillPending []pendingL7Event

	for _, p := range pending {
		// Expire old events
		if now.Sub(p.addedAt) > maxAge {
			klog.V(3).Infof("L7_EVENT_EXPIRED: pid=%d fd=%d age=%v", p.event.Pid, p.event.Fd, now.Sub(p.addedAt))
			continue
		}

		// Try to process the event
		c := r.containersByPid[p.event.Pid]
		if c == nil {
			if p.retryCount < maxRetries {
				p.retryCount++
				stillPending = append(stillPending, p)
			}
			continue
		}

		ip2fqdn, result, panicked := r.safeOnL7Request(c, p.event)
		if panicked {
			continue
		}
		if result == L7RequestConnNotFound {
			// Still not found - keep in queue if not exceeded max retries
			if p.retryCount < maxRetries {
				p.retryCount++
				stillPending = append(stillPending, p)
			} else {
				klog.V(3).Infof("L7_EVENT_MAX_RETRIES: pid=%d fd=%d", p.event.Pid, p.event.Fd)
			}
			continue
		}

		// Successfully processed
		klog.V(3).Infof("L7_EVENT_RETRY_SUCCESS: pid=%d fd=%d retries=%d", p.event.Pid, p.event.Fd, p.retryCount)
		r.ip2fqdnLock.Lock()
		for ip, domain := range ip2fqdn {
			r.ip2fqdn[ip] = domain
			r.ip_resolver.CacheDNS(ip.String(), domain.FQDN)
		}
		r.ip2fqdnLock.Unlock()
	}

	// Re-queue still pending events
	if len(stillPending) > 0 {
		r.pendingL7EventsLock.Lock()
		r.pendingL7Events = append(r.pendingL7Events, stillPending...)
		r.pendingL7EventsLock.Unlock()
	}
}

func (r *Registry) safeOnL7Request(c *Container, e ebpftracer.Event) (ip2fqdn map[netaddr.IP]*common.Domain, result L7RequestResult, panicked bool) {
	defer func() {
		if p := recover(); p != nil {
			klog.Errorf("recovered from panic in pending L7 retry: pid=%d fd=%d protocol=%d: %v", e.Pid, e.Fd, e.L7Request.Protocol, p)
			panicked = true
		}
	}()
	ip2fqdn, result = c.onL7RequestWithResult(e.Pid, e.Fd, e.Timestamp, e.L7Request, e.SocketInfo)
	return
}

func (r *Registry) getOrCreateContainer(pid uint32) *Container {
	// Fast path: try to find existing container with read lock
	lockStart := time.Now()

	r.containerLock.RLock()
	lockAcquireTime := time.Since(lockStart)
	if lockAcquireTime > 50*time.Millisecond {
		klog.Warningf("LOCK_CONTENTION: Registry read lock took %v (pid %d)", lockAcquireTime, pid)
	}

	if c := r.containersByPid[pid]; c != nil {
		r.containerLock.RUnlock()
		return c
	}
	if t := r.containersByPidIgnored[pid]; t != nil {
		if time.Since(*t) < IgnoredContainersCacheTTL {
			r.containerLock.RUnlock()
			return nil
		}
		// Will clean up ignored container later with write lock
	}
	r.containerLock.RUnlock()
	cg, err := proc.ReadCgroup(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln("failed to read proc cgroup:", err)
		}
		return nil
	}
	if strings.HasSuffix(cg.Id, "(deleted)") {
		return nil
	}

	// Check if container exists by cgroup ID with read lock
	r.containerLock.RLock()
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		r.containerLock.RUnlock()
		// Need write lock to update PID mapping
		r.containerLock.Lock()
		r.containersByPid[pid] = c
		r.containerLock.Unlock()
		return c
	}
	r.containerLock.RUnlock()
	if cg.ContainerType == cgroup.ContainerTypeSandbox {
		cmdline := proc.GetCmdline(pid)
		parts := bytes.Split(cmdline, []byte{0})
		if len(parts) > 0 {
			cmd := parts[0]
			lastArg := parts[len(parts)-1]
			if (bytes.HasSuffix(cmd, []byte("runsc-sandbox")) || bytes.HasSuffix(cmd, []byte("runsc"))) && containerIdRegexp.Match(lastArg) {
				cg.ContainerId = string(lastArg)
			}
		}
	}
	md, err := getContainerMetadata(cg)
	if err != nil {
		klog.Warningf("failed to get container metadata for pid %d -> %s: %s", pid, cg.Id, err)
		return nil
	}
	id := calcId(cg, md)
	if id == "" {
		if cg.Id == "/init.scope" && pid != 1 {
			klog.V(5).InfoS("ignoring without persisting", "cg", cg.Id, "pid", pid)
		} else {
			klog.V(5).InfoS("ignoring", "cg", cg.Id, "pid", pid)
			r.containerLock.Lock()
			t := time.Now()
			r.containersByPidIgnored[pid] = &t
			// Clean up stale ignored PIDs while we have the lock
			if oldT := r.containersByPidIgnored[pid]; oldT != nil && time.Since(*oldT) >= IgnoredContainersCacheTTL {
				delete(r.containersByPidIgnored, pid)
			}
			r.containerLock.Unlock()
		}
		return nil
	}
	if common.ContainerFilter.ShouldBeSkipped(string(id)) {
		klog.InfoS("skipping due to user-defined settings", "id", id, "pid", pid)
		r.containerLock.Lock()
		t := time.Now()
		r.containersByPidIgnored[pid] = &t
		r.containerLock.Unlock()
		return nil
	}
	if cg.ContainerType == cgroup.ContainerTypeSystemdService && *flags.SkipSystemdSystemServices {
		if md.systemd.IsSystemService() {
			klog.InfoS("skipping system service", "id", id, "unit", md.systemd.Unit, "type", md.systemd.Type, "triggered_by", md.systemd.TriggeredBy, "pid", pid)
			t := time.Now()
			r.containersByPidIgnored[pid] = &t
			return nil
		}
	}

	// Acquire write lock for container creation to prevent race conditions
	writeLockStart := time.Now()

	r.containerLock.Lock()
	writeLockAcquireTime := time.Since(writeLockStart)
	if writeLockAcquireTime > 100*time.Millisecond {
		klog.Warningf("LOCK_CONTENTION: Registry write lock took %v (pid %d)", writeLockAcquireTime, pid)
	}
	defer func() {
		writeLockHeldTime := time.Since(writeLockStart)
		if writeLockHeldTime > 500*time.Millisecond {
			klog.Warningf("LOCK_CONTENTION: Registry held write lock for %v (pid %d)", writeLockHeldTime, pid)
		}
		r.containerLock.Unlock()
	}()

	// Double-check pattern: verify container doesn't exist after acquiring write lock
	if c := r.containersByPid[pid]; c != nil {
		return c
	}
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		r.containersByPid[pid] = c
		return c
	}
	if c := r.containersById[id]; c != nil {
		klog.Warningln("id conflict, replacing container:", id)
		delete(r.containersById, c.id)
		for cgid, container := range r.containersByCgroupId {
			if container == c {
				delete(r.containersByCgroupId, cgid)
			}
		}
		for p, container := range r.containersByPid {
			if container == c {
				delete(r.containersByPid, p)
			}
		}
		c.Close()
	}

	// Create new container while holding write lock
	c, err := NewContainer(id, cg, md, pid, r)
	if err != nil {
		klog.Warningf("failed to create container pid=%d cg=%s id=%s: %s", pid, cg.Id, id, err)
		return nil
	}
	klog.InfoS("detected a new container", "pid", pid, "cg", cg.Id, "id", id, "app", c.appId)

	// Update all maps atomically while holding the lock
	r.containersByPid[pid] = c
	r.containersByCgroupId[cg.Id] = c
	r.containersById[id] = c
	return c
}

// updateEbpfStatsAndActiveConns reads eBPF maps and updates container stats
// directly from the event handler goroutine. Also refreshes active connection gauges.
func (r *Registry) updateEbpfStatsAndActiveConns() {
	// Traffic stats from eBPF maps
	iter := r.tracer.ActiveConnectionsIterator()
	cid := ebpftracer.ConnectionId{}
	stats := ebpftracer.Connection{}
	for iter.Next(&cid, &stats) {
		r.containerLock.RLock()
		c := r.containersByPid[cid.PID]
		r.containerLock.RUnlock()
		if c != nil {
			c.updateTrafficStats(&TrafficStatsUpdate{
				Pid:           cid.PID,
				FD:            cid.FD,
				BytesSent:     stats.BytesSent,
				BytesReceived: stats.BytesReceived,
				Protocol:      stats.Protocol,
			})
		}
	}
	if err := iter.Err(); err != nil {
		klog.Warningln(err)
	}

	// Node.js stats
	njsIter := r.tracer.NodejsStatsIterator()
	var pid uint64
	njsStats := ebpftracer.NodejsStats{}
	for njsIter.Next(&pid, &njsStats) {
		r.containerLock.RLock()
		c := r.containersByPid[uint32(pid)]
		r.containerLock.RUnlock()
		if c != nil {
			c.updateNodejsStats(NodejsStatsUpdate{Pid: uint32(pid), Stats: njsStats})
		}
	}
	if err := njsIter.Err(); err != nil {
		klog.Warningln(err)
	}

	// Python stats
	pyIter := r.tracer.PythonStatsIterator()
	pyStats := ebpftracer.PythonStats{}
	for pyIter.Next(&pid, &pyStats) {
		r.containerLock.RLock()
		c := r.containersByPid[uint32(pid)]
		r.containerLock.RUnlock()
		if c != nil {
			c.updatePythonStats(PythonStatsUpdate{Pid: uint32(pid), Stats: pyStats})
		}
	}
	if err := pyIter.Err(); err != nil {
		klog.Warningln(err)
	}

	// Refresh active connection gauges for all containers
	r.containerLock.RLock()
	containers := make([]*Container, 0, len(r.containersById))
	for _, c := range r.containersById {
		containers = append(containers, c)
	}
	r.containerLock.RUnlock()
	for _, c := range containers {
		c.refreshActiveConnections()
	}
}

// evictStaleCounterLabels removes CounterVec entries for destinations that no
// longer have active connections. Runs at gcInterval from the event handler goroutine.
func (r *Registry) evictStaleCounterLabels() {
	r.containerLock.RLock()
	containers := make([]*Container, 0, len(r.containersById))
	for _, c := range r.containersById {
		containers = append(containers, c)
	}
	r.containerLock.RUnlock()

	for _, c := range containers {
		activeKeys, activeFailedDsts := c.activeCounterLabelKeys()
		c.tcpMetrics.EvictStaleLabels(activeKeys, activeFailedDsts)
	}
}

func (r *Registry) getDomain(ip netaddr.IP) *common.Domain {
	r.ip2fqdnLock.RLock()
	defer r.ip2fqdnLock.RUnlock()
	return r.ip2fqdn[ip]
}

// feedDNSToLLMDetector notifies the LLM detector about DNS resolutions.
// This builds the IP→LLM provider cache for connection-level detection.
func (r *Registry) feedDNSToLLMDetector(ip2fqdn map[netaddr.IP]*common.Domain) {
	if r.llmDetector == nil || len(ip2fqdn) == 0 {
		return
	}
	for ip, domain := range ip2fqdn {
		if domain == nil || domain.FQDN == "" {
			continue
		}
		// OnDNS will check if it's an LLM provider internally
		r.llmDetector.OnDNS(domain.FQDN, []netaddr.IP{ip})
	}
}

// handleHostDNSRequest processes DNS queries from non-monitored processes
// to populate global ip2fqdn mapping for hostname resolution
func (r *Registry) handleHostDNSRequest(req *l7.RequestData) map[netaddr.IP]*common.Domain {
	status := req.Status.DNS()
	if status == "" {
		return nil
	}

	t, fqdn, ips := l7.ParseDns(req.Payload)
	if t == "" {
		return nil
	}
	fqdn = common.NormalizeFQDN(fqdn, t)

	// Skip AAAA requests with empty results (same logic as Container.onDNSRequest)
	if t == "TypeAAAA" && req.Status == 0 && len(ips) == 0 {
		return nil
	}

	// Create ip2fqdn mapping without container-specific metrics
	ip2fqdn := map[netaddr.IP]*common.Domain{}
	if fqdn != "" {
		d := common.NewDomain(fqdn, ips)
		for _, ip := range ips {
			ip2fqdn[ip] = d
		}
	}
	return ip2fqdn
}

func calcId(cg *cgroup.Cgroup, md *ContainerMetadata) ContainerID {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		if strings.HasPrefix(cg.ContainerId, "/system.slice/crio-conmon-") {
			return ""
		}
		// Skip systemd services that match the ignore control plane list
		if ignoreControlPlane(cg.ContainerId) {
			return ""
		}
		return ContainerID(cg.ContainerId)
	case cgroup.ContainerTypeTalosRuntime:
		return ContainerID(cg.ContainerId)
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return ""
	}
	if cg.ContainerId == "" {
		return ""
	}
	if md.labels["io.kubernetes.pod.name"] != "" {
		pod := md.labels["io.kubernetes.pod.name"]
		namespace := md.labels["io.kubernetes.pod.namespace"]
		name := md.labels["io.kubernetes.container.name"]
		if cg.ContainerType == cgroup.ContainerTypeSandbox {
			name = "sandbox"
		}
		if name == "" || name == "POD" { // skip pause containers
			return ""
		}
		if g := cronjobPodName.FindStringSubmatch(pod); len(g) == 3 {
			now := time.Now()
			tsMiniutes, _ := strconv.ParseUint(g[2], 10, 64)
			scheduledAt := time.Unix(int64(tsMiniutes)*60, 0)
			if scheduledAt.After(now.Add(-cronjobPodScheduleWindow)) && scheduledAt.Before(now.Add(cronjobPodScheduleWindow)) {
				return ContainerID(fmt.Sprintf("/k8s-cronjob/%s/%s/%s", namespace, g[1], name))
			}
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, name))
	}
	if taskNameParts := strings.SplitN(md.labels["com.docker.swarm.task.name"], ".", 3); len(taskNameParts) == 3 {
		namespace := md.labels["com.docker.stack.namespace"]
		service := md.labels["com.docker.swarm.service.name"]
		if namespace != "" {
			service = strings.TrimPrefix(service, namespace+"_")
		}
		if namespace == "" {
			namespace = "_"
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", namespace, service, taskNameParts[1]))
	}
	if md.env != nil {
		allocId := md.env["NOMAD_ALLOC_ID"]
		group := md.env["NOMAD_GROUP_NAME"]
		job := md.env["NOMAD_JOB_NAME"]
		namespace := md.env["NOMAD_NAMESPACE"]
		task := md.env["NOMAD_TASK_NAME"]
		if allocId != "" && group != "" && job != "" && namespace != "" && task != "" {
			return ContainerID(fmt.Sprintf("/nomad/%s/%s/%s/%s/%s", namespace, job, group, allocId, task))
		}
	}
	if md.name == "" { // should be "pure" dockerd container here
		klog.Warningln("empty dockerd container name for:", cg.ContainerId)
		return ""
	}
	return ContainerID("/docker/" + md.name)
}

func getContainerMetadata(cg *cgroup.Cgroup) (*ContainerMetadata, error) {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		var err error
		md := &ContainerMetadata{}
		md.systemd, err = getSystemdProperties(cg.Id)
		return md, err
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerId == "" {
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerType == cgroup.ContainerTypeCrio {
		return CrioInspect(cg.ContainerId)
	}
	var dockerdErr error
	if dockerdClient != nil {
		md, err := DockerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		dockerdErr = err
	}
	var containerdErr error
	if containerdClient != nil {
		md, err := ContainerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		containerdErr = err
	}
	return nil, fmt.Errorf("failed to interact with dockerd (%s) or with containerd (%s)", dockerdErr, containerdErr)
}

type TrafficStatsUpdate struct {
	Pid           uint32
	FD            uint64
	BytesSent     uint64
	BytesReceived uint64
	Protocol      uint8
}

type NodejsStatsUpdate struct {
	Pid   uint32
	Stats ebpftracer.NodejsStats
}

type PythonStatsUpdate struct {
	Pid   uint32
	Stats ebpftracer.PythonStats
}

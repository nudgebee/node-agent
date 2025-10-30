package containers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/pinger"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/tracing"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/nudgebee/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"golang.org/x/exp/maps"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	gcInterval                = 10 * time.Minute
	pingTimeout               = 300 * time.Millisecond
	multilineCollectorTimeout = time.Second
	payloadThreshold          = 1024 * 1024
	gpuStatsWindow            = 15 * time.Second
)

const (
	connectionStatsCacheSize = 8192 // LRU cache size for connection stats
)

type ContainerID string

type ContainerNetwork struct {
	NetworkID string
}

type ContainerMetadata struct {
	name               string
	labels             map[string]string
	volumes            map[string]string
	logPath            string
	image              string
	logDecoder         logparser.Decoder
	hostListens        map[string][]netaddr.IPPort
	networks           map[string]ContainerNetwork
	env                map[string]string
	systemdTriggeredBy string
}

type Delays struct {
	cpu  time.Duration
	disk time.Duration
}

type LLMStats struct {
	Provider         LLMProvider
	Model            string
	Host             string
	RequestCount     int64
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
	TotalLatency     time.Duration
}

// Removed complex HTTP fragment reassembly - using simple 5KB L7 events instead

type LogParser struct {
	parser *logparser.Parser
	stop   func()
}

func (p *LogParser) Stop() {
	if p.stop != nil {
		p.stop()
	}
	p.parser.Stop()
}

type ConnectionKey struct {
	src                netaddr.IPPort
	dst                netaddr.IPPort
	srcWorkload        common.Workload
	dstWorkload        common.Workload
	actualDestWorkload common.Workload
}

type ActiveConnection struct {
	DestinationKey     common.DestinationKey
	srcWorkload        common.Workload
	dstWorkload        common.Workload
	actualDestWorkload common.Workload
	Pid                uint32
	Fd                 uint64
	Timestamp          uint64
	Closed             time.Time

	BytesSent     uint64
	BytesReceived uint64
	Protocol      uint8

	http2Parser    *l7.Http2Parser
	postgresParser *l7.PostgresParser
	mysqlParser    *l7.MysqlParser
}

type ListenDetails struct {
	ClosedAt time.Time
	NsIPs    []netaddr.IP
}

type PidFd struct {
	Pid uint32
	Fd  uint64
}

type ConnectionStats struct {
	Count           uint64
	TotalTime       time.Duration
	Retransmissions uint64
	BytesSent       uint64
	BytesReceived   uint64
}

type Container struct {
	id       ContainerID
	appId    string
	cgroup   *cgroup.Cgroup
	metadata *ContainerMetadata

	processes map[uint32]*Process

	startedAt time.Time
	zombieAt  time.Time
	restarts  int

	delays      Delays
	delaysByPid map[uint32]Delays

	listens map[netaddr.IPPort]map[uint32]*ListenDetails

	connectionStats          *lru.Cache[common.DestinationKey, *ConnectionStats]
	failedConnectionAttempts map[common.HostPort]int64
	lastConnectionAttempts   map[common.HostPort]time.Time
	activeConnections        map[ConnectionKey]*ActiveConnection
	connectionsByPidFd       map[PidFd]*ActiveConnection

	l7Stats L7Stats

	llmStats map[string]*LLMStats

	gpuStats map[string]*GpuUsage

	oomKills    int
	nodejsStats *ebpftracer.NodejsStats
	pythonStats *ebpftracer.PythonStats

	mounts     map[string]proc.MountInfo
	seenMounts map[uint64]struct{}

	logParsers map[string]*LogParser
	logSamples map[string]string

	tracer *tracing.Tracer

	registry *Registry

	lock sync.RWMutex

	done        chan struct{}
	ip_resolver IPResolver
	srcWorkload common.Workload

	// Atomic throttling fields for lock-free access
	collectCallCount int64
	lastCollectTime  int64 // Unix nanoseconds
}

func NewContainer(id ContainerID, cg *cgroup.Cgroup, md *ContainerMetadata, pid uint32, registry *Registry) (*Container, error) {
	netNs, err := proc.GetNetNs(pid)
	if err != nil {
		return nil, err
	}
	defer netNs.Close()
	split := strings.Split(string(id), "/")
	if len(split) < 4 {
		klog.Errorf("unexpected container id %s", id)
		return nil, errors.New("unexpected container id")
	}
	namespace := split[2]
	podName := split[3]
	src_workload := registry.ip_resolver.ResolvePodOwner(podName, namespace)
	klog.Infof("Pod %s/%s is owned by %s/%s/%s", namespace, podName, src_workload.Name, src_workload.Namespace, src_workload.Kind)

	cid := string(id)
	appId := common.ContainerIdToOtelServiceName(cid)
	if appId == cid {
		appId = ""
	}
	c := &Container{
		id:       id,
		appId:    appId,
		cgroup:   cg,
		metadata: md,

		processes: map[uint32]*Process{},

		delaysByPid: map[uint32]Delays{},

		listens: map[netaddr.IPPort]map[uint32]*ListenDetails{},

		connectionStats:          nil, // Will be initialized below
		failedConnectionAttempts: map[common.HostPort]int64{},
		lastConnectionAttempts:   map[common.HostPort]time.Time{},
		activeConnections:        map[ConnectionKey]*ActiveConnection{},
		connectionsByPidFd:       map[PidFd]*ActiveConnection{},
		l7Stats:                  NewL7Stats(),

		llmStats: map[string]*LLMStats{},

		gpuStats: map[string]*GpuUsage{},

		mounts:     map[string]proc.MountInfo{},
		seenMounts: map[uint64]struct{}{},

		logParsers: map[string]*LogParser{},
		logSamples: map[string]string{},

		tracer: tracing.GetContainerTracer(string(id)),

		done:        make(chan struct{}),
		ip_resolver: registry.ip_resolver,
		registry:    registry,
		srcWorkload: src_workload,
	}

	// Initialize the LRU cache for connection stats
	connStatsCache, err := lru.New[common.DestinationKey, *ConnectionStats](connectionStatsCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection stats cache: %w", err)
	}
	c.connectionStats = connStatsCache

	c.runLogParser("")

	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case t := <-ticker.C:
				c.gc(t)
			}
		}
	}()

	return c, nil
}

func (c *Container) Close() {
	for _, p := range c.logParsers {
		p.Stop()
	}
	close(c.done)
}

func (c *Container) Dead(now time.Time) bool {
	return !c.zombieAt.IsZero() && now.Sub(c.zombieAt) > gcInterval
}

func (c *Container) Describe(ch chan<- *prometheus.Desc) {
	// some fixed metric description is required here to register/unregister the collector correctly
	ch <- prometheus.NewDesc("container", "", nil, nil)
}

func (c *Container) Collect(ch chan<- prometheus.Metric) {
	// Add comprehensive performance monitoring
	collectStart := time.Now()

	// Lock-free throttling using atomic operations
	currentCount := atomic.AddInt64(&c.collectCallCount, 1)
	now := time.Now()
	nowNanos := now.UnixNano()

	// Get last collection time atomically
	lastCollectNanos := atomic.LoadInt64(&c.lastCollectTime)
	timeSinceLastCall := time.Duration(nowNanos - lastCollectNanos)

	// Prevent duplicate metric emissions by ensuring minimum 1 second interval between collections
	if timeSinceLastCall < 1*time.Second && currentCount > 1 {
		klog.V(2).Infof("COLLECT_SKIP: Container %s skipped due to recent collection (%v ago)", c.id, timeSinceLastCall)
		return
	}

	// Update last collection time atomically
	atomic.StoreInt64(&c.lastCollectTime, nowNanos)

	// Track timing of different collection phases
	phaseStart := time.Now()

	if c.metadata.image != "" || c.metadata.systemdTriggeredBy != "" {
		ch <- gauge(metrics.ContainerInfo, 1, c.metadata.image, c.metadata.systemdTriggeredBy)
	}

	ch <- counter(metrics.Restarts, float64(c.restarts))

	if cpu := c.cgroup.CpuStat(); cpu != nil {
		if cpu.LimitCores > 0 {
			ch <- gauge(metrics.CPULimit, cpu.LimitCores)
		}
		ch <- counter(metrics.CPUUsage, cpu.UsageSeconds)
		ch <- counter(metrics.ThrottledTime, cpu.ThrottledTimeSeconds)
	}

	if taskstatsClient != nil {
		c.updateDelays()
		ch <- counter(metrics.CPUDelay, float64(c.delays.cpu)/float64(time.Second))
		ch <- counter(metrics.DiskDelay, float64(c.delays.disk)/float64(time.Second))
	}

	if s := c.cgroup.MemoryStat(); s != nil {
		ch <- gauge(metrics.MemoryRss, float64(s.RSS))
		ch <- gauge(metrics.MemoryCache, float64(s.Cache))
		if s.Limit > 0 {
			ch <- gauge(metrics.MemoryLimit, float64(s.Limit))
		}
	}

	if psi := c.cgroup.PSI(); psi != nil {
		ch <- counter(metrics.PsiCPU, psi.CPUSecondsSome, "some")
		ch <- counter(metrics.PsiCPU, psi.CPUSecondsFull, "full")
		ch <- counter(metrics.PsiMemory, psi.MemorySecondsSome, "some")
		ch <- counter(metrics.PsiMemory, psi.MemorySecondsFull, "full")
		ch <- counter(metrics.PsiIO, psi.IOSecondsSome, "some")
		ch <- counter(metrics.PsiIO, psi.IOSecondsFull, "full")
	}

	if c.oomKills > 0 {
		ch <- counter(metrics.OOMKills, float64(c.oomKills))
	}

	if disks, err := node.GetDisks(); err == nil {
		ioStat := c.cgroup.IOStat()
		for majorMinor, mounts := range c.getMounts() {
			var device string
			if dev := disks.GetParentBlockDevice(majorMinor); dev != nil {
				device = dev.Name
			}
			for mountPoint, fsStat := range mounts {
				dls := []string{mountPoint, device, c.metadata.volumes[mountPoint]}
				ch <- gauge(metrics.DiskSize, float64(fsStat.CapacityBytes), dls...)
				ch <- gauge(metrics.DiskUsed, float64(fsStat.UsedBytes), dls...)
				ch <- gauge(metrics.DiskReserved, float64(fsStat.ReservedBytes), dls...)
				if ioStat != nil {
					if io, ok := ioStat[majorMinor]; ok {
						ch <- counter(metrics.DiskReadOps, float64(io.ReadOps), dls...)
						ch <- counter(metrics.DiskReadBytes, float64(io.ReadBytes), dls...)
						ch <- counter(metrics.DiskWriteOps, float64(io.WriteOps), dls...)
						ch <- counter(metrics.DiskWriteBytes, float64(io.WrittenBytes), dls...)
					}
				}
			}
		}
	}

	// Log basic metrics phase timing
	basicMetricsTime := time.Since(phaseStart)
	if basicMetricsTime > 100*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s basic metrics took %v", c.id, basicMetricsTime)
	}
	phaseStart = time.Now()

	for addr, open := range c.getListens() {
		ch <- gauge(metrics.NetListenInfo, float64(open), addr.String(), "")
	}
	for proxy, addrs := range c.getProxiedListens() {
		for addr := range addrs {
			ch <- gauge(metrics.NetListenInfo, 1, addr.String(), proxy)
		}
	}

	// Log network listen metrics phase timing
	listenTime := time.Since(phaseStart)
	if listenTime > 100*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s listen metrics took %v", c.id, listenTime)
	}
	phaseStart = time.Now()

	for _, d := range c.connectionStats.Keys() {
		stats, ok := c.connectionStats.Peek(d)
		if !ok {
			continue
		}
		workload_src := c.srcWorkload
		workload_dest := d.GetDestinationWorkload()
		actualDestWorkload := d.GetActualDestinationWorkload()

		ch <- counter(metrics.NetConnectionsSuccessful, float64(stats.Count), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, workload_src.Region, workload_src.Zone, workload_dest.Region, workload_dest.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
		ch <- counter(metrics.NetConnectionsTotalTime, stats.TotalTime.Seconds(), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, workload_src.Region, workload_src.Zone, workload_dest.Region, workload_dest.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
		if stats.Retransmissions > 0 {
			ch <- counter(metrics.NetRetransmits, float64(stats.Retransmissions), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, workload_src.Region, workload_src.Zone, workload_dest.Region, workload_dest.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
		}
		ch <- counter(metrics.NetBytesSent, float64(stats.BytesSent), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, workload_src.Region, workload_src.Zone, workload_dest.Region, workload_dest.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
		ch <- counter(metrics.NetBytesReceived, float64(stats.BytesReceived), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, workload_src.Region, workload_src.Zone, workload_dest.Region, workload_dest.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
	}
	for dst, count := range c.failedConnectionAttempts {
		workload := c.ip_resolver.ResolveIP(dst.IP().String())
		ch <- counter(metrics.NetConnectionsFailed, float64(count), dst.String(), workload.Name, workload.Namespace, workload.Kind, workload.Name, workload.Namespace, workload.Kind, c.srcWorkload.Region, c.srcWorkload.Zone, workload.Region, workload.Zone, workload.Region, workload.Zone, workload.Instance)
	}

	// Log connection stats phase timing
	connStatsTime := time.Since(phaseStart)
	if connStatsTime > 500*time.Millisecond {
		klog.Warningf("COLLECT_TIMING: Container %s connection stats took %v", c.id, connStatsTime)
	} else if connStatsTime > 100*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s connection stats took %v", c.id, connStatsTime)
	}
	phaseStart = time.Now()

	connections := map[common.DestinationKey]int{}
	for _, conn := range c.activeConnections {
		if !conn.Closed.IsZero() {
			continue
		}
		connections[conn.DestinationKey]++
	}
	for d, count := range connections {
		actualDestWorkload := d.GetActualDestinationWorkload()
		destWorkload := d.GetDestinationWorkload()
		ch <- gauge(metrics.NetConnectionsActive, float64(count), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), c.srcWorkload.Name, c.srcWorkload.Namespace, c.srcWorkload.Kind, destWorkload.Name, destWorkload.Namespace, destWorkload.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind, c.srcWorkload.Region, c.srcWorkload.Zone, destWorkload.Region, destWorkload.Zone, actualDestWorkload.Region, actualDestWorkload.Zone, actualDestWorkload.Instance)
	}

	for source, p := range c.logParsers {
		for _, ctr := range p.parser.GetCounters() {
			if ctr.Level == logparser.LevelCritical || ctr.Level == logparser.LevelError {
				sample, ok := c.logSamples[ctr.Hash]
				if !ok {
					sample = common.TruncateUtf8(ctr.Sample, *flags.MaxLabelLength)
					c.logSamples[ctr.Hash] = sample
				}
				ch <- counter(metrics.LogMessages, float64(ctr.Messages), source, ctr.Level.String(), ctr.Hash, sample)
			}
		}
		for _, c := range p.parser.GetSensitiveCounters() {
			ch <- counter(metrics.SensitiveLogMessages, float64(c.Messages), source, c.Pattern, common.TruncateUtf8(c.Sample, *flags.MaxLabelLength), c.Regex, c.Name, c.Hash)
		}
	}

	appTypes := map[string]struct{}{}
	seenJvms := map[string]bool{}
	seenDotNetApps := map[string]bool{}
	pids := maps.Keys(c.processes)
	sort.Slice(pids, func(i, j int) bool {
		return pids[i] < pids[j]
	})

	for _, pid := range pids {
		process := c.processes[pid]
		cmdline := proc.GetCmdline(pid)
		if len(cmdline) == 0 {
			continue
		}
		if appType := guessApplicationTypeByCmdline(cmdline); appType != "" {
			appTypes[appType] = struct{}{}
		} else {
			if exe, err := os.Readlink(proc.Path(pid, "exe")); err == nil {
				if appType = guessApplicationTypeByExe(exe); appType != "" {
					appTypes[appType] = struct{}{}
				}
			}
		}
		if process.isGolangApp {
			appTypes["golang"] = struct{}{}
		}
		switch {
		case proc.IsJvm(cmdline):
			jvm, jMetrics := jvmMetrics(pid)
			if len(jMetrics) > 0 && !seenJvms[jvm] {
				seenJvms[jvm] = true
				for _, m := range jMetrics {
					ch <- m
				}
			}
		case process.dotNetMonitor != nil:
			appTypes["dotnet"] = struct{}{}
			appName := process.dotNetMonitor.AppName()
			if !seenDotNetApps[appName] {
				seenDotNetApps[appName] = true
				process.dotNetMonitor.Collect(ch)
			}
		}

		for _, usage := range c.gpuStats {
			usage.Reset()
		}
		if usage := process.getGPUUsage(); usage != nil {
			for uuid, u := range usage {
				tu := c.gpuStats[uuid]
				if tu == nil {
					tu = &GpuUsage{}
					c.gpuStats[uuid] = tu
				}
				tu.GPU += u.GPU
				tu.Memory += u.Memory
			}
		}
	}
	for uuid, usage := range c.gpuStats {
		ch <- gauge(metrics.GpuUsagePercent, usage.GPU, uuid)
		ch <- gauge(metrics.GpuMemoryUsagePercent, usage.Memory, uuid)
	}

	for appType := range appTypes {
		ch <- gauge(metrics.ApplicationType, 1, appType)
	}
	if c.pythonStats != nil {
		ch <- counter(metrics.PythonThreadLockWaitTime, c.pythonStats.ThreadLockWaitTime.Seconds())
	}
	if c.nodejsStats != nil {
		ch <- counter(metrics.NodejsEventLoopBlockedTime, c.nodejsStats.EventLoopBlockedTime.Seconds())
	}

	// LLM metrics collection
	for _, stats := range c.llmStats {
		ch <- counter(metrics.LLMRequests, float64(stats.RequestCount), string(stats.Provider), stats.Model, stats.Host)
		ch <- counter(metrics.LLMTokensUsed, float64(stats.PromptTokens), string(stats.Provider), stats.Model, "prompt", stats.Host)
		ch <- counter(metrics.LLMTokensUsed, float64(stats.CompletionTokens), string(stats.Provider), stats.Model, "completion", stats.Host)
		ch <- counter(metrics.LLMTokensUsed, float64(stats.TotalTokens), string(stats.Provider), stats.Model, "total", stats.Host)
		if stats.RequestCount > 0 {
			avgLatency := float64(stats.TotalLatency) / float64(stats.RequestCount) / float64(time.Second)
			ch <- gauge(metrics.LLMLatency, avgLatency, string(stats.Provider), stats.Model, stats.Host)
		}
	}

	// Log process and application metrics phase timing
	processTime := time.Since(phaseStart)
	if processTime > 500*time.Millisecond {
		klog.Warningf("COLLECT_TIMING: Container %s process metrics took %v", c.id, processTime)
	} else if processTime > 100*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s process metrics took %v", c.id, processTime)
	}
	phaseStart = time.Now()

	c.l7Stats.collect(ch)

	// Log L7 stats collection timing
	l7Time := time.Since(phaseStart)
	if l7Time > 1*time.Second {
		klog.Warningf("COLLECT_TIMING: Container %s L7 stats took %v", c.id, l7Time)
	} else if l7Time > 200*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s L7 stats took %v", c.id, l7Time)
	}
	phaseStart = time.Now()

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			destination_workload := c.ip_resolver.ResolveIP(ip.String())
			ch <- gauge(metrics.NetLatency, rtt, ip.String(), destination_workload.Name, destination_workload.Namespace, destination_workload.Kind, destination_workload.Instance)
		}
	}

	// Log final phase and total timing
	finalTime := time.Since(phaseStart)
	if finalTime > 100*time.Millisecond {
		klog.V(2).Infof("COLLECT_TIMING: Container %s final phase took %v", c.id, finalTime)
	}

	totalTime := time.Since(collectStart)
	if totalTime > 2*time.Second {
		klog.Errorf("COLLECT_SLOW: Container %s total Collect() took %v", c.id, totalTime)
	} else if totalTime > 1*time.Second {
		klog.Warningf("COLLECT_SLOW: Container %s total Collect() took %v", c.id, totalTime)
	} else if totalTime > 500*time.Millisecond {
		klog.V(1).Infof("COLLECT_TIMING: Container %s total Collect() took %v", c.id, totalTime)
	}
}

func (c *Container) onProcessStart(pid uint32) *Process {
	c.lock.Lock()
	defer c.lock.Unlock()
	stats, err := TaskstatsPID(pid)
	if err != nil {
		return nil
	}
	c.zombieAt = time.Time{}
	p := NewProcess(pid, stats, c.registry.tracer)

	if p == nil {
		return nil
	}
	c.processes[pid] = p

	if c.startedAt.IsZero() {
		c.startedAt = stats.BeginTime
	} else {
		min := stats.BeginTime
		for _, p := range c.processes {
			if p.StartedAt.Before(min) {
				min = p.StartedAt
			}
		}
		if min.After(c.startedAt) {
			c.restarts++
			c.startedAt = min
		}
	}
	return p
}

func (c *Container) onProcessExit(pid uint32, oomKill bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if p := c.processes[pid]; p != nil {
		p.Close()
	}
	delete(c.processes, pid)
	if len(c.processes) == 0 {
		c.zombieAt = time.Now()
	}
	delete(c.delaysByPid, pid)
	if oomKill {
		c.oomKills++
	}
}

func (c *Container) onFileOpen(pid uint32, fd uint64, mnt uint64, log bool) {
	if mnt > 0 && !log {
		c.lock.Lock()
		_, ok := c.seenMounts[mnt]
		c.lock.Unlock()
		if ok {
			return
		}
	}
	mntId, logPath := resolveFd(pid, fd)
	func() {
		if mntId == "" {
			return
		}
		c.lock.Lock()
		if mnt > 0 {
			c.seenMounts[mnt] = struct{}{}
		}
		_, ok := c.mounts[mntId]
		c.lock.Unlock()
		if ok {
			return
		}
		byMountId := proc.GetMountInfo(pid)
		if byMountId == nil {
			return
		}
		if mi, ok := byMountId[mntId]; ok {
			c.lock.Lock()
			c.mounts[mntId] = mi
			c.lock.Unlock()
		}
	}()
	if logPath != "" {
		if *flags.EnableDynamicLogTailing {
			c.lock.Lock()
			c.runLogParser(logPath)
			c.lock.Unlock()
		}
	}
}

func (c *Container) onListenOpen(pid uint32, addr netaddr.IPPort, safe bool) {
	klog.Infof("TCP listen open pid=%d id=%s addr=%s", pid, c.id, addr)
	if common.PortFilter.ShouldBeSkipped(addr.Port()) {
		return
	}
	if !safe {
		c.lock.Lock()
		defer c.lock.Unlock()
	}
	if _, ok := c.listens[addr]; !ok {
		c.listens[addr] = map[uint32]*ListenDetails{}
	}
	details := &ListenDetails{}
	c.listens[addr][pid] = details

	if addr.IP().IsUnspecified() {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			return
		}
		defer ns.Close()
		ips, err := proc.GetNsIps(ns)
		if err != nil {
			klog.Warningln(err)
			return
		}
		klog.Infof("got IPs %s for %s", ips, ns.UniqueId())
		details.NsIPs = ips
	}
}

func (c *Container) onListenClose(pid uint32, addr netaddr.IPPort) {
	klog.Infof("TCP listen close pid=%d id=%s addr=%s", pid, c.id, addr)
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, byAddr := c.listens[addr]; byAddr {
		if _, byPid := c.listens[addr][pid]; byPid {
			if details := c.listens[addr][pid]; details != nil {
				details.ClosedAt = time.Now()
			}
		}
	}
}

func ignoreControlPlane(name string) bool {
	keywords := strings.Split(*flags.IgnoreControlPlane, ",")
	if len(keywords) == 0 {
		return false
	}
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(name), keyword) {
			return true
		}
	}
	return false
}

func (c *Container) onConnectionOpen(pid uint32, fd uint64, src, dst, actualDst netaddr.IPPort, timestamp uint64, failed bool, duration time.Duration) {
	if common.PortFilter.ShouldBeSkipped(dst.Port()) {
		return
	}
	p := c.processes[pid]
	if p == nil {
		return
	}
	if dst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	if actualDst.Port() == 0 {
		if a := lookupCiliumConntrackTable(src, dst); a != nil {
			actualDst = *a
		} else {
			actualDst = dst
		}
	}

	srcWorkload := c.ip_resolver.ResolveIP(src.IP().String())
	if ignoreControlPlane(srcWorkload.Name) {
		return
	}
	dstWorkload := c.ip_resolver.ResolveIP(dst.IP().String())
	if ignoreControlPlane(dstWorkload.Name) {
		return
	}
	actualDstWorkload := c.ip_resolver.ResolveActualIP(actualDst.IP().String())
	if actualDst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	if common.ConnectionFilter.ShouldBeSkipped(dst.IP(), actualDst.IP()) {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	// Fast Path (or slow path that found no match):
	// Proceed with creating the key and updating stats as usual.
	key := common.NewDestinationKey(dst, actualDst, c.registry.getDomain(dst.IP()), dstWorkload, actualDstWorkload)

	if failed {
		c.failedConnectionAttempts[key.Destination()]++
	} else {
		stats, _ := c.connectionStats.Get(key)
		if stats == nil {
			stats = &ConnectionStats{}
			c.connectionStats.Add(key, stats)
		}
		stats.Count++
		stats.TotalTime += duration
		connection := &ActiveConnection{
			DestinationKey:     key,
			Pid:                pid,
			Fd:                 fd,
			Timestamp:          timestamp,
			srcWorkload:        srcWorkload,
			dstWorkload:        dstWorkload,
			actualDestWorkload: actualDstWorkload,
		}
		c.activeConnections[ConnectionKey{src: src, dst: dst}] = connection
		k := PidFd{Pid: pid, Fd: fd}
		prev := c.connectionsByPidFd[k]
		if prev != nil {
			prev.Closed = time.Now()
		}
		c.connectionsByPidFd[k] = connection
	}
	c.lastConnectionAttempts[key.Destination()] = time.Now()
}

func (c *Container) onConnectionClose(e ebpftracer.Event) {
	c.lock.Lock()
	conn := c.connectionsByPidFd[PidFd{Pid: e.Pid, Fd: e.Fd}]
	c.lock.Unlock()
	if conn != nil {
		if conn.Timestamp != 0 && conn.Timestamp != e.Timestamp {
			return
		}
		if conn.Closed.IsZero() {
			if e.TrafficStats != nil {
				c.lock.Lock()
				c.updateConnectionTrafficStats(conn, e.TrafficStats.BytesSent, e.TrafficStats.BytesReceived)
				c.lock.Unlock()
			}
			conn.Closed = time.Now()
		}
	}
}

func (c *Container) updateTrafficStats(u *TrafficStatsUpdate) {
	if u == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	conn := c.connectionsByPidFd[PidFd{Pid: u.Pid, Fd: u.FD}]
	if conn != nil {
		conn.Protocol = u.Protocol
	}
	c.updateConnectionTrafficStats(conn, u.BytesSent, u.BytesReceived)
}

func (c *Container) updateConnectionTrafficStats(ac *ActiveConnection, sent, received uint64) {
	if ac == nil {
		return
	}
	stats, _ := c.connectionStats.Get(ac.DestinationKey)
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats.Add(ac.DestinationKey, stats)
	}
	if sent > ac.BytesSent {
		stats.BytesSent += sent - ac.BytesSent
	}
	if received > ac.BytesReceived {
		stats.BytesReceived += received - ac.BytesReceived
	}
	ac.BytesSent = sent
	ac.BytesReceived = received
}

func (c *Container) trackLLMRequest(provider LLMProvider, host, payloadBase64, responseBase64 string, duration time.Duration) {
	// Parse request data
	llmReq, err := ParseLLMRequest(provider, payloadBase64)
	if err != nil || llmReq == nil {
		return // Skip tracking if we can't parse the request
	}

	// Parse response data for token usage
	llmResp, _ := ParseLLMResponse(provider, responseBase64)

	// Store LLM metrics for collection during next Collect() call
	c.lock.Lock()
	defer c.lock.Unlock()

	key := string(provider) + ":" + llmReq.Model + ":" + host
	stats := c.llmStats[key]
	if stats == nil {
		stats = &LLMStats{
			Provider: provider,
			Model:    llmReq.Model,
			Host:     host,
		}
		c.llmStats[key] = stats
	}

	// Update counters
	stats.RequestCount++
	stats.TotalLatency += duration

	if llmResp != nil {
		stats.PromptTokens += int64(llmResp.PromptTokens)
		stats.CompletionTokens += int64(llmResp.CompletionTokens)
		stats.TotalTokens += int64(llmResp.TotalTokens)
	}
}

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) map[netaddr.IP]*common.Domain {
	c.lock.Lock()
	defer c.lock.Unlock()

	conn := c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}]
	if conn == nil {
		return nil
	}
	if timestamp != 0 && conn.Timestamp != timestamp {
		return nil
	}

	// Check if eBPF traces are disabled (upstream feature)
	ebpfTracesDisabled := false
	for _, p := range c.processes {
		if p.Flags.EbpfTracesDisabled {
			ebpfTracesDisabled = true
			break
		}
	}

	// Create trace with proper parameters (enhanced version)
	var trace *tracing.Trace
	if !ebpfTracesDisabled {
		// Last-minute DNS enrichment for traces
		destWorkload := conn.DestinationKey.GetDestinationWorkload()
		actualDestWorkload := conn.DestinationKey.GetActualDestinationWorkload()
		if domain := c.registry.getDomain(conn.DestinationKey.ActualDestinationIfKnown().IP()); domain != nil {
			destWorkload.Name = domain.FQDN
			actualDestWorkload.Name = domain.FQDN
		}
		trace = c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown(), conn.srcWorkload, destWorkload, actualDestWorkload)
	}

	// Process L7 requests and update metrics
	switch r.Protocol {
	case l7.ProtocolDNS:
		status := r.Status.DNS()
		if status == "" {
			return nil
		}
		t, fqdn, ips := l7.ParseDns(r.Payload)
		if t == "" {
			return nil
		}
		// To reduce the number of metrics, we ignore AAAA requests with empty results
		if t == "TypeAAAA" && r.Status == 0 && len(ips) == 0 {
			return nil
		}
		c.l7Stats.observe(r.Protocol, status, t, r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")

		ip2fqdn := map[netaddr.IP]*common.Domain{}
		if fqdn != "" {
			d := common.NewDomain(common.NormalizeFQDN(fqdn, t), ips)
			for _, ip := range ips {
				ip2fqdn[ip] = d
			}
		}
		return ip2fqdn
	case l7.ProtocolHTTP:
		// Use new HTTP processor - parse once, use everywhere
		httpCtx := NewHTTPRequestProcessor(r, conn)

		// Update stats with extracted trace ID
		c.l7Stats.observe(r.Protocol, r.Status.Http(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, httpCtx.TraceID)

		// Debug logging for SSL payload capture (enable via environment variable)
		if os.Getenv("DEBUG_SSL_PAYLOAD") == "true" {
			log.Printf("SSL Payload Debug: %s -> %s: payload_len=%d, response_len=%d",
				conn.srcWorkload.Name, httpCtx.Host, len(r.Payload), len(r.Response))
		}

		// LLM tracking with improved detection
		if httpCtx.IsLLMRequest() {
			provider := httpCtx.GetLLMProvider()
			c.trackLLMRequest(provider, httpCtx.Host, httpCtx.PayloadBase64, httpCtx.ResponseBase64, r.Duration)
		}

		// Create trace with processed context
		if trace != nil {
			trace.HttpRequest(httpCtx.Method, httpCtx.Path, r.Status, r.Duration, r.PayloadSize,
				httpCtx.PayloadBase64, httpCtx.Headers, httpCtx.ResponseBase64, httpCtx.Host)
		}
	case l7.ProtocolHTTP2:
		// HTTP/2 stats will be updated in the loop below

		if conn.http2Parser == nil {
			conn.http2Parser = l7.NewHttp2Parser()
		}
		requests := conn.http2Parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		for _, req := range requests {
			if !common.HttpFilter.ShouldBeSkipped(req.Path) {
				status := req.Status.Http()
				if req.GrpcStatus >= 0 {
					status = req.GrpcStatus.GRPC()
				}
				c.l7Stats.observe(r.Protocol, status, "", req.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
				if trace != nil {
					trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.GrpcStatus, req.Duration)
				}
			}

			// Enhanced LLM API tracking for HTTP/2 (including gRPC-based LLM services)
			host := conn.DestinationKey.GetDestinationWorkload().Name

			// Use extracted HTTP/2 DATA frame payloads for LLM tracking
			requestPayloadBase64 := ""
			if len(req.RequestPayload) > 0 {
				requestPayloadBase64 = base64.StdEncoding.EncodeToString(req.RequestPayload)
			}

			responsePayloadBase64 := ""
			if len(req.ResponsePayload) > 0 {
				responsePayloadBase64 = base64.StdEncoding.EncodeToString(req.ResponsePayload)
			}

			provider := DetectLLMProvider(host)
			if provider == ProviderUnknown && len(req.RequestPayload) > 0 {
				// Fallback: Try to detect from HTTP/2 request and response payload
				provider = detectLLMFromHTTPRequest(req.RequestPayload, responsePayloadBase64)
			}

			if provider != ProviderUnknown && len(req.RequestPayload) > 0 {
				c.trackLLMRequest(provider, host, requestPayloadBase64, responsePayloadBase64, req.Duration)
			}
		}
	case l7.ProtocolPostgres:
		// Update stats for Postgres
		if r.Method != l7.MethodStatementClose {
			c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		}
		if conn.postgresParser == nil {
			conn.postgresParser = l7.NewPostgresParser()
		}
		query := conn.postgresParser.Parse(r.Payload)
		if trace != nil {
			trace.PostgresQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolMysql:
		// Update stats for MySQL
		if r.Method != l7.MethodStatementClose {
			c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		}
		if conn.mysqlParser == nil {
			conn.mysqlParser = l7.NewMysqlParser()
		}
		query := conn.mysqlParser.Parse(r.Payload, r.StatementId)
		if trace != nil {
			trace.MysqlQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolMemcached:
		// Update stats for Memcached
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		cmd, items := l7.ParseMemcached(r.Payload)
		if trace != nil {
			trace.MemcachedQuery(cmd, items, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolRedis:
		// Update stats for Redis
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		cmd, args := l7.ParseRedis(r.Payload)
		if trace != nil {
			trace.RedisQuery(cmd, args, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolMongo:
		// Update stats for Mongo
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		query := l7.ParseMongo(r.Payload)
		if trace != nil {
			trace.MongoQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolKafka, l7.ProtocolCassandra:
		// Update stats for Kafka/Cassandra
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		// Update stats for RabbitMQ/Nats
		c.l7Stats.observe(r.Protocol, r.Status.String(), r.Method.String(), 0, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolDubbo2:
		// Update stats for Dubbo2
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolClickhouse:
		// Update stats for Clickhouse
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		query := l7.ParseClickhouse(r.Payload)
		if trace != nil {
			trace.ClickhouseQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolZookeeper:
		// Update stats for Zookeeper
		c.l7Stats.observe(r.Protocol, r.Status.Zookeeper(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		op, arg := l7.ParseZookeeper(r.Payload)
		if trace != nil {
			trace.ZookeeperRequest(op, arg, r.Status, r.Duration)
		}
	case l7.ProtocolFoundationDB:
		// Update stats for FoundationDB
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	default:
		// For all other protocols, update stats
		c.l7Stats.observe(r.Protocol, "unknown", "", 0, conn.DestinationKey, conn.srcWorkload, r, "")
	}
	return nil
}

func (c *Container) onRetransmission(src netaddr.IPPort, dst netaddr.IPPort) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn, ok := c.activeConnections[ConnectionKey{src: src, dst: dst}]
	if !ok {
		return false
	}
	stats, _ := c.connectionStats.Get(conn.DestinationKey)
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats.Add(conn.DestinationKey, stats)
	}
	stats.Retransmissions++
	return true
}

func (c *Container) updateDelays() {
	for pid := range c.processes {
		stats, err := TaskstatsTGID(pid)
		if err != nil {
			continue
		}
		d := c.delaysByPid[pid]
		c.delays.cpu += stats.CPUDelay - d.cpu
		c.delays.disk += stats.BlockIODelay - d.disk
		d.cpu = stats.CPUDelay
		d.disk = stats.BlockIODelay
		c.delaysByPid[pid] = d
	}
}

func (c *Container) updateNodejsStats(s NodejsStatsUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()

	p := c.processes[s.Pid]
	if p == nil || p.nodejsPrevStats == nil {
		return
	}
	if delta := s.Stats.EventLoopBlockedTime - p.nodejsPrevStats.EventLoopBlockedTime; delta > 0 {
		if c.nodejsStats == nil {
			c.nodejsStats = &ebpftracer.NodejsStats{}
		}
		c.nodejsStats.EventLoopBlockedTime += delta
	}
	p.nodejsPrevStats = &s.Stats
}

func (c *Container) updatePythonStats(s PythonStatsUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()

	p := c.processes[s.Pid]
	if p == nil || p.pythonPrevStats == nil {
		return
	}
	if delta := s.Stats.ThreadLockWaitTime - p.pythonPrevStats.ThreadLockWaitTime; delta > 0 {
		if c.pythonStats == nil {
			c.pythonStats = &ebpftracer.PythonStats{}
		}
		c.pythonStats.ThreadLockWaitTime += delta
	}
	p.pythonPrevStats = &s.Stats
}

func (c *Container) getMounts() map[string]map[string]*proc.FSStat {
	if len(c.mounts) == 0 {
		return nil
	}
	res := map[string]map[string]*proc.FSStat{}
	for _, mi := range c.mounts {
		var stat *proc.FSStat
		for pid := range c.processes {
			s, err := proc.StatFS(proc.Path(pid, "root", mi.MountPoint))
			if err == nil {
				stat = &s
				break
			}
		}
		if stat == nil {
			continue
		}
		if _, ok := res[mi.MajorMinor]; !ok {
			res[mi.MajorMinor] = map[string]*proc.FSStat{}
		}
		res[mi.MajorMinor][mi.MountPoint] = stat
	}
	return res
}

func (c *Container) getListens() map[netaddr.IPPort]int {
	res := map[netaddr.IPPort]int{}
	for addr, byPid := range c.listens {
		open := 0
		isHostNs := false
		ips := map[netaddr.IP]bool{}
		for pid, details := range byPid {
			p := c.processes[pid]
			if p == nil {
				continue
			}
			if p.isHostNs() {
				isHostNs = true
			}
			if details.ClosedAt.IsZero() {
				open = 1
			}
			for _, ip := range details.NsIPs {
				ips[ip] = true
			}
		}
		if !addr.IP().IsUnspecified() {
			ips = map[netaddr.IP]bool{addr.IP(): true}
		}
		for ip := range ips {
			if ip.IsLoopback() && !isHostNs {
				continue
			}
			res[netaddr.IPPortFrom(ip, addr.Port())] = open
		}
	}
	return res
}

func (c *Container) getProxiedListens() map[string]map[netaddr.IPPort]struct{} {
	if len(c.metadata.hostListens) == 0 {
		return nil
	}

	hasUnspecified := false
	for _, addrs := range c.metadata.hostListens {
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				hasUnspecified = true
				break
			}
		}
	}

	var hostIps []netaddr.IP
	if hasUnspecified {
		if ns, err := proc.GetHostNetNs(); err != nil {
			klog.Warningln(err)
		} else {
			ips, err := proc.GetNsIps(ns)
			_ = ns.Close()
			if err != nil {
				klog.Warningln(err)
			} else {
				hostIps = ips
			}
		}
	}

	res := map[string]map[netaddr.IPPort]struct{}{}
	for proxy, addrs := range c.metadata.hostListens {
		res[proxy] = map[netaddr.IPPort]struct{}{}
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				for _, ip := range hostIps {
					if addr.IP().Is4() && ip.Is4() || addr.IP().Is6() && ip.Is6() {
						res[proxy][netaddr.IPPortFrom(ip, addr.Port())] = struct{}{}
					}
				}
			} else {
				res[proxy][addr] = struct{}{}
			}
		}
	}
	return res
}

func (c *Container) ping() map[netaddr.IP]float64 {
	netNs := netns.None()
	for pid := range c.processes {
		if pid == agentPid {
			netNs = selfNetNs
			break
		}
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			continue
		}
		netNs = ns
		defer netNs.Close()
		break
	}
	if !netNs.IsOpen() {
		return nil
	}

	ips := map[netaddr.IP]struct{}{}
	for _, d := range c.connectionStats.Keys() {
		if ip := d.ActualDestination().IP(); !ip.IsZero() {
			ips[ip] = struct{}{}
		}
	}
	for dst := range c.failedConnectionAttempts {
		if ip := dst.IP(); !ip.IsZero() {
			ips[dst.IP()] = struct{}{}
		}
	}
	if len(ips) == 0 {
		return nil
	}
	targets := make([]netaddr.IP, 0, len(ips))
	for ip := range ips {
		if ip.IsLoopback() {
			continue
		}
		if !ip.Is4() { // pinger doesn't support IPv6 yet
			continue
		}
		targets = append(targets, ip)
	}
	rtt, err := pinger.Ping(netNs, selfNetNs, targets, pingTimeout)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	return rtt
}

func (c *Container) runLogParser(logPath string) {
	if *flags.DisableLogParsing {
		return
	}

	for _, p := range c.processes {
		if p.Flags.LogMonitoringDisabled {
			klog.InfoS("skipping log monitoring due to COROOT_LOG_MONITORING=disabled", "cg", c.cgroup.Id)
			return
		}
	}

	containerId := string(c.id)

	if logPath != "" {
		if c.logParsers[logPath] != nil {
			return
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.DisableSensitiveLogParsing)
		reader, err := logs.NewTailReader(proc.HostPath(logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started logparser for container", c.id, "log", logPath)
		klog.InfoS("started varlog logparser", "cg", c.cgroup.Id, "log", logPath)
		c.logParsers[logPath] = &LogParser{parser: parser, stop: reader.Stop}
		return
	}

	switch c.cgroup.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		ch := make(chan logparser.LogEntry)
		if err := JournaldSubscribe(c.cgroup, ch); err != nil {
			klog.Warningln(err)
			return
		}
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.DisableSensitiveLogParsing)
		stop := func() {
			JournaldUnsubscribe(c.cgroup)
		}
		klog.InfoS("started logparser for container", c.id)
		klog.InfoS("started journald logparser", "cg", c.cgroup.Id)
		c.logParsers["journald"] = &LogParser{parser: parser, stop: stop}

	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeCrio:
		if c.metadata.logPath == "" {
			return
		}
		if parser := c.logParsers["stdout/stderr"]; parser != nil {
			parser.Stop()
			delete(c.logParsers, "stdout/stderr")
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, c.metadata.logDecoder, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.DisableSensitiveLogParsing)
		reader, err := logs.NewTailReader(proc.HostPath(c.metadata.logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started logparser for container", c.id, "log", c.metadata.logPath)
		klog.InfoS("started container logparser", "cg", c.cgroup.Id)
		c.logParsers["stdout/stderr"] = &LogParser{parser: parser, stop: reader.Stop}
	}
}

func (c *Container) gc(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()

	established := map[ConnectionKey]struct{}{}
	listens := map[netaddr.IPPort]string{}
	seenNamespaces := map[string]bool{}
	for _, p := range c.processes {
		if seenNamespaces[p.NetNsId()] {
			continue
		}
		sockets, err := proc.GetSockets(p.Pid)
		if err != nil {
			continue
		}
		for _, s := range sockets {
			if s.Listen {
				listens[s.SAddr] = s.Inode
			} else {
				established[ConnectionKey{src: s.SAddr, dst: s.DAddr}] = struct{}{}
			}
		}
		seenNamespaces[p.NetNsId()] = true
	}

	c.revalidateListens(now, listens)

	establishedDst := map[common.HostPort]struct{}{}
	for k, conn := range c.activeConnections {
		pidFd := PidFd{Pid: conn.Pid, Fd: conn.Fd}
		if _, ok := established[k]; !ok {
			delete(c.activeConnections, k)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
			continue
		} else {
			establishedDst[conn.DestinationKey.Destination()] = struct{}{}
		}
		if !conn.Closed.IsZero() && now.Sub(conn.Closed) > gcInterval {
			delete(c.activeConnections, k)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
		}
	}
	for dst, at := range c.lastConnectionAttempts {
		_, active := establishedDst[dst]
		if !active && !at.IsZero() && now.Sub(at) > gcInterval {
			delete(c.lastConnectionAttempts, dst)
			delete(c.failedConnectionAttempts, dst)
			for _, d := range c.connectionStats.Keys() {
				if d.Destination() == dst {
					c.connectionStats.Remove(d)
				}
			}
			c.l7Stats.delete(dst)
		}
	}
}

func (c *Container) revalidateListens(now time.Time, actualListens map[netaddr.IPPort]string) {
	for addr, byPid := range c.listens {
		if _, open := actualListens[addr]; open {
			continue
		}
		klog.Warningln("deleting the outdated listen:", addr)
		for _, details := range byPid {
			if details.ClosedAt.IsZero() {
				details.ClosedAt = now
			}
		}
	}

	missingListens := map[netaddr.IPPort]string{}
	for addr, inode := range actualListens {
		byPids, found := c.listens[addr]
		if !found {
			missingListens[addr] = inode
			continue
		}
		open := false
		for _, details := range byPids {
			if details.ClosedAt.IsZero() {
				open = true
				break
			}
		}
		if !open {
			missingListens[addr] = inode
		}
	}

	if len(missingListens) > 0 {
		inodeToPid := map[string]uint32{}
		for pid := range c.processes {
			fds, err := proc.ReadFds(pid)
			if err != nil {
				klog.Warningln(err)
				continue
			}
			for _, fd := range fds {
				if fd.SocketInode != "" {
					inodeToPid[fd.SocketInode] = pid
				}
			}
		}
		for addr, inode := range missingListens {
			pid, found := inodeToPid[inode]
			if !found {
				continue
			}
			klog.Warningln("missing listen found:", addr, pid)
			c.onListenOpen(pid, addr, true)
		}
	}

	for addr, pids := range c.listens {
		for pid, details := range pids {
			if !details.ClosedAt.IsZero() && now.Sub(details.ClosedAt) > gcInterval {
				delete(c.listens[addr], pid)
			}
		}
		if len(c.listens[addr]) == 0 {
			delete(c.listens, addr)
		}
	}
}

func (c *Container) attachTlsUprobes(tracer *ebpftracer.Tracer, pid uint32) {
	p := c.processes[pid]
	if p == nil {
		return
	}
	if !p.openSslUprobesChecked {
		openSslUprobes := tracer.AttachOpenSslUprobes(pid)
		p.uprobes = append(p.uprobes, openSslUprobes...)
		p.openSslUprobesChecked = true

		// Debug logging for SSL uprobes (enable via environment variable)
		if os.Getenv("DEBUG_SSL_UPROBES") == "true" && len(openSslUprobes) > 0 {
			log.Printf("SSL Debug: %s PID %d - OpenSSL uprobes attached: %d", c.srcWorkload.Name, pid, len(openSslUprobes))
		}
	}
	if !p.goTlsUprobesChecked {
		uprobes, isGolangApp := tracer.AttachGoTlsUprobes(pid)
		p.isGolangApp = isGolangApp
		p.uprobes = append(p.uprobes, uprobes...)
		p.goTlsUprobesChecked = true

		// Debug logging for Go TLS uprobes (enable via environment variable)
		if os.Getenv("DEBUG_SSL_UPROBES") == "true" && len(uprobes) > 0 {
			log.Printf("SSL Debug: %s PID %d - Go TLS uprobes attached: %d, isGolangApp: %v", c.srcWorkload.Name, pid, len(uprobes), isGolangApp)
		}
	}
}

func resolveFd(pid uint32, fd uint64) (mntId string, logPath string) {
	info := proc.GetFdInfo(pid, fd)
	if info == nil {
		return
	}
	switch {
	case info.Flags&os.O_WRONLY == 0 && info.Flags&os.O_RDWR == 0,
		!strings.HasPrefix(info.Dest, "/"),
		strings.HasPrefix(info.Dest, "/proc/"),
		strings.HasPrefix(info.Dest, "/dev/"),
		strings.HasPrefix(info.Dest, "/sys/"),
		strings.HasSuffix(info.Dest, "(deleted)"):
		return
	}
	mntId = info.MntId

	if info.Flags&os.O_WRONLY != 0 && strings.HasPrefix(info.Dest, "/var/log/") &&
		!strings.HasPrefix(info.Dest, "/var/log/pods/") &&
		!strings.HasPrefix(info.Dest, "/var/log/containers/") &&
		!strings.HasPrefix(info.Dest, "/var/log/journal/") {

		logPath = info.Dest
	}
	return
}

// detectLLMFromHTTPRequest detects LLM provider from HTTP request URL and response when hostname detection fails
func detectLLMFromHTTPRequest(requestPayload []byte, responseBase64 string) LLMProvider {
	// Parse HTTP request to extract URL path
	requestStr := string(requestPayload)

	// Look for URL patterns in the HTTP request
	if path := extractHTTPPath(requestStr); path != "" {
		// Google Gemini API patterns
		if strings.Contains(path, "/v1beta/models/gemini") ||
			strings.Contains(path, "generativelanguage.googleapis.com") ||
			strings.Contains(path, ":streamGenerateContent") ||
			strings.Contains(path, ":generateContent") {
			return ProviderGoogle
		}

		// OpenAI API patterns
		if strings.Contains(path, "/v1/chat/completions") ||
			strings.Contains(path, "/v1/completions") ||
			strings.Contains(path, "api.openai.com") {
			return ProviderOpenAI
		}

		// Anthropic API patterns
		if strings.Contains(path, "/v1/messages") ||
			strings.Contains(path, "api.anthropic.com") ||
			strings.Contains(path, "claude") {
			return ProviderAnthropic
		}

		// Cohere API patterns
		if strings.Contains(path, "/v1/generate") ||
			strings.Contains(path, "/v1/chat") ||
			strings.Contains(path, "api.cohere.ai") ||
			strings.Contains(path, "api.cohere.com") {
			return ProviderCohere
		}
	}

	// Fallback: Analyze response structure if available
	if responseBase64 != "" {
		if responseBytes, err := base64.StdEncoding.DecodeString(responseBase64); err == nil {
			return detectProviderFromResponseStructure(responseBytes)
		}
	}

	return ProviderUnknown
}

// extractHTTPPath extracts the URL path from HTTP request payload
func extractHTTPPath(request string) string {
	// Look for "GET /path" or "POST /path" patterns
	lines := strings.Split(request, "\n")
	if len(lines) > 0 {
		firstLine := lines[0]
		parts := strings.Fields(firstLine)
		if len(parts) >= 2 {
			return parts[1] // URL path
		}
	}

	// Also check Host header and full URLs
	if hostStart := strings.Index(request, "Host: "); hostStart != -1 {
		hostEnd := strings.Index(request[hostStart:], "\n")
		if hostEnd != -1 {
			hostLine := request[hostStart : hostStart+hostEnd]
			if host := strings.TrimPrefix(hostLine, "Host: "); host != "" {
				return strings.TrimSpace(host)
			}
		}
	}

	return ""
}

// detectProviderFromResponseStructure analyzes response JSON to identify provider
func detectProviderFromResponseStructure(responseData []byte) LLMProvider {
	// Look for JSON in response (skip HTTP headers)
	jsonStart := bytes.Index(responseData, []byte("{"))
	if jsonStart == -1 {
		return ProviderUnknown
	}

	jsonStr := string(responseData[jsonStart:])

	// Google Gemini: "candidates" array with "content" objects
	if (strings.Contains(jsonStr, `"candidates"`) && strings.Contains(jsonStr, `"content"`)) ||
		strings.Contains(jsonStr, `"usageMetadata"`) {
		return ProviderGoogle
	}

	// OpenAI: "choices" array with "message" objects
	if (strings.Contains(jsonStr, `"choices"`) && strings.Contains(jsonStr, `"message"`)) ||
		(strings.Contains(jsonStr, `"usage"`) && strings.Contains(jsonStr, `"prompt_tokens"`)) {
		return ProviderOpenAI
	}

	// Anthropic: "content" array with "text" objects
	if (strings.Contains(jsonStr, `"content"`) && strings.Contains(jsonStr, `"text"`)) ||
		(strings.Contains(jsonStr, `"usage"`) && strings.Contains(jsonStr, `"input_tokens"`)) {
		return ProviderAnthropic
	}

	// Cohere: "generations" array or "message" with "text"
	if strings.Contains(jsonStr, `"generations"`) ||
		(strings.Contains(jsonStr, `"meta"`) && strings.Contains(jsonStr, `"tokens"`)) {
		return ProviderCohere
	}

	return ProviderUnknown
}

func counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}

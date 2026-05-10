package containers

import (
	"errors"
	"os"
	"path/filepath"
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
	"github.com/nudgebee/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"golang.org/x/exp/maps"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	gcInterval                = 5 * time.Minute
	pingTimeout               = 300 * time.Millisecond
	multilineCollectorTimeout = time.Second
	payloadThreshold          = 1024 * 1024
	gpuStatsWindow            = 15 * time.Second
)

const (
	// Max per-connection HTTP/2 parsers per container.
	// Each parser holds HPACK decoders and active request state.
	maxHTTP2ParsersPerContainer = 50
)

type ContainerID string

type ContainerNetwork struct {
	NetworkID string
}

type ContainerMetadata struct {
	name        string
	labels      map[string]string
	volumes     map[string]string
	logPath     string
	image       string
	logDecoder  logparser.Decoder
	hostListens map[string][]netaddr.IPPort
	networks    map[string]ContainerNetwork
	env         map[string]string
	systemd     SystemdProperties
}

type Delays struct {
	cpu  time.Duration
	disk time.Duration
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
	src netaddr.IPPort
	dst netaddr.IPPort
}

type ActiveConnection struct {
	DestinationKey common.DestinationKey
	srcWorkload    common.Workload
	Pid            uint32
	Fd             uint64
	Timestamp      uint64
	Closed         time.Time

	BytesSent     uint64
	BytesReceived uint64
	Protocol      uint8

	http2Parser    *l7.Http2Parser
	postgresParser *l7.PostgresParser
	mysqlParser    *l7.MysqlParser

	parseFailCount   int
	protocolOverride l7.Protocol // non-zero = override eBPF-detected protocol
}

type ListenDetails struct {
	ClosedAt time.Time
	NsIPs    []netaddr.IP
}

type PidFd struct {
	Pid uint32
	Fd  uint64
}

type Container struct {
	id       ContainerID
	appId    string
	cgroup   *cgroup.Cgroup
	metadata *ContainerMetadata

	processes map[uint32]*Process

	startedAt time.Time
	zombieAt  time.Time

	delays      Delays
	delaysByPid map[uint32]Delays

	listens map[netaddr.IPPort]map[uint32]*ListenDetails

	lastConnectionAttempts map[common.HostPort]time.Time
	activeConnections      map[ConnectionKey]*ActiveConnection
	connectionsByPidFd     map[PidFd]*ActiveConnection
	googleHTTP2Parsers     map[PidFd]*l7.Http2Parser // Per-connection HTTP/2 parsers (keyed by pid:fd for correct HPACK state)

	l7Stats    L7Stats
	tcpMetrics *TCPMetrics

	// LLM observability pipeline
	llmDetector *LLMDetector // Connection-level LLM detection (shared across containers via registry)
	llmParser   *LLMParser   // Per-container LLM response parser

	gpuStats map[string]*GpuUsage

	nodejsStats *ebpftracer.NodejsStats
	pythonStats *ebpftracer.PythonStats

	mounts     map[string]proc.MountInfo
	seenMounts map[uint64]struct{}

	logParsers map[string]*LogParser
	logSamples sync.Map // map[string]string — hash -> truncated sample (write-once)

	tracer *tracing.Tracer

	registry *Registry

	lock sync.RWMutex

	done        chan struct{}
	ip_resolver IPResolver
	srcWorkload common.Workload
	constLabels []string // [container_id, app_id, machine_id, system_uuid, az, region]

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

	// Resolve workload based on container type
	var src_workload common.Workload
	idStr := string(id)
	split := strings.Split(idStr, "/")

	if strings.HasPrefix(idStr, "/k8s/") || strings.HasPrefix(idStr, "/k8s-cronjob/") {
		// Kubernetes container: /k8s/namespace/pod/container or /k8s-cronjob/namespace/job/container
		if len(split) < 4 {
			klog.Errorf("unexpected k8s container id %s", id)
			return nil, errors.New("unexpected container id")
		}
		namespace := split[2]
		podName := split[3]
		src_workload = registry.ip_resolver.ResolvePodOwner(podName, namespace)
		klog.Infof("Pod %s/%s is owned by %s/%s/%s", namespace, podName, src_workload.Name, src_workload.Namespace, src_workload.Kind)
	} else {
		// Non-k8s containers (docker, systemd, swarm, nomad): use container name as workload
		name := ""
		if len(split) > 0 {
			name = split[len(split)-1]
		}
		src_workload = common.Workload{Name: name, Kind: "container"}
		klog.V(2).Infof("Non-k8s container %s using workload name: %s", id, name)
	}

	cid := string(id)
	appId := common.ContainerIdToOtelServiceName(cid)
	if appId == cid {
		appId = ""
	}

	// Build const labels for direct embedding in metrics (avoids WrapRegistererWith overhead)
	nl := registry.nodeConstLabels
	nodeValues := nl.Values()
	constLabels := make([]string, 0, 2+len(nodeValues))
	constLabels = append(constLabels, cid, appId)
	constLabels = append(constLabels, nodeValues...)

	promConstLabels := prometheus.Labels{
		"container_id": cid,
		"app_id":       appId,
		"machine_id":   nl.MachineID,
		"system_uuid":  nl.SystemUUID,
		"az":           nl.AZ,
		"region":       nl.Region,
	}

	c := &Container{
		id:       id,
		appId:    appId,
		cgroup:   cg,
		metadata: md,

		processes: map[uint32]*Process{},

		delaysByPid: map[uint32]Delays{},

		listens: map[netaddr.IPPort]map[uint32]*ListenDetails{},

		lastConnectionAttempts: map[common.HostPort]time.Time{},
		activeConnections:      map[ConnectionKey]*ActiveConnection{},
		connectionsByPidFd:     map[PidFd]*ActiveConnection{},
		l7Stats:                NewL7Stats(promConstLabels),
		tcpMetrics:             NewTCPMetrics(promConstLabels),

		gpuStats: map[string]*GpuUsage{},

		mounts:     map[string]proc.MountInfo{},
		seenMounts: map[uint64]struct{}{},

		logParsers: map[string]*LogParser{},

		tracer: tracing.GetContainerTracer(string(id)),

		done:        make(chan struct{}),
		ip_resolver: registry.ip_resolver,
		registry:    registry,
		srcWorkload: src_workload,
		constLabels: constLabels,
	}

	// Initialize LLM pipeline
	c.llmDetector = registry.llmDetector
	c.llmParser = NewLLMParser(string(id), src_workload.Name, src_workload.Namespace,
		func(event *LLMEvent) {
			c.onLLMEvent(event)
		})

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
	// Stop the LLM parser
	if c.llmParser != nil {
		c.llmParser.Stop()
	}
	close(c.done)
}

func (c *Container) Dead(now time.Time) bool {
	return !c.zombieAt.IsZero() && now.Sub(c.zombieAt) > gcInterval
}

func (c *Container) Describe(ch chan<- *prometheus.Desc) {
	// Unchecked collector: each container emits varying metrics over its lifecycle
	// (different L7 protocols, connections, etc.), and we manage label uniqueness
	// via constLabels embedded directly in each metric.
	// Sending no descriptors lets prometheus handle registration/unregistration by pointer.
}

func (c *Container) Collect(ch chan<- prometheus.Metric) {
	collectStart := time.Now()

	// Throttle: prevent duplicate metric emissions within 1 second
	currentCount := atomic.AddInt64(&c.collectCallCount, 1)
	nowNanos := time.Now().UnixNano()
	lastCollectNanos := atomic.LoadInt64(&c.lastCollectTime)
	if time.Duration(nowNanos-lastCollectNanos) < 1*time.Second && currentCount > 1 {
		return
	}
	atomic.StoreInt64(&c.lastCollectTime, nowNanos)

	if c.metadata.image != "" || !c.metadata.systemd.IsEmpty() {
		ch <- c.gauge(metrics.ContainerInfo, 1, c.metadata.image, c.metadata.systemd.TriggeredBy, c.metadata.systemd.Type)
	}

	// --- Cgroup/procfs metrics (no c.lock needed) ---

	if cpu := c.cgroup.CpuStat(); cpu != nil {
		if cpu.LimitCores > 0 {
			ch <- c.gauge(metrics.CPULimit, cpu.LimitCores)
		}
		ch <- c.counter(metrics.CPUUsage, cpu.UsageSeconds)
		ch <- c.counter(metrics.ThrottledTime, cpu.ThrottledTimeSeconds)
	}

	if taskstatsClient != nil {
		c.updateDelays()
		ch <- c.counter(metrics.CPUDelay, float64(c.delays.cpu)/float64(time.Second))
		ch <- c.counter(metrics.DiskDelay, float64(c.delays.disk)/float64(time.Second))
	}

	if s := c.cgroup.MemoryStat(); s != nil {
		ch <- c.gauge(metrics.MemoryRss, float64(s.RSS))
		ch <- c.gauge(metrics.MemoryCache, float64(s.Cache))
		if s.Limit > 0 {
			ch <- c.gauge(metrics.MemoryLimit, float64(s.Limit))
		}
	}

	if psi := c.cgroup.PSI(); psi != nil {
		ch <- c.counter(metrics.PsiCPU, psi.CPUSecondsSome, "some")
		ch <- c.counter(metrics.PsiCPU, psi.CPUSecondsFull, "full")
		ch <- c.counter(metrics.PsiMemory, psi.MemorySecondsSome, "some")
		ch <- c.counter(metrics.PsiMemory, psi.MemorySecondsFull, "full")
		ch <- c.counter(metrics.PsiIO, psi.IOSecondsSome, "some")
		ch <- c.counter(metrics.PsiIO, psi.IOSecondsFull, "full")
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
				ch <- c.gauge(metrics.DiskSize, float64(fsStat.CapacityBytes), dls...)
				ch <- c.gauge(metrics.DiskUsed, float64(fsStat.UsedBytes), dls...)
				ch <- c.gauge(metrics.DiskReserved, float64(fsStat.ReservedBytes), dls...)
				if ioStat != nil {
					if io, ok := ioStat[majorMinor]; ok {
						ch <- c.counter(metrics.DiskReadOps, float64(io.ReadOps), dls...)
						ch <- c.counter(metrics.DiskReadBytes, float64(io.ReadBytes), dls...)
						ch <- c.counter(metrics.DiskWriteOps, float64(io.WriteOps), dls...)
						ch <- c.counter(metrics.DiskWriteBytes, float64(io.WrittenBytes), dls...)
					}
				}
			}
		}
	}

	// --- Listens: brief snapshot under c.lock ---
	c.lock.RLock()
	listens := c.getListens()
	proxiedListens := c.getProxiedListens()
	c.lock.RUnlock()

	for addr, open := range listens {
		ch <- c.gauge(metrics.NetListenInfo, float64(open), addr.String(), "")
	}
	for proxy, addrs := range proxiedListens {
		for addr := range addrs {
			ch <- c.gauge(metrics.NetListenInfo, 1, addr.String(), proxy)
		}
	}

	// --- TCP/connection metrics: push-model, no c.lock ---
	c.tcpMetrics.collect(ch)

	// --- Log metrics: use sync.Map for samples, brief c.lock for logParsers snapshot ---
	c.lock.RLock()
	logParsersCopy := make(map[string]*LogParser, len(c.logParsers))
	for k, v := range c.logParsers {
		logParsersCopy[k] = v
	}
	c.lock.RUnlock()

	for source, p := range logParsersCopy {
		for _, ctr := range p.parser.GetCounters() {
			if ctr.Level == logparser.LevelCritical || ctr.Level == logparser.LevelError {
				sample, _ := c.logSamples.LoadOrStore(ctr.Hash, common.TruncateUtf8(ctr.Sample, *flags.MaxLabelLength))
				ch <- c.counter(metrics.LogMessages, float64(ctr.Messages), source, ctr.Level.String(), ctr.Hash, sample.(string))
			}
		}
		for _, sc := range p.parser.GetSensitiveCounters() {
			ch <- c.counter(metrics.SensitiveLogMessages, float64(sc.Messages), source, sc.Pattern, common.TruncateUtf8(sc.Sample, *flags.MaxLabelLength), sc.Regex, sc.Name, sc.Hash)
		}
	}

	// --- Process-level metrics: brief snapshot under c.lock ---
	appTypes := map[string]struct{}{}
	seenJvms := map[string]bool{}
	seenDotNetApps := map[string]bool{}

	c.lock.RLock()
	processesCopy := make(map[uint32]*Process, len(c.processes))
	for pid, p := range c.processes {
		processesCopy[pid] = p
	}
	c.lock.RUnlock()

	pids := maps.Keys(processesCopy)
	sort.Slice(pids, func(i, j int) bool {
		return pids[i] < pids[j]
	})

	for _, pid := range pids {
		process := processesCopy[pid]
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
			jvm, jMetrics := c.jvmMetrics(pid)
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
		ch <- c.gauge(metrics.GpuUsagePercent, usage.GPU, uuid)
		ch <- c.gauge(metrics.GpuMemoryUsagePercent, usage.Memory, uuid)
	}

	for appType := range appTypes {
		ch <- c.gauge(metrics.ApplicationType, 1, appType)
	}
	if c.pythonStats != nil {
		ch <- c.counter(metrics.PythonThreadLockWaitTime, c.pythonStats.ThreadLockWaitTime.Seconds())
	}
	if c.nodejsStats != nil {
		ch <- c.counter(metrics.NodejsEventLoopBlockedTime, c.nodejsStats.EventLoopBlockedTime.Seconds())
	}

	// --- L7 metrics: push-model, own lock ---
	c.l7Stats.collect(ch)

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			destination_workload := c.ip_resolver.ResolveIP(ip.String())
			ch <- c.gauge(metrics.NetLatency, rtt, ip.String(), destination_workload.Name, destination_workload.Namespace, destination_workload.Kind)
		}
	}

	totalTime := time.Since(collectStart)
	if totalTime > 2*time.Second {
		klog.Errorf("COLLECT_SLOW: Container %s total Collect() took %v", c.id, totalTime)
	} else if totalTime > 1*time.Second {
		klog.Warningf("COLLECT_SLOW: Container %s total Collect() took %v", c.id, totalTime)
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
			c.tcpMetrics.ObserveRestart()
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
		c.tcpMetrics.ObserveOOMKill()
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
	c.lock.RLock()
	p := c.processes[pid]
	c.lock.RUnlock()
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

	key := common.NewDestinationKey(dst, actualDst, c.registry.getDomain(dst.IP()), dstWorkload, actualDstWorkload)

	if failed {
		c.tcpMetrics.ObserveConnectionFailed(key.Destination(), dstWorkload)
	} else {
		c.tcpMetrics.ObserveConnectionOpen(key, srcWorkload, duration.Seconds())
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if !failed {
		connection := &ActiveConnection{
			DestinationKey: key,
			Pid:            pid,
			Fd:             fd,
			Timestamp:      timestamp,
			srcWorkload:    srcWorkload,
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

// createConnectionFromSocketInfo creates an ActiveConnection from socket info extracted in eBPF
// This is used when TCP connection tracking fails (common for Go TLS due to goroutine thread switching)
// but we have socket tuple info extracted directly from the fd
func (c *Container) createConnectionFromSocketInfo(pid uint32, fd uint64, socketInfo *ebpftracer.SocketInfo) *ActiveConnection {
	if socketInfo == nil || !socketInfo.Valid {
		return nil
	}

	// Parse destination IP
	dstIP, err := netaddr.ParseIP(socketInfo.DstIP)
	if err != nil {
		klog.V(2).Infof("createConnectionFromSocketInfo: failed to parse dst IP %s: %v", socketInfo.DstIP, err)
		return nil
	}

	// Parse source IP
	srcIP, err := netaddr.ParseIP(socketInfo.SrcIP)
	if err != nil {
		klog.V(2).Infof("createConnectionFromSocketInfo: failed to parse src IP %s: %v", socketInfo.SrcIP, err)
		return nil
	}

	dst := netaddr.IPPortFrom(dstIP, socketInfo.DstPort)
	src := netaddr.IPPortFrom(srcIP, socketInfo.SrcPort)

	// Resolve workloads
	srcWorkload := c.ip_resolver.ResolveIP(src.IP().String())
	dstWorkload := c.ip_resolver.ResolveIP(dst.IP().String())
	actualDstWorkload := c.ip_resolver.ResolveActualIP(dst.IP().String())

	// Try to get DNS domain for destination
	domain := c.registry.getDomain(dst.IP())

	// Create destination key
	key := common.NewDestinationKey(dst, dst, domain, dstWorkload, actualDstWorkload)

	// Create connection
	connection := &ActiveConnection{
		DestinationKey: key,
		Pid:            pid,
		Fd:             fd,
		Timestamp:      0, // We don't have timestamp from socket info
		srcWorkload:    srcWorkload,
	}

	// Store in connectionsByPidFd for future L7 events on same connection
	k := PidFd{Pid: pid, Fd: fd}
	c.connectionsByPidFd[k] = connection

	klog.V(3).Infof("L7_CONN_CREATED_FROM_SOCKET: pid=%d fd=%d src=%s dst=%s domain=%v",
		pid, fd, src, dst, domain)

	return connection
}

func (c *Container) onConnectionClose(e ebpftracer.Event) {
	c.lock.Lock()
	conn := c.connectionsByPidFd[PidFd{Pid: e.Pid, Fd: e.Fd}]
	if conn == nil {
		c.lock.Unlock()
		return
	}
	if conn.Timestamp != 0 && conn.Timestamp != e.Timestamp {
		c.lock.Unlock()
		return
	}
	if conn.Closed.IsZero() {
		if e.TrafficStats != nil {
			c.updateConnectionTrafficStats(conn, e.TrafficStats.BytesSent, e.TrafficStats.BytesReceived)
		}
		conn.Closed = time.Now()
	}
	c.lock.Unlock()
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
	c.migrateConnectionKeyIfNeeded(ac)
	var sentDelta, recvDelta uint64
	if sent > ac.BytesSent {
		sentDelta = sent - ac.BytesSent
	}
	if received > ac.BytesReceived {
		recvDelta = received - ac.BytesReceived
	}
	ac.BytesSent = sent
	ac.BytesReceived = received
	if sentDelta > 0 || recvDelta > 0 {
		c.tcpMetrics.ObserveTraffic(ac.DestinationKey, ac.srcWorkload, sentDelta, recvDelta)
	}
}

// onLLMEvent is called by LLMParser when an LLM request completes (streaming or non-streaming).
// Single code path for all LLM metrics and traces.
func (c *Container) onLLMEvent(event *LLMEvent) {
	if event == nil {
		return
	}

	// Record Prometheus metrics
	RecordLLMEvent(event)

	// Emit OTel trace if tracer is available
	if c.tracer != nil {
		dstWorkload := common.Workload{Name: event.ServerAddress}
		trace := c.tracer.NewTrace(
			common.HostPortWithEmptyIP(event.ServerAddress, 443),
			c.srcWorkload,
			dstWorkload,
			dstWorkload,
		)
		if trace != nil {
			requestTime := time.Now().Add(-event.Duration)
			completionTime := time.Now()
			var firstTokenTime time.Time
			if event.TTFT > 0 {
				firstTokenTime = requestTime.Add(event.TTFT)
			}

			trace.LLMRequest(tracing.LLMStreamInfo{
				Provider:       string(event.Provider),
				Model:          event.Model,
				Operation:      event.Operation,
				ServerAddress:  event.ServerAddress,
				TraceID:        event.TraceID,
				ParentSpanID:   event.ParentSpanID,
				RequestTime:    requestTime,
				FirstTokenTime: firstTokenTime,
				CompletionTime: completionTime,
				InputTokens:    event.InputTokens,
				OutputTokens:   event.OutputTokens,
				StatusCode:     event.StatusCode,
				IsError:        event.StatusCode >= 400,
			})
		}
	}
}

// L7RequestResult indicates the result of processing an L7 request
type L7RequestResult int

const (
	L7RequestProcessed         L7RequestResult = iota // Event was processed successfully
	L7RequestConnNotFound                             // Connection not found - should retry
	L7RequestTimestampMismatch                        // Timestamp mismatch - don't retry
)

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) map[netaddr.IP]*common.Domain {
	ip2fqdn, _ := c.onL7RequestWithResult(pid, fd, timestamp, r, nil)
	return ip2fqdn
}

// enrichDestinationKey checks if the DestinationKey has an IP-based workload name
// and attempts to resolve it to an FQDN using the DNS cache. Returns the original
// key if no resolution is needed or available.
func (c *Container) enrichDestinationKey(key common.DestinationKey) common.DestinationKey {
	ip := key.ActualDestinationIfKnown().IP()
	if !common.IsIpExternal(ip) {
		return key
	}
	if isIPAddress(key.GetDestinationWorkload().Name) {
		if domain := c.registry.getDomain(ip); domain != nil {
			return key.WithResolvedDomain(domain.FQDN)
		}
	}
	return key
}

// migrateConnectionKeyToFQDN updates conn.DestinationKey from IP to the given FQDN.
// Must be called under c.lock.
func (c *Container) migrateConnectionKeyToFQDN(conn *ActiveConnection, fqdn string) {
	newKey := conn.DestinationKey.WithResolvedDomain(fqdn)
	conn.DestinationKey = newKey
}

// migrateConnectionKeyIfNeeded updates conn.DestinationKey from IP to FQDN when
// DNS becomes available.
// Must be called under c.lock.
func (c *Container) migrateConnectionKeyIfNeeded(conn *ActiveConnection) {
	if conn == nil {
		return
	}
	if !isIPAddress(conn.DestinationKey.GetDestinationWorkload().Name) {
		return
	}
	ip := conn.DestinationKey.ActualDestinationIfKnown().IP()
	if !common.IsIpExternal(ip) {
		return
	}
	domain := c.registry.getDomain(ip)
	if domain == nil {
		return
	}
	c.migrateConnectionKeyToFQDN(conn, domain.FQDN)
}

// onL7RequestWithResult processes an L7 request and returns the result along with whether it should be retried
// socketInfo contains connection tuple extracted directly from fd in eBPF (nil if extraction failed)
func (c *Container) onL7RequestWithResult(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData, socketInfo *ebpftracer.SocketInfo) (map[netaddr.IP]*common.Domain, L7RequestResult) {
	c.lock.Lock()
	defer c.lock.Unlock()

	conn := c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}]
	if conn == nil {
		// TCP connection tracking failed - common for Go TLS due to goroutine thread switching
		// Try to create connection from socket info extracted directly from fd in eBPF
		if socketInfo != nil && socketInfo.Valid {
			klog.V(3).Infof("L7_CREATING_CONN_FROM_SOCKET_INFO: pid=%d fd=%d dst=%s:%d container=%s",
				pid, fd, socketInfo.DstIP, socketInfo.DstPort, c.id)
			conn = c.createConnectionFromSocketInfo(pid, fd, socketInfo)
		}

		if conn == nil {
			// For HTTP/2 TLS connections, we can still process LLM detection using
			// the :authority header from HTTP/2 frames (fallback path)
			if r.Protocol == l7.ProtocolHTTP2 {
				klog.V(3).Infof("HTTP2_CONN_NOT_FOUND: pid=%d fd=%d container=%s - attempting connectionless processing",
					pid, fd, c.id)
				return c.processHTTP2WithoutConnection(pid, fd, r)
			}
			// TLS ClientHello SNI parsing needs only the payload, not the conn.
			// Go's crypto/tls runs the handshake on a goroutine that often
			// hasn't been associated with the fd yet via tcp_connect tracepoint
			// when the first ClientHello write fires; without this branch the
			// event would get queued, retried, and expire — defeating SNI-based
			// LLM tagging for the very connection where we need it most.
			if r.Protocol == l7.ProtocolTLSClientHello {
				host, err := l7.ParseSNI(r.Payload)
				if err != nil || host == "" || c.llmDetector == nil {
					return nil, L7RequestProcessed
				}
				pidFd := PidFd{Pid: pid, Fd: fd}
				if tag := c.llmDetector.LateTag(pidFd, host, netaddr.IP{}); tag != nil {
					LLMSNITagsTotal.WithLabelValues(string(tag.Provider)).Inc()
					klog.V(2).Infof("LLM_SNI_TAG_NOCONN: pid=%d fd=%d sni=%s provider=%s",
						pid, fd, host, tag.Provider)
				}
				return nil, L7RequestProcessed
			}
			klog.V(3).Infof("L7_EVENT_CONN_NOT_FOUND: pid=%d fd=%d container=%s num_connections=%d",
				pid, fd, c.id, len(c.connectionsByPidFd))
			return nil, L7RequestConnNotFound
		}
	}
	if timestamp != 0 && conn.Timestamp != timestamp {
		klog.V(5).Infof("L7_EVENT_TIMESTAMP_MISMATCH: pid=%d fd=%d event_ts=%d conn_ts=%d protocol=%d",
			pid, fd, timestamp, conn.Timestamp, r.Protocol)
		// For HTTP/2, fall through to connectionless processing instead of dropping.
		// This handles Go TLS connections (S2A, gRPC) where ensure_connection_tracked()
		// in eBPF creates entries with different timestamps than TCP tracepoints.
		// Pass the destination IP so DNS cache can resolve :authority when HPACK fails.
		if r.Protocol == l7.ProtocolHTTP2 {
			return c.processHTTP2WithoutConnection(pid, fd, r, conn.DestinationKey.ActualDestinationIfKnown().IP())
		}
		return nil, L7RequestTimestampMismatch
	}

	// Migrate connection key from IP to FQDN if DNS is now available
	// (fixes race condition where DNS wasn't cached at connection open time)
	c.migrateConnectionKeyIfNeeded(conn)

	// Check if eBPF traces are disabled (upstream feature)
	ebpfTracesDisabled := false
	for _, p := range c.processes {
		if p.Flags.EbpfTracesDisabled {
			ebpfTracesDisabled = true
			break
		}
	}

	// Create trace — migrateConnectionKeyIfNeeded already enriched the key with FQDN
	var trace *tracing.Trace
	if !ebpfTracesDisabled {
		destWorkload := conn.DestinationKey.GetDestinationWorkload()
		actualDestWorkload := conn.DestinationKey.GetActualDestinationWorkload()
		trace = c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown(), conn.srcWorkload, destWorkload, actualDestWorkload)
	}

	// Protocol reclassification: if previous parse attempts failed repeatedly,
	// the connection was likely misidentified by eBPF heuristics. Use the
	// override to skip further parsing for this connection.
	protocol := r.Protocol
	if conn.protocolOverride != 0 {
		protocol = conn.protocolOverride
	}

	// Process L7 requests and update metrics
	switch protocol {
	case l7.ProtocolDNS:
		status := r.Status.DNS()
		if status == "" {
			return nil, L7RequestProcessed
		}
		t, fqdn, ips := l7.ParseDns(r.Payload)
		if t == "" {
			return nil, L7RequestProcessed
		}
		// To reduce the number of metrics, we ignore AAAA requests with empty results
		if t == "TypeAAAA" && r.Status == 0 && len(ips) == 0 {
			return nil, L7RequestProcessed
		}
		c.l7Stats.observe(r.Protocol, status, t, "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")

		ip2fqdn := map[netaddr.IP]*common.Domain{}
		if fqdn != "" {
			d := common.NewDomain(common.NormalizeFQDN(fqdn, t), ips)
			for _, ip := range ips {
				ip2fqdn[ip] = d
			}
		}
		return ip2fqdn, L7RequestProcessed
	case l7.ProtocolHTTP:
		// DNS resolver function - allows HTTP processor to lookup hostnames at request time
		// This fixes the race condition where DNS cache wasn't populated at connection time
		dnsResolver := func(ip netaddr.IP) string {
			if domain := c.registry.getDomain(ip); domain != nil {
				return domain.FQDN
			}
			return ""
		}

		// Use new HTTP processor - parse once, use everywhere
		httpCtx := NewHTTPRequestContext(r, conn, dnsResolver)

		// If DestinationKey still has a raw IP but the HTTP Host header has an FQDN,
		// use it to update the connection key and populate ip_to_fqdn.
		var ip2fqdn map[netaddr.IP]*common.Domain
		if isIPAddress(conn.DestinationKey.GetDestinationWorkload().Name) &&
			httpCtx.Host != "" && !isIPAddress(httpCtx.Host) {
			ip := conn.DestinationKey.ActualDestinationIfKnown().IP()
			if common.IsIpExternal(ip) {
				c.migrateConnectionKeyToFQDN(conn, httpCtx.Host)
				domain := common.NewDomain(httpCtx.Host, []netaddr.IP{ip})
				ip2fqdn = map[netaddr.IP]*common.Domain{ip: domain}
			}
		}

		// Update stats with extracted trace ID (uses resolved key if migrated above)
		c.l7Stats.observe(r.Protocol, r.Status.Http(), httpCtx.Method, httpCtx.Path, r.Duration, conn.DestinationKey, conn.srcWorkload, r, httpCtx.TraceID)

		// LLM tracking via DNS-based connection detection
		if c.llmParser != nil {
			httpPidFd := PidFd{Pid: pid, Fd: fd}
			destIP := conn.DestinationKey.ActualDestinationIfKnown().IP()
			llmTag := c.llmDetector.IsLLMConnection(httpPidFd, destIP)
			// Late-tag fallback from Host header
			if llmTag == nil && httpCtx.Host != "" {
				llmTag = c.llmDetector.LateTag(httpPidFd, httpCtx.Host, destIP)
			}
			if llmTag != nil {
				c.llmParser.ParseHTTP1(llmTag, int(r.Status),
					httpCtx.Path, extractHTTPBody(r.Payload), extractHTTPBody(r.Response),
					r.Duration, httpCtx.TraceID)
			}
		}

		// Create trace with processed context
		if trace != nil {
			trace.HttpRequest(httpCtx.Method, httpCtx.Path, r.Status, r.Duration, r.PayloadSize,
				httpCtx.PayloadBase64, httpCtx.Headers, httpCtx.ResponseBase64, httpCtx.Host)
		}
		if ip2fqdn != nil {
			return ip2fqdn, L7RequestProcessed
		}
	case l7.ProtocolHTTP2:
		// HTTP/2 stats will be updated in the loop below
		// Each HTTP/2 connection has its own HPACK dynamic table, so we use per-fd
		// parsers to avoid header decoding corruption across connections.
		if c.googleHTTP2Parsers == nil {
			c.googleHTTP2Parsers = make(map[PidFd]*l7.Http2Parser)
		}
		pidFd := PidFd{Pid: pid, Fd: fd}
		if c.googleHTTP2Parsers[pidFd] == nil {
			if len(c.googleHTTP2Parsers) >= maxHTTP2ParsersPerContainer {
				return nil, L7RequestProcessed
			}
			p := l7.NewHttp2Parser()
			p.Lightweight = true
			p.LLMHostChecker = isLLMRelevantHost
			c.googleHTTP2Parsers[pidFd] = p
		}
		parser := c.googleHTTP2Parsers[pidFd]
		conn.http2Parser = parser // Keep reference on connection for compatibility
		requests := parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		activeCount := parser.ActiveRequestCount()
		if activeCount > 0 {
			klog.V(3).Infof("HTTP2_PARSE_RESULT: pid=%d fd=%d completed=%d active=%d",
				pid, fd, len(requests), activeCount)
		}

		// If DestinationKey still has a raw IP, try to resolve from :authority header
		if isIPAddress(conn.DestinationKey.GetDestinationWorkload().Name) {
			for _, req := range requests {
				authority := stripPort(req.Authority)
				if authority != "" && !isIPAddress(authority) {
					ip := conn.DestinationKey.ActualDestinationIfKnown().IP()
					if common.IsIpExternal(ip) {
						c.migrateConnectionKeyToFQDN(conn, authority)
						domain := common.NewDomain(authority, []netaddr.IP{ip})
						return map[netaddr.IP]*common.Domain{ip: domain}, L7RequestProcessed
					}
					break
				}
			}
		}

		// Feed active streams to LLM parser if this is an LLM-tagged connection
		destIP := conn.DestinationKey.ActualDestinationIfKnown().IP()
		llmTag := c.llmDetector.IsLLMConnection(pidFd, destIP)

		// Late-tag fallback: if not tagged yet, check :authority from parsed requests
		if llmTag == nil {
			for _, req := range requests {
				authority := stripPort(req.Authority)
				if authority != "" && !isIPAddress(authority) {
					llmTag = c.llmDetector.LateTag(pidFd, authority, destIP)
					if llmTag != nil {
						break
					}
				}
			}
		}

		if klog.V(4).Enabled() {
			activeStreamsDbg := parser.GetActiveStreamsForLLM()
			authorities := []string{}
			respLens := []int{}
			hasStatus := []bool{}
			for _, u := range activeStreamsDbg {
				authorities = append(authorities, u.Authority)
				respLens = append(respLens, len(u.ResponsePayload))
				hasStatus = append(hasStatus, u.HasResponseStatus)
			}
			tagStr := "nil"
			if llmTag != nil {
				tagStr = string(llmTag.Provider) + "/" + llmTag.Host
			}
			klog.V(4).Infof("LLM_ROUTE: pid=%d fd=%d destIP=%s llmTag=%s activeStreams=%d authorities=%v respLens=%v hasStatus=%v requestsLen=%d",
				pid, fd, destIP, tagStr, len(activeStreamsDbg), authorities, respLens, hasStatus, len(requests))
		}

		if llmTag != nil && c.llmParser != nil {
			activeStreams := parser.GetActiveStreamsForLLM()
			for _, update := range activeStreams {
				// Feed request data
				c.llmParser.FeedHTTP2Data(llmTag, update.StreamId,
					nil, false, update.Path, 0, update.RequestHeaders)

				// Feed response status
				if update.HasResponseStatus {
					c.llmParser.OnHTTP2Status(update.StreamId, int(update.Status))
				}

				// Feed response data
				if len(update.ResponsePayload) > 0 {
					c.llmParser.FeedHTTP2Data(llmTag, update.StreamId,
						update.ResponsePayload, true, update.Path, int(update.Status), nil)
				}
			}
		}
		for _, req := range requests {
			klog.V(4).Infof("HTTP2_COMPLETED_REQUEST: pid=%d fd=%d method=%s path=%s status=%d req_payload_len=%d resp_payload_len=%d",
				pid, fd, req.Method, req.Path, req.Status, len(req.RequestPayload), len(req.ResponsePayload))
			if !common.HttpFilter.ShouldBeSkipped(req.Path) {
				status := req.Status.Http()
				if req.GrpcStatus >= 0 {
					status = req.GrpcStatus.GRPC()
				}
				c.l7Stats.observe(r.Protocol, status, "", "", req.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
				if trace != nil {
					trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.GrpcStatus, req.Duration)
				}
			}

			// HTTP/2 LLM tracking is handled by the LLM parser above via FeedHTTP2Data.
		}
	case l7.ProtocolPostgres:
		// Update stats for Postgres
		if r.Method != l7.MethodStatementClose {
			c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		}
		if conn.postgresParser == nil {
			conn.postgresParser = l7.NewPostgresParser()
		}
		query := conn.postgresParser.Parse(r.Payload)
		if query == "" && r.Method != l7.MethodStatementClose {
			c.trackParseFail(conn, pid, fd, r.Protocol)
		} else {
			conn.parseFailCount = 0
		}
		if trace != nil {
			trace.PostgresQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolMysql:
		// Update stats for MySQL
		if r.Method != l7.MethodStatementClose {
			c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
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
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		cmd, items := l7.ParseMemcached(r.Payload)
		if trace != nil {
			trace.MemcachedQuery(cmd, items, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolRedis:
		// Update stats for Redis
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		cmd, args := l7.ParseRedis(r.Payload)
		if trace != nil {
			trace.RedisQuery(cmd, args, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolMongo:
		// Update stats for Mongo
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		query := l7.ParseMongo(r.Payload)
		if trace != nil {
			trace.MongoQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolKafka, l7.ProtocolCassandra:
		// Update stats for Kafka/Cassandra
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		// Update stats for RabbitMQ/Nats
		c.l7Stats.observe(r.Protocol, r.Status.String(), r.Method.String(), "", 0, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolDubbo2:
		// Update stats for Dubbo2
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolClickhouse:
		// Update stats for Clickhouse
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		query := l7.ParseClickhouse(r.Payload)
		if query == "" {
			c.trackParseFail(conn, pid, fd, r.Protocol)
		} else {
			conn.parseFailCount = 0
		}
		if trace != nil {
			trace.ClickhouseQuery(query, r.Status.Error(), r.Duration)
		}
	case l7.ProtocolZookeeper:
		// Update stats for Zookeeper
		c.l7Stats.observe(r.Protocol, r.Status.Zookeeper(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
		op, arg := l7.ParseZookeeper(r.Payload)
		if op == "" {
			c.trackParseFail(conn, pid, fd, r.Protocol)
		} else {
			conn.parseFailCount = 0
		}
		if trace != nil {
			trace.ZookeeperRequest(op, arg, r.Status, r.Duration)
		}
	case l7.ProtocolFoundationDB:
		// Update stats for FoundationDB
		c.l7Stats.observe(r.Protocol, r.Status.String(), "", "", r.Duration, conn.DestinationKey, conn.srcWorkload, r, "")
	case l7.ProtocolTLSClientHello:
		// SNI-based LLM detection. The eBPF side captures TLS ClientHello
		// records on outbound port-443 writes; here we parse the SNI and
		// tag the connection if it matches a known LLM provider. This
		// fires once per TCP connection (at handshake) and is independent
		// of HPACK state, so it works for HTTP/2 connections where
		// :authority parsing fails after a mid-stream agent attach.
		host, err := l7.ParseSNI(r.Payload)
		if err != nil || host == "" || c.llmDetector == nil {
			return nil, L7RequestProcessed
		}
		destIP := conn.DestinationKey.ActualDestinationIfKnown().IP()
		pidFd := PidFd{Pid: pid, Fd: fd}
		if tag := c.llmDetector.LateTag(pidFd, host, destIP); tag != nil {
			LLMSNITagsTotal.WithLabelValues(string(tag.Provider)).Inc()
			klog.V(2).Infof("LLM_SNI_TAG: pid=%d fd=%d sni=%s provider=%s",
				pid, fd, host, tag.Provider)
		}
	default:
		// For all other protocols, update stats
		c.l7Stats.observe(r.Protocol, "unknown", "", "", 0, conn.DestinationKey, conn.srcWorkload, r, "")
	}
	return nil, L7RequestProcessed
}

const (
	parseFailThreshold   = 3
	protocolReclassified = l7.Protocol(0xFF) // sentinel: no protocol matches, hits default case
)

// trackParseFail tracks consecutive parse failures on a connection. After
// parseFailThreshold failures, the connection's protocol is overridden to
// skip further parsing. This handles eBPF protocol misidentification where
// weak heuristics (e.g., 3-byte ClickHouse check) tag a non-matching
// connection permanently.
func (c *Container) trackParseFail(conn *ActiveConnection, pid uint32, fd uint64, proto l7.Protocol) {
	conn.parseFailCount++
	if conn.parseFailCount == parseFailThreshold {
		conn.protocolOverride = protocolReclassified
		klog.Warningf("reclassified connection pid=%d fd=%d from %s to unknown after %d consecutive parse failures",
			pid, fd, proto, conn.parseFailCount)
	}
}

// processHTTP2WithoutConnection handles HTTP/2 events when TCP connection tracking failed.
// This is common for Go TLS connections where goroutines switch threads between
// TCP connect and TLS write, causing fd_by_pid_tgid lookup to fail in eBPF.
//
// Uses LLMDetector for fast IP-based detection. No skip-set needed — the detector
// handles caching at the connection level.
func (c *Container) processHTTP2WithoutConnection(pid uint32, fd uint64, r *l7.RequestData, dstIP ...netaddr.IP) (map[netaddr.IP]*common.Domain, L7RequestResult) {
	pidFd := PidFd{Pid: pid, Fd: fd}

	// Check if this is an LLM connection via IP-based detection
	var llmTag *LLMConnectionTag
	if len(dstIP) > 0 && !dstIP[0].IsZero() {
		llmTag = c.llmDetector.IsLLMConnection(pidFd, dstIP[0])
	}

	// Note: do NOT early-skip when llmTag is nil. The IP cache is positive-only —
	// Google providers (generativelanguage.googleapis.com, *-aiplatform.googleapis.com)
	// are intentionally excluded from the cache because they share anycast IPs with
	// non-LLM googleapis.com services. For those, detection MUST come from the
	// HTTP/2 :authority header below. We bound overhead with Lightweight mode and
	// per-container parser caps; non-LLM parsers are deleted after first completion.

	// Parse the HTTP/2 frames
	if c.googleHTTP2Parsers == nil {
		c.googleHTTP2Parsers = make(map[PidFd]*l7.Http2Parser)
	}
	parser := c.googleHTTP2Parsers[pidFd]
	if parser == nil {
		if len(c.googleHTTP2Parsers) >= maxHTTP2ParsersPerContainer {
			return nil, L7RequestProcessed
		}
		parser = l7.NewHttp2Parser()
		parser.Lightweight = true
		parser.LLMHostChecker = isLLMRelevantHost
		c.googleHTTP2Parsers[pidFd] = parser
	}

	requests := parser.Parse(r.Method, r.Payload, uint64(r.Duration))

	// Late-tag from :authority header if not yet tagged
	if llmTag == nil {
		for _, req := range requests {
			if req.Authority != "" {
				host := stripPort(req.Authority)
				if !isIPAddress(host) {
					ip := netaddr.IP{}
					if len(dstIP) > 0 {
						ip = dstIP[0]
					}
					llmTag = c.llmDetector.LateTag(pidFd, host, ip)
					if llmTag != nil {
						klog.V(2).Infof("LLM_LATETAG_FALLBACK: pid=%d fd=%d host=%s provider=%s",
							pid, fd, host, llmTag.Provider)
						break
					}
				}
			}
		}
	}

	// If still not LLM, nothing to do on this connectionless path
	if llmTag == nil {
		if len(requests) > 0 {
			// Completed non-LLM requests — clean up parser
			delete(c.googleHTTP2Parsers, pidFd)
		}
		return nil, L7RequestProcessed
	}

	// Feed completed requests to LLM parser
	if c.llmParser != nil {
		for _, req := range requests {
			c.llmParser.ParseHTTP1(llmTag, int(req.Status),
				req.Path, req.RequestPayload, req.ResponsePayload, req.Duration, "")
		}

		// Feed active streams
		activeStreams := parser.GetActiveStreamsForLLM()
		for _, update := range activeStreams {
			c.llmParser.FeedHTTP2Data(llmTag, update.StreamId,
				nil, false, update.Path, 0, update.RequestHeaders)
			if update.HasResponseStatus {
				c.llmParser.OnHTTP2Status(update.StreamId, int(update.Status))
			}
			if len(update.ResponsePayload) > 0 {
				c.llmParser.FeedHTTP2Data(llmTag, update.StreamId,
					update.ResponsePayload, true, update.Path, int(update.Status), nil)
			}
		}
	}

	return nil, L7RequestProcessed
}

// refreshActiveConnections snapshots active connections under c.lock and
// pushes the gauge values to TCPMetrics. Called periodically from the
// event handler goroutine (not from Collect).
func (c *Container) refreshActiveConnections() {
	c.lock.RLock()
	counts := map[common.DestinationKey]activeConnAgg{}
	for _, conn := range c.activeConnections {
		if !conn.Closed.IsZero() {
			continue
		}
		enrichedKey := c.enrichDestinationKey(conn.DestinationKey)
		agg, ok := counts[enrichedKey]
		if !ok {
			agg = activeConnAgg{src: conn.srcWorkload}
		}
		agg.count++
		counts[enrichedKey] = agg
	}
	c.lock.RUnlock()

	entries := make([]activeEntry, 0, len(counts))
	for key, agg := range counts {
		entries = append(entries, activeEntry{
			labels: tcpLabels(key, agg.src),
			count:  agg.count,
		})
	}
	c.tcpMetrics.resetAndSetActive(entries)
}

type activeConnAgg struct {
	src   common.Workload
	count int
}

// activeCounterLabelKeys returns the set of labelKey() values for destinations
// that have at least one open connection, and the set of destination strings
// for destinations still in lastConnectionAttempts (for failed-connect eviction).
// Called from the event handler goroutine.
func (c *Container) activeCounterLabelKeys() (activeKeys map[string]struct{}, activeFailedDsts map[string]struct{}) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	activeKeys = make(map[string]struct{})
	for _, conn := range c.activeConnections {
		if !conn.Closed.IsZero() {
			continue
		}
		enrichedKey := c.enrichDestinationKey(conn.DestinationKey)
		labels := tcpLabels(enrichedKey, conn.srcWorkload)
		activeKeys[labelKey(labels)] = struct{}{}
	}

	activeFailedDsts = make(map[string]struct{}, len(c.lastConnectionAttempts))
	for dst := range c.lastConnectionAttempts {
		activeFailedDsts[dst.String()] = struct{}{}
	}

	return activeKeys, activeFailedDsts
}

func (c *Container) onRetransmission(src netaddr.IPPort, dst netaddr.IPPort) bool {
	c.lock.RLock()
	conn, ok := c.activeConnections[ConnectionKey{src: src, dst: dst}]
	c.lock.RUnlock()
	if !ok {
		return false
	}
	c.tcpMetrics.ObserveRetransmission(conn.DestinationKey, conn.srcWorkload)
	return true
}

func (c *Container) updateDelays() {
	// Get a snapshot of PIDs under read lock to avoid concurrent map access
	c.lock.RLock()
	pids := make([]uint32, 0, len(c.processes))
	for pid := range c.processes {
		pids = append(pids, pid)
	}
	c.lock.RUnlock()

	// Make syscalls without holding the lock to avoid contention
	type pidDelayStats struct {
		pid       uint32
		cpuDelay  time.Duration
		diskDelay time.Duration
	}
	pidStats := make([]pidDelayStats, 0, len(pids))
	for _, pid := range pids {
		stats, err := TaskstatsTGID(pid)
		if err != nil {
			continue
		}
		pidStats = append(pidStats, pidDelayStats{
			pid:       pid,
			cpuDelay:  stats.CPUDelay,
			diskDelay: stats.BlockIODelay,
		})
	}

	// Update delays under write lock
	c.lock.Lock()
	for _, ps := range pidStats {
		d := c.delaysByPid[ps.pid]
		c.delays.cpu += ps.cpuDelay - d.cpu
		c.delays.disk += ps.diskDelay - d.disk
		d.cpu = ps.cpuDelay
		d.disk = ps.diskDelay
		c.delaysByPid[ps.pid] = d
	}
	c.lock.Unlock()
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
	// Copy pids under read lock — c.processes is mutated by handleEvents goroutine
	c.lock.RLock()
	pids := make([]uint32, 0, len(c.processes))
	for pid := range c.processes {
		pids = append(pids, pid)
	}
	c.lock.RUnlock()

	res := map[string]map[string]*proc.FSStat{}
	for _, mi := range c.mounts {
		var stat *proc.FSStat
		for _, pid := range pids {
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

// getListens must be called with c.lock held (at least RLock).
func (c *Container) getListens() map[netaddr.IPPort]int {
	processesCopy := make(map[uint32]*Process, len(c.processes))
	for pid, p := range c.processes {
		processesCopy[pid] = p
	}

	res := map[netaddr.IPPort]int{}
	for addr, byPid := range c.listens {
		open := 0
		isHostNs := false
		ips := map[netaddr.IP]bool{}
		for pid, details := range byPid {
			p := processesCopy[pid]
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
	// Copy pids under read lock — c.processes is mutated by handleEvents goroutine
	c.lock.RLock()
	pids := make([]uint32, 0, len(c.processes))
	for pid := range c.processes {
		pids = append(pids, pid)
	}
	c.lock.RUnlock()

	netNs := netns.None()
	for _, pid := range pids {
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
	c.lock.RLock()
	for _, conn := range c.activeConnections {
		if ip := conn.DestinationKey.ActualDestinationIfKnown().IP(); !ip.IsZero() {
			ips[ip] = struct{}{}
		}
	}
	c.lock.RUnlock()
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
	sensitiveCfg := logparser.SensitiveConfig{
		Enabled:       !*flags.DisableSensitiveLogParsing,
		SampleRate:    *flags.SensitiveLogSampleRate,
		MinConfidence: *flags.SensitiveLogMinConfidence,
		MaxDetections: *flags.SensitiveLogMaxDetectionsPerContainer,
	}

	if logPath != "" {
		if c.logParsers[logPath] != nil {
			return
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.LogPatternsPerContainer, sensitiveCfg)
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
		if err := JournaldSubscribe(c.metadata.systemd.Unit, ch); err != nil {
			klog.Warningln(err)
			return
		}
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.LogPatternsPerContainer, sensitiveCfg)
		stop := func() {
			JournaldUnsubscribe(c.metadata.systemd.Unit)
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
		parser := logparser.NewParser(ch, c.metadata.logDecoder, logs.OtelLogEmitter(containerId), multilineCollectorTimeout, *flags.LogPatternsPerContainer, sensitiveCfg)
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
	// Clean up HTTP/2 parsers for closed/dead connections.
	// Parsers hold HPACK decoders, partial frame buffers, and active request maps
	// that accumulate memory over time if not cleaned up.
	// Two cases: (1) connection-tracked parsers — delete when connection is gone,
	// (2) connectionless parsers (processHTTP2WithoutConnection) — delete when pid dies.
	if c.googleHTTP2Parsers != nil {
		for pidFd := range c.googleHTTP2Parsers {
			if _, hasConn := c.connectionsByPidFd[pidFd]; hasConn {
				continue // connection still alive
			}
			if _, hasProc := c.processes[pidFd.Pid]; !hasProc {
				delete(c.googleHTTP2Parsers, pidFd) // pid dead — connectionless parser cleanup
				continue
			}
			// Pid is alive but no connection — could be a connectionless parser
			// (still needed) or a closed connection's parser (stale).
			// Check if this parser was created via the connectionless path by
			// seeing if there was ever a tracked connection for this pidFd.
			// If activeConnections had it at some point, it's stale.
			// Use a simple heuristic: if the parser has zero active requests
			// and no partial frame data, it's safe to clean up.
			p := c.googleHTTP2Parsers[pidFd]
			if p.ActiveRequestCount() == 0 && !p.HasPartialData() {
				delete(c.googleHTTP2Parsers, pidFd)
			}
		}
	}

	// Clean up LLM detector connection cache for dead pids
	if c.llmDetector != nil {
		for pidFd := range c.googleHTTP2Parsers {
			if _, hasProc := c.processes[pidFd.Pid]; !hasProc {
				c.llmDetector.RemoveConnection(pidFd)
			}
		}
	}

	for dst, at := range c.lastConnectionAttempts {
		_, active := establishedDst[dst]
		if !active && !at.IsZero() && now.Sub(at) > gcInterval {
			delete(c.lastConnectionAttempts, dst)
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
	}
	if !p.goTlsUprobesChecked {
		uprobes, isGolangApp := tracer.AttachGoTlsUprobes(pid)
		p.isGolangApp = isGolangApp
		p.uprobes = append(p.uprobes, uprobes...)
		p.goTlsUprobesChecked = true
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

	if info.Flags&os.O_WRONLY != 0 {
		cleaned := filepath.Clean(info.Dest)
		if strings.HasPrefix(cleaned, "/var/log/") &&
			!strings.HasPrefix(cleaned, "/var/log/pods/") &&
			!strings.HasPrefix(cleaned, "/var/log/containers/") &&
			!strings.HasPrefix(cleaned, "/var/log/journal/") {
			logPath = cleaned
		}
	}
	return
}

func (c *Container) counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	allLabels := make([]string, 0, len(c.constLabels)+len(labelValues))
	allLabels = append(allLabels, c.constLabels...)
	allLabels = append(allLabels, labelValues...)
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, allLabels...)
}

func (c *Container) gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	allLabels := make([]string, 0, len(c.constLabels)+len(labelValues))
	allLabels = append(allLabels, c.constLabels...)
	allLabels = append(allLabels, labelValues...)
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, allLabels...)
}

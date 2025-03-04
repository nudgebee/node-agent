package containers

import (
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"encoding/base64"

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
	gcInterval                = 10 * time.Minute
	pingTimeout               = 300 * time.Millisecond
	multilineCollectorTimeout = time.Second
	payloadThreshold          = 1024 * 1024
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
	cgroup   *cgroup.Cgroup
	metadata *ContainerMetadata

	processes map[uint32]*Process

	startedAt time.Time
	zombieAt  time.Time
	restarts  int

	delays      Delays
	delaysByPid map[uint32]Delays
	delaysLock  sync.Mutex

	listens map[netaddr.IPPort]map[uint32]*ListenDetails

	connectionStats          map[common.DestinationKey]*ConnectionStats
	failedConnectionAttempts map[common.HostPort]int64
	lastConnectionAttempts   map[common.HostPort]time.Time
	activeConnections        map[ConnectionKey]*ActiveConnection
	connectionsByPidFd       map[PidFd]*ActiveConnection

	l7Stats  L7Stats
	dnsStats *L7Metrics

	oomKills                 int
	pythonThreadLockWaitTime time.Duration

	mounts     map[string]proc.MountInfo
	seenMounts map[uint64]struct{}

	logParsers map[string]*LogParser

	tracer *tracing.Tracer

	registry *Registry

	lock sync.RWMutex

	done        chan struct{}
	ip_resolver IPResolver
	srcWorkload common.Workload
}

func NewContainer(id ContainerID, cg *cgroup.Cgroup, md *ContainerMetadata, pid uint32, registry *Registry) (*Container, error) {
	netNs, err := proc.GetNetNs(pid)
	if err != nil {
		return nil, err
	}
	defer netNs.Close()
	// /k8s/%s/%s/%s split
	// /k8s/ -> namespace
	// %s -> pod name

	split := strings.Split(string(id), "/")
	namespace := split[1]
	podName := split[2]

	c := &Container{
		id:       id,
		cgroup:   cg,
		metadata: md,

		processes: map[uint32]*Process{},

		delaysByPid: map[uint32]Delays{},

		listens: map[netaddr.IPPort]map[uint32]*ListenDetails{},

		connectionStats:          map[common.DestinationKey]*ConnectionStats{},
		failedConnectionAttempts: map[common.HostPort]int64{},
		lastConnectionAttempts:   map[common.HostPort]time.Time{},
		activeConnections:        map[ConnectionKey]*ActiveConnection{},
		connectionsByPidFd:       map[PidFd]*ActiveConnection{},
		l7Stats:                  L7Stats{},
		dnsStats:                 &L7Metrics{},

		mounts:     map[string]proc.MountInfo{},
		seenMounts: map[uint64]struct{}{},

		logParsers: map[string]*LogParser{},

		tracer: tracing.GetContainerTracer(string(id)),

		done:        make(chan struct{}),
		ip_resolver: registry.ip_resolver,
		registry:    registry,
		srcWorkload: common.Workload{Name: podName, Namespace: namespace, Kind: "Pod"},
	}
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
	c.registry.updateTrafficStatsIfNecessary()

	c.lock.RLock()
	defer c.lock.RUnlock()

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

	if c.oomKills > 0 {
		ch <- counter(metrics.OOMKills, float64(c.oomKills))
	}

	if disks, err := node.GetDisks(); err == nil {
		ioStat := c.cgroup.IOStat()
		for majorMinor, mounts := range c.getMounts() {
			dev := disks.GetParentBlockDevice(majorMinor)
			if dev == nil {
				continue
			}
			for mountPoint, fsStat := range mounts {
				dls := []string{mountPoint, dev.Name, c.metadata.volumes[mountPoint]}
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

	for addr, open := range c.getListens() {
		ch <- gauge(metrics.NetListenInfo, float64(open), addr.String(), "")
	}
	for proxy, addrs := range c.getProxiedListens() {
		for addr := range addrs {
			ch <- gauge(metrics.NetListenInfo, 1, addr.String(), proxy)
		}
	}

	for d, stats := range c.connectionStats {
		workload_src := c.srcWorkload
		workload_dest := d.GetDestinationWorkload()
		actualDestWorkload := d.GetActualDestinationWorkload()
		ch <- counter(metrics.NetConnectionsSuccessful, float64(stats.Count), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
		ch <- counter(metrics.NetConnectionsTotalTime, stats.TotalTime.Seconds(), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
		if stats.Retransmissions > 0 {
			ch <- counter(metrics.NetRetransmits, float64(stats.Retransmissions), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
		}
		ch <- counter(metrics.NetBytesSent, float64(stats.BytesSent), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
		ch <- counter(metrics.NetBytesReceived, float64(stats.BytesReceived), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), workload_src.Name, workload_src.Namespace, workload_src.Kind, workload_dest.Name, workload_dest.Namespace, workload_dest.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
	}
	for dst, count := range c.failedConnectionAttempts {
		workload := c.ip_resolver.ResolveIP(dst.IP().String())
		ch <- counter(metrics.NetConnectionsFailed, float64(count), dst.String(), workload.Name, workload.Namespace, workload.Kind, workload.Name, workload.Namespace, workload.Kind)
	}

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
		ch <- gauge(metrics.NetConnectionsActive, float64(count), d.DestinationLabelValue(), d.ActualDestinationLabelValue(), c.srcWorkload.Name, c.srcWorkload.Namespace, c.srcWorkload.Kind, destWorkload.Name, destWorkload.Namespace, destWorkload.Kind, actualDestWorkload.Name, actualDestWorkload.Namespace, actualDestWorkload.Kind)
	}

	for source, p := range c.logParsers {
		for _, c := range p.parser.GetCounters() {
			if c.Level == logparser.LevelCritical || c.Level == logparser.LevelError {
				ch <- counter(metrics.LogMessages, float64(c.Messages), source, c.Level.String(), c.Hash, c.Sample)
			}
		}
		for _, c := range p.parser.GetSensitiveCounters() {
			ch <- counter(metrics.SensitiveLogMessages, float64(c.Messages), source, c.Pattern, c.Sample, c.Regex, c.Name, c.Hash)
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
		appType := guessApplicationType(cmdline)
		if appType != "" {
			appTypes[appType] = struct{}{}
		}
		if process.isGolangApp {
			appTypes["golang"] = struct{}{}
		}
		switch {
		case isJvm(cmdline):
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
	}
	for appType := range appTypes {
		ch <- gauge(metrics.ApplicationType, 1, appType)
	}
	if c.pythonThreadLockWaitTime > 0 {
		ch <- counter(metrics.PythonThreadLockWaitTime, c.pythonThreadLockWaitTime.Seconds())
	}

	if c.dnsStats.Requests != nil {
		c.dnsStats.Requests.Collect(ch)
	}
	if c.dnsStats.Latency != nil {
		c.dnsStats.Latency.Collect(ch)
	}
	c.l7Stats.collect(ch)

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			destination_workload := c.ip_resolver.ResolveIP(ip.String())
			ch <- gauge(metrics.NetLatency, rtt, ip.String(), destination_workload.Name, destination_workload.Namespace, destination_workload.Kind)
		}
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
		c.lock.Lock()
		c.runLogParser(logPath)
		c.lock.Unlock()
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
	actualDstWorkload := c.ip_resolver.ResolveIP(actualDst.IP().String())
	if actualDst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	if common.ConnectionFilter.ShouldBeSkipped(dst.IP(), actualDst.IP()) {
		return
	}
	key := common.NewDestinationKey(dst, actualDst, c.registry.getFQDN(dst.IP()), dstWorkload, actualDstWorkload)
	c.lock.Lock()
	defer c.lock.Unlock()
	if failed {
		c.failedConnectionAttempts[key.Destination()]++
	} else {
		stats := c.connectionStats[key]
		if stats == nil {
			stats = &ConnectionStats{}
			c.connectionStats[key] = stats
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
	c.updateConnectionTrafficStats(c.connectionsByPidFd[PidFd{Pid: u.Pid, Fd: u.FD}], u.BytesSent, u.BytesReceived)
}

func (c *Container) updateConnectionTrafficStats(ac *ActiveConnection, sent, received uint64) {
	if ac == nil {
		return
	}
	stats := c.connectionStats[ac.DestinationKey]
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats[ac.DestinationKey] = stats
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

func (c *Container) onDNSRequest(r *l7.RequestData) map[netaddr.IP]string {
	status := r.Status.DNS()
	if status == "" {
		return nil
	}
	t, fqdn, ips := l7.ParseDns(r.Payload)
	if t == "" {
		return nil
	}
	fqdn = common.NormalizeFQDN(fqdn, t)

	// To reduce the number of metrics, we ignore AAAA requests with empty results,
	// as they are typically performed simultaneously with A requests and do not add
	// any additional latency to the application.
	if t == "TypeAAAA" && r.Status == 0 && len(ips) == 0 {
		return nil
	}

	if c.dnsStats.Requests == nil {
		dnsReq := L7Requests[l7.ProtocolDNS]
		c.dnsStats.Requests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: dnsReq.Name, Help: dnsReq.Help},
			[]string{"request_type", "domain", "status"},
		)
	}
	if m, _ := c.dnsStats.Requests.GetMetricWithLabelValues(t, fqdn, status); m != nil {
		m.Inc()
	}
	if r.Duration != 0 {
		if c.dnsStats.Latency == nil {
			dnsLatency := L7Latency[l7.ProtocolDNS]
			c.dnsStats.Latency = prometheus.NewHistogram(prometheus.HistogramOpts{Name: dnsLatency.Name, Help: dnsLatency.Help})
		}
		c.dnsStats.Latency.Observe(r.Duration.Seconds())
	}
	ip2fqdn := map[netaddr.IP]string{}
	if fqdn != "" {
		for _, ip := range ips {
			ip2fqdn[ip] = fqdn
		}
	}
	return ip2fqdn
}

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData, iqfqdn map[netaddr.IP]string) map[netaddr.IP]string {
	c.lock.Lock()
	defer c.lock.Unlock()

	if r.Protocol == l7.ProtocolDNS {
		return c.onDNSRequest(r)
	}

	conn := c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}]
	if conn == nil {
		return nil
	}
	if timestamp != 0 && conn.Timestamp != timestamp {
		return nil
	}
	if conn.dstWorkload.Namespace == "external" && (r.Protocol == l7.ProtocolHTTP || r.Protocol == l7.ProtocolHTTP2) {
		if host, ok := iqfqdn[conn.DestinationKey.ActualDestination().IP()]; ok {
			log.Printf("Setting external host %s", host)
			conn.dstWorkload.Name = host
		} else {
			host, error := l7.ParseHostFromHttpRequest(string(r.Payload))
			if error == nil {
				conn.dstWorkload.Name = host
			}
		}
	}

	headers := http.Header{}
	if r.Protocol == l7.ProtocolHTTP {
		req, err := l7.ParseHTTPRequest(r.Payload)
		if err == nil && req != nil && req.Header != nil {
			headers = req.Header
		}
	}

	traceId := ""
	if headers != nil {
		traceIdHeaders := strings.Split(*flags.TraceIdHeaders, ",")
		for _, header := range traceIdHeaders {
			if id := headers.Get(header); id != "" {
				// check for lowercase header
				traceId = id
				break
			} else if id := headers.Get(strings.ToLower(header)); id != "" {
				traceId = id
				break
			}
		}
	}

	stats := c.l7Stats.get(r.Protocol, conn.DestinationKey, r, conn.srcWorkload, conn.DestinationKey.GetDestinationWorkload(), conn.DestinationKey.GetActualDestinationWorkload(), traceId)

	trace := c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown(), conn.srcWorkload, conn.DestinationKey.GetDestinationWorkload(), conn.DestinationKey.GetActualDestinationWorkload())
	switch r.Protocol {
	case l7.ProtocolHTTP:
		stats.observe(r.Status.Http(), "", r.Duration)
		payload := ""
		method := ""
		uri := ""
		response := ""
		host := conn.dstWorkload.Name
		req, err := l7.ParseHTTPRequest(r.Payload)
		if err != nil {
			log.Printf("Failed to parse payload %s, %q", err, string(r.Payload))
			method, uri = l7.ParseHttp(r.Payload)
		} else {
			if req != nil && req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				base64String := base64.StdEncoding.EncodeToString(body)
				payload = string(base64String)
			}
			method = req.Method
			if utf8.ValidString(req.URL.Path) {
				uri = req.URL.Path
			} else {
				// remove non-utf8 characters
				klog.Warningf("Non-utf8 characters in uri %q", req.URL.Path)
				uri = string([]rune(req.URL.Path))
			}
		}
		if r.Response != nil {
			response = base64.StdEncoding.EncodeToString(r.Response)
		}
		trace.HttpRequest(method, uri, r.Status, r.Duration, r.PayloadSize, payload, headers, response, host)
	case l7.ProtocolHTTP2:
		if conn.http2Parser == nil {
			conn.http2Parser = l7.NewHttp2Parser()
		}
		requests := conn.http2Parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		for _, req := range requests {
			stats.observe(req.Status.Http(), "", req.Duration)
			payload := ""
			if int(r.PayloadSize) < payloadThreshold {
				payload = string(r.Payload)
			}
			trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.Duration, string(payload))
		}
	case l7.ProtocolPostgres:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.postgresParser == nil {
			conn.postgresParser = l7.NewPostgresParser()
		}
		query := conn.postgresParser.Parse(r.Payload)
		trace.PostgresQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMysql:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.mysqlParser == nil {
			conn.mysqlParser = l7.NewMysqlParser()
		}
		query := conn.mysqlParser.Parse(r.Payload, r.StatementId)
		trace.MysqlQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMemcached:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, items := l7.ParseMemcached(r.Payload)
		trace.MemcachedQuery(cmd, items, r.Status.Error(), r.Duration)
	case l7.ProtocolRedis:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, args := l7.ParseRedis(r.Payload)
		trace.RedisQuery(cmd, args, r.Status.Error(), r.Duration)
	case l7.ProtocolMongo:
		stats.observe(r.Status.String(), "", r.Duration)
		query := l7.ParseMongo(r.Payload)
		trace.MongoQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolKafka, l7.ProtocolCassandra:
		stats.observe(r.Status.String(), "", r.Duration)
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		stats.observe(r.Status.String(), r.Method.String(), 0)
	case l7.ProtocolDubbo2:
		stats.observe(r.Status.String(), "", r.Duration)
	case l7.ProtocolClickhouse:
		stats.observe(r.Status.String(), "", r.Duration)
		query := l7.ParseClickhouse(r.Payload)
		trace.ClickhouseQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolZookeeper:
		stats.observe(r.Status.Zookeeper(), "", r.Duration)
		op, arg := l7.ParseZookeeper(r.Payload)
		trace.ZookeeperRequest(op, arg, r.Status, r.Duration)
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
	stats := c.connectionStats[conn.DestinationKey]
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats[conn.DestinationKey] = stats
	}
	stats.Retransmissions++
	return true
}

func (c *Container) updateDelays() {
	c.delaysLock.Lock()
	defer c.delaysLock.Unlock()
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
	for d := range c.connectionStats {
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
			for d := range c.connectionStats {
				if d.Destination() == dst {
					delete(c.connectionStats, d)
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
		p.uprobes = append(p.uprobes, tracer.AttachOpenSslUprobes(pid)...)
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

	if info.Flags&os.O_WRONLY != 0 && strings.HasPrefix(info.Dest, "/var/log/") &&
		!strings.HasPrefix(info.Dest, "/var/log/pods/") &&
		!strings.HasPrefix(info.Dest, "/var/log/containers/") &&
		!strings.HasPrefix(info.Dest, "/var/log/journal/") {

		logPath = info.Dest
	}
	return
}

func counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}

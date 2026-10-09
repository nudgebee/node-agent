package node

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// Host metrics under node_exporter's names, for hosts without node_exporter.
// They are emitted only in standalone (VM) mode: on Kubernetes node_exporter
// usually runs alongside, and the same series would be counted twice.

var (
	load1Desc  = prometheus.NewDesc("node_load1", "1m load average.", nil, nil)
	load5Desc  = prometheus.NewDesc("node_load5", "5m load average.", nil, nil)
	load15Desc = prometheus.NewDesc("node_load15", "15m load average.", nil, nil)

	swapTotalDesc = prometheus.NewDesc("node_memory_SwapTotal_bytes", "Memory information field SwapTotal_bytes.", nil, nil)
	swapFreeDesc  = prometheus.NewDesc("node_memory_SwapFree_bytes", "Memory information field SwapFree_bytes.", nil, nil)

	fsLabels         = []string{"device", "fstype", "mountpoint"}
	fsSizeDesc       = prometheus.NewDesc("node_filesystem_size_bytes", "Filesystem size in bytes.", fsLabels, nil)
	fsFreeDesc       = prometheus.NewDesc("node_filesystem_free_bytes", "Filesystem free space in bytes.", fsLabels, nil)
	fsAvailDesc      = prometheus.NewDesc("node_filesystem_avail_bytes", "Filesystem space available to non-root users in bytes.", fsLabels, nil)
	fsFilesDesc      = prometheus.NewDesc("node_filesystem_files", "Filesystem total file nodes.", fsLabels, nil)
	fsFilesFreeDesc  = prometheus.NewDesc("node_filesystem_files_free", "Filesystem total free file nodes.", fsLabels, nil)
	fsReadonlyDesc   = prometheus.NewDesc("node_filesystem_readonly", "Filesystem read-only status.", fsLabels, nil)
	statfsTimeout    = 2 * time.Second
	stuckMountRetry  = 5 * time.Minute
	errStatfsTimeout = errors.New("statfs timed out")
	errStatfsRunning = errors.New("statfs still running")

	statfsSyscall = unix.Statfs // replaced in tests
)

var hostDescs = []*prometheus.Desc{
	load1Desc, load5Desc, load15Desc, swapTotalDesc, swapFreeDesc,
	fsSizeDesc, fsFreeDesc, fsAvailDesc, fsFilesDesc, fsFilesFreeDesc, fsReadonlyDesc,
}

// node_exporter's default exclusions: pseudo and container filesystems.
var (
	ignoredFsTypes = map[string]bool{
		"autofs": true, "binfmt_misc": true, "bpf": true, "cgroup": true, "cgroup2": true, "configfs": true,
		"debugfs": true, "devpts": true, "devtmpfs": true, "fusectl": true, "hugetlbfs": true, "iso9660": true,
		"mqueue": true, "nsfs": true, "overlay": true, "proc": true, "procfs": true, "pstore": true,
		"rpc_pipefs": true, "securityfs": true, "selinuxfs": true, "squashfs": true, "erofs": true,
		"sysfs": true, "tracefs": true,
	}
	ignoredMountPrefixes = []string{"/dev", "/proc", "/sys", "/run/credentials/", "/var/lib/docker/", "/var/lib/containers/storage/"}
)

type hostMount struct {
	device, mountPoint, fsType string
	readonly                   bool
}

type hostCollector struct {
	procRoot string

	lock    sync.Mutex
	stuck   map[string]time.Time // mount points whose statfs timed out
	running map[string]bool      // mount points with a statfs call in flight
}

func newHostCollector(procRoot string) *hostCollector {
	return &hostCollector{procRoot: procRoot, stuck: map[string]time.Time{}, running: map[string]bool{}}
}

func (h *hostCollector) collect(ch chan<- prometheus.Metric) {
	if l1, l5, l15, err := loadAvg(h.procRoot); err != nil {
		klog.Errorln(err)
	} else {
		ch <- gauge(load1Desc, l1)
		ch <- gauge(load5Desc, l5)
		ch <- gauge(load15Desc, l15)
	}

	if mem, err := memoryInfo(h.procRoot); err == nil {
		ch <- gauge(swapTotalDesc, mem.SwapTotalBytes)
		ch <- gauge(swapFreeDesc, mem.SwapFreeBytes)
	}

	mounts, err := hostMounts(h.procRoot)
	if err != nil {
		klog.Errorln(err)
		return
	}
	for _, m := range mounts {
		if h.isStuck(m.mountPoint) {
			continue
		}
		s, err := h.statfs(m.mountPoint)
		if err != nil {
			if errors.Is(err, errStatfsTimeout) {
				klog.Warningf("statfs of %s timed out, skipping it for %s", m.mountPoint, stuckMountRetry)
				h.markStuck(m.mountPoint)
			}
			continue
		}
		bsize := float64(s.Bsize)
		readonly := float64(0)
		if m.readonly {
			readonly = 1
		}
		labels := []string{m.device, m.fsType, m.mountPoint}
		ch <- gauge(fsSizeDesc, float64(s.Blocks)*bsize, labels...)
		ch <- gauge(fsFreeDesc, float64(s.Bfree)*bsize, labels...)
		ch <- gauge(fsAvailDesc, float64(s.Bavail)*bsize, labels...)
		ch <- gauge(fsFilesDesc, float64(s.Files), labels...)
		ch <- gauge(fsFilesFreeDesc, float64(s.Ffree), labels...)
		ch <- gauge(fsReadonlyDesc, readonly, labels...)
	}
}

func (h *hostCollector) isStuck(mountPoint string) bool {
	h.lock.Lock()
	defer h.lock.Unlock()
	t, ok := h.stuck[mountPoint]
	if ok && time.Since(t) > stuckMountRetry {
		delete(h.stuck, mountPoint)
		return false
	}
	return ok
}

func (h *hostCollector) markStuck(mountPoint string) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.stuck[mountPoint] = time.Now()
}

// statfs runs statfs(2) with a timeout: on a hung network mount it never
// returns, and a scrape must not hang with it. A call that hangs keeps its
// goroutine, and its OS thread, blocked in the kernel, so no second call is
// started for a mount point while one is still in flight.
func (h *hostCollector) statfs(mountPoint string) (*unix.Statfs_t, error) {
	h.lock.Lock()
	if h.running[mountPoint] {
		h.lock.Unlock()
		return nil, errStatfsRunning
	}
	h.running[mountPoint] = true
	h.lock.Unlock()

	type result struct {
		s   unix.Statfs_t
		err error
	}
	ch := make(chan result, 1)
	p := path.Join(h.procRoot, "1", "root", mountPoint)
	go func() {
		var r result
		r.err = statfsSyscall(p, &r.s)
		h.lock.Lock()
		delete(h.running, mountPoint)
		h.lock.Unlock()
		ch <- r
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		h.lock.Lock()
		delete(h.stuck, mountPoint)
		h.lock.Unlock()
		return &r.s, nil
	case <-time.After(statfsTimeout):
		return nil, errStatfsTimeout
	}
}

func loadAvg(procRoot string) (l1, l5, l15 float64, err error) {
	data, err := os.ReadFile(path.Join(procRoot, "loadavg"))
	if err != nil {
		return 0, 0, 0, err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return 0, 0, 0, errors.New("unexpected /proc/loadavg format")
	}
	var v [3]float64
	for i := range v {
		if v[i], err = strconv.ParseFloat(parts[i], 64); err != nil {
			return 0, 0, 0, err
		}
	}
	return v[0], v[1], v[2], nil
}

// hostMounts returns the host's mounts (as seen by pid 1), without pseudo
// and container filesystems.
func hostMounts(procRoot string) ([]hostMount, error) {
	data, err := os.ReadFile(path.Join(procRoot, "1", "mounts"))
	if err != nil {
		return nil, err
	}
	var res []hostMount
	// A mount point can be listed more than once (mounted over, or bind
	// mounted again). Only the last mount is visible, and statfs reads that
	// one, so keep only the last; reporting each would also repeat a series.
	byMountPoint := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		m := hostMount{device: unescapeMount(parts[0]), mountPoint: unescapeMount(parts[1]), fsType: parts[2]}
		if ignoredFsTypes[m.fsType] || ignoredMountPoint(m.mountPoint) {
			continue
		}
		for _, o := range strings.Split(parts[3], ",") {
			if o == "ro" {
				m.readonly = true
				break
			}
		}
		if i, ok := byMountPoint[m.mountPoint]; ok {
			res[i] = m
			continue
		}
		byMountPoint[m.mountPoint] = len(res)
		res = append(res, m)
	}
	return res, nil
}

func ignoredMountPoint(mp string) bool {
	for _, p := range ignoredMountPrefixes {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(mp, p) {
				return true
			}
			continue
		}
		if mp == p || strings.HasPrefix(mp, p+"/") {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes /proc/<pid>/mounts uses for
// spaces, tabs, newlines and backslashes in paths.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

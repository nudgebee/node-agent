package containers

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/jpillora/backoff"
)

type GpuUsage struct {
	GPU    float64
	Memory float64
}

func (gu *GpuUsage) Reset() {
	gu.Memory = 0
	gu.GPU = 0
}

type Process struct {
	Pid       uint32
	StartedAt time.Time

	Flags proc.Flags

	netNsId string

	ctx        context.Context
	cancelFunc context.CancelFunc

	// mu guards the fields below. They are written by the instrument
	// goroutine, the registry's event loop and the stats updaters, and read by
	// Collect on the scrape goroutine.
	mu              sync.Mutex
	closed          bool
	uprobes         []link.Link
	isGolangApp     bool
	dotNetMonitor   *DotNetMonitor
	nodejsPrevStats *ebpftracer.NodejsStats
	pythonPrevStats *ebpftracer.PythonStats
	gpuUsageSamples []gpu.ProcessUsageSample

	// TLS attach state, only touched by the registry's event loop.
	goTlsUprobesChecked   bool
	openSslUprobesChecked bool
	openSslChecks         int
	openSslLastCheck      time.Time
	tlsAttached           bool
	tlsExe                exeIdentity
	tlsExeName            string
	tlsExeCheckedAt       time.Time

	// Only touched by the instrument goroutine.
	pythonGilChecked bool
	nodejsChecked    bool
}

func NewProcess(pid uint32, startedAt time.Time, tracer *ebpftracer.Tracer) *Process {
	p := &Process{Pid: pid, StartedAt: startedAt}
	p.Flags, _ = proc.GetFlags(pid)
	p.ctx, p.cancelFunc = context.WithCancel(context.Background())
	go p.instrument(tracer)
	return p
}

func (p *Process) NetNsId() string {
	if p.netNsId == "" {
		ns, err := proc.GetNetNs(p.Pid)
		if err != nil {
			return ""
		}
		p.netNsId = ns.UniqueId()
		_ = ns.Close()
	}
	return p.netNsId
}

func (p *Process) isHostNs() bool {
	return p.NetNsId() == hostNetNsId
}

func (p *Process) instrument(tracer *ebpftracer.Tracer) {
	b := backoff.Backoff{Factor: 2, Min: time.Second, Max: time.Minute}
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			dest, err := os.Readlink(proc.Path(p.Pid, "exe"))
			if err != nil {
				return
			}
			cmdline := proc.GetCmdline(p.Pid)
			if dest != "/" && len(cmdline) > 0 {
				p.instrumentPython(cmdline, tracer)
				p.instrumentNodejs(dest, tracer)
				if *flags.EnableDotNetTracing {
					if dotNetAppName, err := dotNetApp(cmdline, p.Pid); err == nil {
						if dotNetAppName != "" {
							m := NewDotNetMonitor(p.ctx, p.Pid, dotNetAppName)
							p.mu.Lock()
							p.dotNetMonitor = m
							p.mu.Unlock()
						}
					}
				}
				return
			}
			time.Sleep(b.Duration())
		}
	}
}

func (p *Process) instrumentPython(cmdline []byte, tracer *ebpftracer.Tracer) {
	if p.pythonGilChecked {
		return
	}
	p.pythonGilChecked = true
	parts := bytes.Split(cmdline, []byte{0})
	cmd := parts[0]
	if len(cmd) == 0 {
		return
	}
	cmdFields := bytes.Fields(cmd)
	if len(cmdFields) == 0 {
		return
	}
	cmd = bytes.TrimSuffix(cmdFields[0], []byte{':'})
	if !pythonCmd.Match(cmd) {
		return
	}
	p.mu.Lock()
	p.pythonPrevStats = &ebpftracer.PythonStats{}
	p.mu.Unlock()
	p.addUprobes(tracer.AttachPythonThreadLockProbes(p.Pid))
}

func (p *Process) instrumentNodejs(exe string, tracer *ebpftracer.Tracer) {
	// Checked before nodejsChecked so enabling the flag on a restart still
	// instruments processes that were skipped while it was off.
	if !*flags.EnableNodejsTracing {
		return
	}
	if p.nodejsChecked {
		return
	}
	p.nodejsChecked = true
	if !nodejsCmd.MatchString(exe) {
		return
	}
	p.mu.Lock()
	p.nodejsPrevStats = &ebpftracer.NodejsStats{}
	p.mu.Unlock()
	p.addUprobes(tracer.AttachNodejsProbes(p.Pid, exe))
}

func (p *Process) addGpuUsageSample(sample gpu.ProcessUsageSample) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeOldGpuUsageSamples(sample.Timestamp.Add(-gpuStatsWindow))
	p.gpuUsageSamples = append(p.gpuUsageSamples, sample)
}

func (p *Process) getGPUUsage() map[string]*GpuUsage {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeOldGpuUsageSamples(time.Now().Add(-gpuStatsWindow))
	if len(p.gpuUsageSamples) == 0 {
		return nil
	}
	gpuStatsWindowSeconds := gpuStatsWindow.Seconds()
	res := make(map[string]*GpuUsage)
	for _, sample := range p.gpuUsageSamples {
		u := res[sample.UUID]
		if u == nil {
			u = &GpuUsage{}
			res[sample.UUID] = u
		}
		u.GPU += float64(sample.GPUPercent) / gpuStatsWindowSeconds
		u.Memory += float64(sample.MemoryPercent) / gpuStatsWindowSeconds
	}
	return res
}

func (p *Process) removeOldGpuUsageSamples(cutoff time.Time) {
	i := 0
	for ; i < len(p.gpuUsageSamples); i++ {
		if p.gpuUsageSamples[i].Timestamp.After(cutoff) {
			break
		}
	}
	if i > 0 {
		copy(p.gpuUsageSamples, p.gpuUsageSamples[i:])
		p.gpuUsageSamples = p.gpuUsageSamples[:len(p.gpuUsageSamples)-i]
	}
}

// addUprobes takes ownership of links. Attaching runs outside the lock and
// can finish after the process exited, so links arriving after Close are
// closed instead of kept: nothing would ever close them otherwise.
func (p *Process) addUprobes(links []link.Link) {
	if len(links) == 0 {
		return
	}
	p.mu.Lock()
	closed := p.closed
	if !closed {
		p.uprobes = append(p.uprobes, links...)
	}
	p.mu.Unlock()
	if closed {
		go closeLinks(links)
	}
}

func (p *Process) golang() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isGolangApp
}

func (p *Process) setGolang(v bool) {
	p.mu.Lock()
	p.isGolangApp = v
	p.mu.Unlock()
}

func (p *Process) dotNet() *DotNetMonitor {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dotNetMonitor
}

// dropUprobes closes the process's uprobes but keeps it open for new ones.
func (p *Process) dropUprobes() {
	p.mu.Lock()
	uprobes := p.uprobes
	p.uprobes = nil
	p.mu.Unlock()
	if len(uprobes) > 0 {
		go closeLinks(uprobes)
	}
}

func (p *Process) Close() {
	p.cancelFunc()
	p.mu.Lock()
	p.closed = true
	uprobes := p.uprobes
	p.uprobes = nil
	p.mu.Unlock()
	if len(uprobes) > 0 {
		go closeLinks(uprobes)
	}
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

// exeIdentity identifies the file a process is executing, so an exec of a
// different binary under the same pid can be noticed.
type exeIdentity struct {
	dev, ino uint64
}

func exeIdentityOf(pid uint32) (exeIdentity, error) {
	fi, err := os.Stat(proc.Path(pid, "exe"))
	if err != nil {
		return exeIdentity{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return exeIdentity{}, fmt.Errorf("stat unavailable for pid %d", pid)
	}
	return exeIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

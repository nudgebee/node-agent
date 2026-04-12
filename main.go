package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/profiling"
	"github.com/coroot/coroot-node-agent/prom"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

var (
	version = flags.Version
)

func uname() (string, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	f, err := os.Open("/proc/1/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	self, err := os.Open("/proc/self/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer self.Close()

	defer func() {
		unix.Setns(int(self.Fd()), unix.CLONE_NEWUTS)
	}()

	err = unix.Setns(int(f.Fd()), unix.CLONE_NEWUTS)
	if err != nil {
		return "", "", err
	}
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", "", err
	}
	hostname := string(bytes.Split(utsname.Nodename[:], []byte{0})[0])
	kernelVersion := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	return hostname, kernelVersion, nil
}

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/devices/virtual/dmi/id/product_uuid"} {
		payload, err := os.ReadFile(proc.HostPath(p))
		if err != nil {
			klog.Warningln("failed to read machine-id:", err)
			continue
		}
		id := strings.TrimSpace(strings.Replace(string(payload), "-", "", -1))
		klog.Infoln("machine-id: ", id)
		return id
	}
	return ""
}

func systemUUID() string {
	payload, err := os.ReadFile(proc.HostPath("/sys/devices/virtual/dmi/id/product_uuid"))
	if err != nil {
		klog.Warningln("failed to read system-uuid:", err)
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func whitelistNodeExternalNetworks() {
	netdevs, err := node.NetDevices()
	if err != nil {
		klog.Warningln("failed to get network interfaces:", err)
		return
	}
	for _, iface := range netdevs {
		for _, p := range iface.IPPrefixes {
			if p.IP().IsLoopback() || common.IsIpPrivate(p.IP()) {
				continue
			}
			// if the node has an external network IP, whitelist that network
			common.ConnectionFilter.WhitelistPrefix(p)
		}
	}
}

func getClientSet() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig :=
			clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(config)
}

func main() {
	// Set GOMEMLIMIT to 60% of cgroup memory limit if available, otherwise use env var.
	// Use 60% (not 90%) because the cgroup OOM killer counts kernel memory (~80MB for
	// eBPF maps) and file page cache (~200MB from /proc reads) which GOMEMLIMIT doesn't
	// control. At 90%, Go heap + kernel + page cache exceeds the cgroup limit.
	if os.Getenv("GOMEMLIMIT") == "" {
		if limit, err := readCgroupMemoryLimit(); err == nil && limit > 0 {
			softLimit := int64(float64(limit) * 0.6)
			debug.SetMemoryLimit(softLimit)
			log.Printf("GOMEMLIMIT set to %dMiB (60%% of cgroup limit %dMiB)", softLimit/1024/1024, limit/1024/1024)
		}
	}

	// Initialize klog flags to prevent duplicate output
	klog.InitFlags(nil)
	if v := os.Getenv("KLOG_V"); v != "" {
		flag.Set("v", v)
	}
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	flag.Set("stderrthreshold", "FATAL")
	klog.SetOutput(&RateLimitedLogOutput{limiter: rate.NewLimiter(rate.Limit(*flags.LogPerSecond), *flags.LogBurst)})

	klog.Infoln("agent version:", version)

	clientset, err := getClientSet()
	if err != nil {
		log.Fatalf("Error getting kubernetes clientset: %v", err)
	}
	resolver, err := common.NewK8sIPResolver(clientset, *flags.ResolveDns)
	if err != nil {
		log.Fatalf("Error creating resolver: %v", err)
	}
	err = resolver.StartWatching()
	if err != nil {
		klog.Errorf("Error starting resolver: %v", err)
	}
	defer resolver.StopWatching()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigChannel := make(chan os.Signal, 1)
		signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
		<-sigChannel
		klog.Infoln("Received signal, shutting down")
		cancel()
	}()
	hostname, kv, err := uname()
	if err != nil {
		klog.Exitln("failed to get uname:", err)
	}

	klog.Infoln("hostname:", hostname)
	klog.Infoln("kernel version:", kv)

	if err = common.SetKernelVersion(kv); err != nil {
		klog.Exitln(err)
	}

	if !common.GetKernelVersion().GreaterOrEqual(common.NewVersion(4, 16, 0)) {
		klog.Exitln("the minimum Linux kernel version required is 4.16 or later")
	}

	whitelistNodeExternalNetworks()

	machineId := machineID()
	systemUuid := systemUUID()

	tracing.Init(machineId, hostname, version)
	logs.Init(machineId, hostname, version)

	nodeCollector := node.NewCollector(hostname, kv)

	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(
		prometheus.Labels{"machine_id": machineId, "system_uuid": systemUuid},
		registry,
	)
	if err := registerer.Register(nodeCollector); err != nil {
		klog.Exitln(err)
	}

	gpuCollector, err := gpu.NewCollector()
	if err != nil {
		klog.Warningln("failed to initialize GPU collector:", err)
	}
	if err := registerer.Register(gpuCollector); err != nil {
		klog.Exitln(err)
	}
	registerer.MustRegister(info("node_agent_info", version))

	az := ""
	region := ""
	if md := nodeCollector.Metadata(); md != nil {
		region = md.Region
		az = md.AvailabilityZone
		if region != "" && az != "" {
			registerer = prometheus.WrapRegistererWith(prometheus.Labels{"az": az, "region": region}, registerer)
		}
	}
	processInfoCh := profiling.Init(machineId, hostname)
	// Pass both the wrapped registerer (for ip2fqdn and LLM metrics) and the raw
	// registry (for containers) to avoid WrapRegistererWith allocation overhead on
	// the hot path. Container metrics embed const labels directly.
	cr, err := containers.NewRegistry(registerer, registry, processInfoCh, resolver, gpuCollector.ProcessUsageSampleCh, machineId, systemUuid, az, region)
	if err != nil {
		klog.Exitln(err)
	}
	defer cr.Close()

	profiling.Start()
	defer profiling.Stop()

	if err := prom.StartAgent(registry, machineId, systemUuid); err != nil {
		klog.Exitln(err)
	}

	// Metrics endpoint with timeout protection
	http.Handle("/metrics", http.TimeoutHandler(
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorLog: logger{}, Registry: registerer}),
		30*time.Second,
		"Metrics collection timeout",
	))

	srv := &http.Server{Addr: *flags.ListenAddress}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			klog.Errorf("HTTP server shutdown error: %v", err)
		}
	}()

	klog.Infoln("listening on:", *flags.ListenAddress)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		klog.Errorln(err)
	}
	klog.Infoln("shutdown complete")
}

func info(name, version string) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        name,
		ConstLabels: prometheus.Labels{"version": version},
	})
	g.Set(1)
	return g
}

type logger struct{}

func (l logger) Println(v ...interface{}) {
	klog.Errorln(v...)
}

type RateLimitedLogOutput struct {
	limiter *rate.Limiter
}

func (o *RateLimitedLogOutput) Write(data []byte) (int, error) {
	if !o.limiter.Allow() {
		return len(data), nil
	}
	return os.Stderr.Write(data)
}

// readCgroupMemoryLimit reads the memory limit from cgroup v2 or v1.
// The agent runs with hostPID, so /proc/1/cgroup points to the host root (init.scope)
// which has no memory limit. We use /proc/self/cgroup to find the container's own
// cgroup path where kubelet enforces the pod memory limit.
func readCgroupMemoryLimit() (int64, error) {
	// Try cgroup v2: read our own cgroup path and look up memory.max there.
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		// cgroupv2 format: "0::/kubepods.slice/.../cri-containerd-xxx.scope"
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				cgPath := "/sys/fs/cgroup" + parts[2] + "/memory.max"
				if mem, err := os.ReadFile(cgPath); err == nil {
					s := strings.TrimSpace(string(mem))
					if s != "max" {
						if limit, err := strconv.ParseInt(s, 10, 64); err == nil {
							return limit, nil
						}
					}
				}
			}
		}
	}
	// Fallback: try cgroup v2 at root (non-hostPID containers)
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if limit, err := strconv.ParseInt(s, 10, 64); err == nil {
				return limit, nil
			}
		}
	}
	// Try cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if limit, err := strconv.ParseInt(s, 10, 64); err == nil {
			// cgroup v1 reports a very large number when unlimited
			if limit < 1<<62 {
				return limit, nil
			}
		}
	}
	return 0, fmt.Errorf("unable to read cgroup memory limit")
}

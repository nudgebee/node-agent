package ebpftracer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/exp/maps"
	"k8s.io/klog/v2"
)

const nodejsPollSymbol = "uv__io_poll"

// libuv I/O callbacks. Not every libuv build exports all of them; the attach
// loop stops at the first one missing, matching the previous behaviour.
var nodejsCallbackSymbols = []string{"uv__stream_io", "uv__async_io", "uv__poll_io", "uv__server_io", "uv__udp_io"}

// Every symbol resolved in one pass over the ELF symbol table, so a cache miss
// costs a single parse rather than one per symbol.
var nodejsProbeSymbols = append([]string{nodejsPollSymbol}, nodejsCallbackSymbols...)

func (t *Tracer) AttachNodejsProbes(pid uint32, exe string) []link.Link {
	log := func(libPath, msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			if strings.Contains(err.Error(), "symbol") && strings.HasSuffix(err.Error(), "not found") {
				return
			}
			klog.ErrorfDepth(1, "pid=%d lib=%s: %s: %s", pid, libPath, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d lib=%s: %s", pid, libPath, msg)
	}

	for _, libPath := range append(getLibuv(pid), proc.Path(pid, "root", exe)) {
		if links, err := t.attachNodejsUprobes(libPath, pid); err == nil {
			log(libPath, "nodejs uprobes attached", nil)
			return links
		} else {
			log(libPath, "failed to attach nodejs uprobes", err)
		}
	}
	return nil
}

func (t *Tracer) attachNodejsUprobes(libPath string, pid uint32) ([]link.Link, error) {
	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, err
	}

	// Resolved once per binary rather than once per pid — see LookupSymbols.
	targets, err := LookupSymbols(libPath, nodejsProbeSymbols)
	if err != nil {
		return nil, err
	}

	poll := targets[nodejsPollSymbol]
	if !poll.Found {
		return nil, fmt.Errorf("symbol %s not found", nodejsPollSymbol)
	}
	l, err := attachUprobeAt(exe, t.uprobes["uv_io_poll_enter"], pid, poll.Address)
	if err != nil {
		return nil, err
	}
	var links []link.Link
	links = append(links, l)

	ls, err := attachUretprobesAt(exe, t.uprobes["uv_io_poll_exit"], pid, poll)
	links = append(links, ls...)
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, err
	}

	for _, cb := range nodejsCallbackSymbols {
		target := targets[cb]
		if !target.Found {
			break
		}
		l, err = attachUprobeAt(exe, t.uprobes["uv_io_cb_enter"], pid, target.Address)
		if err != nil {
			break
		}
		links = append(links, l)
		ls, err = attachUretprobesAt(exe, t.uprobes["uv_io_cb_exit"], pid, target)
		links = append(links, ls...)
		if err != nil {
			break
		}
	}
	return links, nil
}

func getLibuv(pid uint32) []string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	libs := map[string]bool{}
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if strings.Contains(libPath, "libuv") {
			libs[proc.Path(pid, "root", libPath)] = true
		}
	}
	return maps.Keys(libs)
}

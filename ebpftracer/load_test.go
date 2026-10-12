package ebpftracer

import (
	"errors"
	"os"
	"regexp"
	"sort"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/common"
	"golang.org/x/sys/unix"
)

var verifierProcessedRe = regexp.MustCompile(`processed (\d+) insns`)

// TestProgramsLoad loads the program variant the running kernel gets, as the
// agent does, and logs what each program costs. The collection loads
// all-or-nothing, so a single program the verifier rejects stops the agent
// from starting. CI does not load the programs, so run this on the oldest
// kernels the agent supports after changing anything in ebpf/:
//
//	go test -c -o ebpftracer.test ./ebpftracer
//	sudo VM=1 ./ebpftracer.test -test.run TestProgramsLoad -test.v
//
// Per program it logs the compiled instruction count, the count after the
// kernel rewrote the program (xlated), and the instructions the verifier
// processed, which is what its complexity limit applies to.
func TestProgramsLoad(t *testing.T) {
	if os.Getenv("VM") == "" {
		t.Skip("loads eBPF programs into the running kernel; set VM=1 and run as root")
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		t.Fatal(err)
	}
	if err := common.SetKernelVersion(unix.ByteSliceToString(uname.Release[:])); err != nil {
		t.Fatal(err)
	}
	spec, variant, err := collectionSpecForKernel()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel %s, variant %s", common.GetKernelVersion(), variant)

	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		var vErr *ebpf.VerifierError
		if errors.As(err, &vErr) {
			t.Fatalf("%+v", vErr)
		}
		t.Fatal(err)
	}
	defer coll.Close()

	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("%-40s %8s %8s %10s", "program", "insns", "xlated", "processed")
	for _, name := range names {
		p := coll.Programs[name]
		xlated := "-"
		if info, err := p.Info(); err == nil {
			if size, err := info.TranslatedSize(); err == nil {
				xlated = strconv.Itoa(size / 8)
			}
		}
		processed := "-"
		if m := verifierProcessedRe.FindStringSubmatch(p.VerifierLog); m != nil {
			processed = m[1]
		}
		t.Logf("%-40s %8d %8s %10s", name, spec.Programs[name].Instructions.Size()/8, xlated, processed)
	}
}

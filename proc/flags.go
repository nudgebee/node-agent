package proc

import (
	"bufio"
	"os"
	"strings"
)

type Flags struct {
	EbpfProfilingDisabled bool
	EbpfTracesDisabled    bool
	LogMonitoringDisabled bool
}

func GetFlags(pid uint32) (Flags, error) {
	flags := Flags{}
	f, err := os.Open(Path(pid, "environ"))
	if err != nil {
		return Flags{}, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString(0)
		if err != nil {
			break
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		// COROOT_* env vars are accepted for backwards compatibility with
		// users migrating from coroot/coroot-node-agent. NUDGEBEE_* is the
		// canonical prefix going forward.
		if !strings.HasPrefix(kv[0], "NUDGEBEE_") && !strings.HasPrefix(kv[0], "COROOT_") {
			continue
		}
		switch kv[0] {
		case "NUDGEBEE_EBPF_PROFILING", "COROOT_EBPF_PROFILING":
			flags.EbpfProfilingDisabled = strings.Contains(kv[1], "disabled")
		case "NUDGEBEE_LOG_MONITORING", "COROOT_LOG_MONITORING":
			flags.LogMonitoringDisabled = strings.Contains(kv[1], "disabled")
		case "NUDGEBEE_EBPF_TRACES", "COROOT_EBPF_TRACES":
			flags.EbpfTracesDisabled = strings.Contains(kv[1], "disabled")
		}
	}
	return flags, nil
}

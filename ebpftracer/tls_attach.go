package ebpftracer

import (
	"errors"
	"io/fs"
	"strings"
	"syscall"

	lru "github.com/hashicorp/golang-lru/v2"
	"k8s.io/klog/v2"
)

// TLSAttachResult is the outcome of one attempt to attach TLS uprobes to a
// process. The values are exported as the result label of
// node_agent_tls_attach_total, so an operator can tell "attached",
// "nothing to attach to" and "failed" apart without raising log verbosity.
type TLSAttachResult string

const (
	// TLSAttachNotApplicable: there is nothing of this kind to probe, e.g. the
	// executable is not a Go binary. Not counted.
	TLSAttachNotApplicable TLSAttachResult = ""

	TLSAttached TLSAttachResult = "attached"
	// TLSAttachedNoOffsets: uprobes are attached, but the per-process struct
	// offsets could not be written, so the probes fall back to built-in
	// defaults and cannot unwrap gRPC's syscallConn.
	TLSAttachedNoOffsets TLSAttachResult = "attached_no_offsets"
	// TLSAttachNoLibrary: no libssl is mapped into the process (yet).
	TLSAttachNoLibrary TLSAttachResult = "no_library"
	// TLSAttachNoSymbols: the binary or library lacks the functions the
	// probes attach to: a Go binary without crypto/tls, or a stripped build
	// whose functions cannot be located.
	TLSAttachNoSymbols TLSAttachResult = "no_symbols"
	// TLSAttachUnsupported: a Go version below 1.17, or a libssl version that
	// cannot be parsed.
	TLSAttachUnsupported TLSAttachResult = "unsupported"
	// TLSAttachProcessExited: the process went away during the attempt.
	TLSAttachProcessExited TLSAttachResult = "process_exited"
	TLSAttachError         TLSAttachResult = "error"
)

// goTLSSkipCache remembers Go binaries that can never be probed (not Go, too
// old, no crypto/tls), keyed by file identity rather than path: a path is
// only meaningful inside one container, and the same path in another
// container, or in the next image version, can be a different binary.
var goTLSSkipCache, _ = lru.New[binaryKey, goTLSSkip](symbolCacheSize)

type goTLSSkip struct {
	result TLSAttachResult
	isGo   bool
}

// tlsAttachLogged records which outcomes have already been logged for which
// binary. A binary run by thousands of short-lived processes is reported
// once, not once per process, so the log stays useful at default verbosity.
var tlsAttachLogged, _ = lru.New[tlsLogKey, struct{}](symbolCacheSize)

type tlsLogKey struct {
	bin    binaryKey
	lib    string
	result TLSAttachResult
}

// logTLSAttachOnce logs msg the first time this binary reaches this outcome
// and returns whether it did. Failures are warnings: they mean traffic that
// should have been captured is not.
func logTLSAttachOnce(bin binaryKey, lib string, result TLSAttachResult, format string, args ...any) bool {
	if ok, _ := tlsAttachLogged.ContainsOrAdd(tlsLogKey{bin: bin, lib: lib, result: result}, struct{}{}); ok {
		return false
	}
	switch result {
	case TLSAttached, TLSAttachNoSymbols, TLSAttachUnsupported:
		klog.InfofDepth(1, format, args...)
	default:
		klog.WarningfDepth(1, format, args...)
	}
	return true
}

// processGone reports whether err means the process (or its files) went away
// mid-attempt, which is routine for short-lived processes and not a failure.
func processGone(err error) bool {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return true
	}
	s := err.Error()
	return strings.HasSuffix(s, "no such file or directory") || strings.HasSuffix(s, "no such process")
}

// failureResult classifies an attach error.
func failureResult(err error) TLSAttachResult {
	if processGone(err) {
		return TLSAttachProcessExited
	}
	return TLSAttachError
}

package ebpftracer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A binary run by many short-lived processes must be reported once per
// outcome, not once per process: per-process logging is what pushed these
// messages to raised verbosity, where nobody sees them.
func TestLogTLSAttachOnceLogsEachOutcomeOncePerBinary(t *testing.T) {
	bin := binaryKey{dev: 1, ino: 2, size: 3, mtimeNsec: 4}
	if !logTLSAttachOnce(bin, "go", TLSAttachError, "first %d", 1) {
		t.Fatal("first failure of a binary was not logged")
	}
	for i := 0; i < 100; i++ {
		if logTLSAttachOnce(bin, "go", TLSAttachError, "repeat %d", i) {
			t.Fatalf("repeat %d of the same outcome was logged again", i)
		}
	}
	if !logTLSAttachOnce(bin, "go", TLSAttached, "attached") {
		t.Error("a different outcome for the same binary was suppressed")
	}
	if !logTLSAttachOnce(bin, "openssl", TLSAttachError, "openssl") {
		t.Error("the same outcome for a different library was suppressed")
	}
	other := bin
	other.ino++
	if !logTLSAttachOnce(other, "go", TLSAttachError, "other binary") {
		t.Error("the same outcome for a different binary was suppressed")
	}
}

// A process exiting mid-attach is routine and must not be reported as a
// capture failure; anything else is one.
func TestFailureResultSeparatesExitedProcessesFromErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	_, statErr := os.Stat(missing)
	for _, tc := range []struct {
		err  error
		want TLSAttachResult
	}{
		{statErr, TLSAttachProcessExited},
		{fs.ErrNotExist, TLSAttachProcessExited},
		{fmt.Errorf("open executable: %w", syscall.ESRCH), TLSAttachProcessExited},
		{errors.New("creating perf_uprobe PMU: no such process"), TLSAttachProcessExited},
		{errors.New("opening perf event: input/output error"), TLSAttachError},
		{fmt.Errorf("open: %w", fs.ErrPermission), TLSAttachError},
	} {
		if got := failureResult(tc.err); got != tc.want {
			t.Errorf("failureResult(%q) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

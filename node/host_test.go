package node

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLoadAvg(t *testing.T) {
	l1, l5, l15, err := loadAvg("fixtures/proc")
	require.NoError(t, err)
	assert.Equal(t, []float64{0.52, 0.58, 0.59}, []float64{l1, l5, l15})
}

func TestHostMounts(t *testing.T) {
	mounts, err := hostMounts("fixtures/proc")
	require.NoError(t, err)
	assert.Equal(t, []hostMount{
		{device: "/dev/nvme0n1p1", mountPoint: "/", fsType: "ext4"},
		{device: "tmpfs", mountPoint: "/run", fsType: "tmpfs"},
		{device: "/dev/nvme1n1", mountPoint: "/var/lib/data", fsType: "xfs", readonly: true}, // remounted read-only further down
		{device: "/dev/nvme1n1", mountPoint: "/mnt/my disk", fsType: "xfs", readonly: true},
		{device: "/dev/nvme2n1", mountPoint: "/srv", fsType: "ext4"}, // mounted over a tmpfs
	}, mounts)
}

func TestUnescapeMount(t *testing.T) {
	assert.Equal(t, "/mnt/a b", unescapeMount(`/mnt/a\040b`))
	assert.Equal(t, `/mnt/a\b`, unescapeMount(`/mnt/a\134b`))
	assert.Equal(t, `/mnt/trailing\`, unescapeMount(`/mnt/trailing\`))
	assert.Equal(t, "/plain", unescapeMount("/plain"))
}

// A statfs that hangs must not be called again for the same mount point
// while it is still in flight: each hung call holds an OS thread.
func TestStatfsHungMountSingleCall(t *testing.T) {
	savedSyscall, savedTimeout := statfsSyscall, statfsTimeout
	defer func() { statfsSyscall, statfsTimeout = savedSyscall, savedTimeout }()
	statfsTimeout = 50 * time.Millisecond

	release := make(chan struct{})
	var calls atomic.Int32
	statfsSyscall = func(string, *unix.Statfs_t) error {
		calls.Add(1)
		<-release
		return nil
	}
	h := newHostCollector("fixtures/proc")
	_, err := h.statfs("/mnt/nfs")
	assert.ErrorIs(t, err, errStatfsTimeout)
	for i := 0; i < 3; i++ {
		_, err = h.statfs("/mnt/nfs")
		assert.ErrorIs(t, err, errStatfsRunning)
	}
	assert.Equal(t, int32(1), calls.Load())

	close(release) // the hung call returns
	require.Eventually(t, func() bool {
		_, err := h.statfs("/mnt/nfs")
		return err == nil
	}, time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(2), calls.Load())
}

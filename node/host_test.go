package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{device: "/dev/nvme1n1", mountPoint: "/var/lib/data", fsType: "xfs"},
		{device: "/dev/nvme1n1", mountPoint: "/mnt/my disk", fsType: "xfs", readonly: true},
	}, mounts)
}

func TestUnescapeMount(t *testing.T) {
	assert.Equal(t, "/mnt/a b", unescapeMount(`/mnt/a\040b`))
	assert.Equal(t, `/mnt/a\b`, unescapeMount(`/mnt/a\134b`))
	assert.Equal(t, `/mnt/trailing\`, unescapeMount(`/mnt/trailing\`))
	assert.Equal(t, "/plain", unescapeMount("/plain"))
}

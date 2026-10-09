package proc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetStartTime(t *testing.T) {
	saved := bootTime
	defer func() { bootTime = saved }()
	bootTime = 1700000000

	// starttime is field 22 of /proc/<pid>/stat, in clock ticks since boot:
	// 12345 ticks = 123.45s. The comm contains spaces and ')', so fields
	// must be counted from the last ')'.
	assert.Equal(t, time.Unix(1700000000+123, 0), GetStartTime(123))

	assert.True(t, GetStartTime(999999).IsZero(), "missing pid")

	bootTime = 0
	assert.True(t, GetStartTime(123).IsZero(), "unknown boot time")
}

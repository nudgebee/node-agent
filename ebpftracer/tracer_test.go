package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/assert"
	"k8s.io/klog/v2"
)

func TestProcessL7RecordTruncationFlags(t *testing.T) {
	// Capture klog output
	var logBuf bytes.Buffer
	klog.LogToStderr(false) // Disable stderr for the duration of this test
	klog.SetOutput(&logBuf)
	defer func() {
		klog.SetOutput(os.Stderr) // Restore klog output to stderr
		klog.LogToStderr(true)
	}()

	testCases := []struct {
		name                      string
		flagsToSet                uint16
		payloadSize               uint64
		responseSize              uint64
		expectedRequestTruncated  bool
		expectedResponseTruncated bool
		expectedLogSubstrings     []string
	}{
		{
			name:                      "Request truncated",
			flagsToSet:                L7EventFlagRequestTruncated,
			payloadSize:               10,
			responseSize:              5,
			expectedRequestTruncated:  true,
			expectedResponseTruncated: false,
			expectedLogSubstrings:     []string{"L7 Request payload potentially truncated"},
		},
		{
			name:                      "Response truncated",
			flagsToSet:                L7EventFlagResponseTruncated,
			payloadSize:               10,
			responseSize:              5,
			expectedRequestTruncated:  false,
			expectedResponseTruncated: true,
			expectedLogSubstrings:     []string{"L7 Response payload potentially truncated"},
		},
		{
			name:                      "Both truncated",
			flagsToSet:                L7EventFlagRequestTruncated | L7EventFlagResponseTruncated,
			payloadSize:               10,
			responseSize:              5,
			expectedRequestTruncated:  true,
			expectedResponseTruncated: true,
			expectedLogSubstrings:     []string{"L7 Request payload potentially truncated", "L7 Response payload potentially truncated"},
		},
		{
			name:                      "No flags set",
			flagsToSet:                0,
			payloadSize:               10,
			responseSize:              5,
			expectedRequestTruncated:  false,
			expectedResponseTruncated: false,
			expectedLogSubstrings:     []string{}, // No truncation logs expected
		},
		{
			name:                      "Request truncated with zero payload size in event",
			flagsToSet:                L7EventFlagRequestTruncated,
			payloadSize:               0, // eBPF might report 0 if it couldn't copy, but flag is set
			responseSize:              5,
			expectedRequestTruncated:  true,
			expectedResponseTruncated: false,
			expectedLogSubstrings:     []string{"L7 Request payload potentially truncated"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf.Reset() // Reset log buffer for each test case

			testL7Event := l7Event{
				Fd:                  1,
				ConnectionTimestamp: uint64(time.Now().UnixNano()),
				Pid:                 1234,
				Status:              int32(l7.StatusOk),
				Duration:            uint64(time.Millisecond),
				Protocol:            uint8(l7.ProtocolHTTP),
				Method:              uint8(l7.MethodUnknown), // Not relevant for this test
				Flags:               tc.flagsToSet,
				StatementId:         0,
				PayloadSize:         tc.payloadSize,   // Original intended size
				ResponseSize:        tc.responseSize, // Original intended size
			}

			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, &testL7Event)
			assert.NoError(t, err)

			// Append dummy bytes for payload and response based on PayloadSize and ResponseSize
			// processL7Record expects these bytes to be present in rawSample after l7Event struct.
			// The actual content of these dummy bytes doesn't matter for this test.
			// The number of dummy bytes should be what would have been copied.
			// Here, we simulate that the full intended payload/response was available in the eBPF buffer initially.
			// The truncation logic in processL7Record will then virtually "truncate" them if sizes are large,
			// but for this test, we just need to provide enough bytes for it to try to read.
			// The actual truncation happens based on MAX_PAYLOAD_SIZE, which is not directly tested here,
			// rather we test if the flags are correctly interpreted.
			// For simplicity, let's assume the sizes in l7Event are small enough that they wouldn't
			// be truncated by MAX_PAYLOAD_SIZE, so payloadData/responseData would be of these sizes.

			// The `payloadBytes` in `processL7Record` is `reader.Bytes()`.
			// `reader` initially contains the serialized `testL7Event`.
			// `binary.Read` consumes data from `reader`.
			// `payloadBytes` will be the *remaining* bytes.
			// So, we need to append dummy data for payload and response to `buf` *after* serializing `testL7Event`.

			dummyPayload := make([]byte, tc.payloadSize)
			_, err = buf.Write(dummyPayload)
			assert.NoError(t, err)

			dummyResponse := make([]byte, tc.responseSize)
			_, err = buf.Write(dummyResponse)
			assert.NoError(t, err)

			rawSampleBytes := buf.Bytes()

			event, err := processL7Record(rawSampleBytes, 0)
			assert.NoError(t, err)

			assert.NotNil(t, event.L7Request, "L7Request should not be nil")
			assert.Equal(t, EventTypeL7Request, event.Type, "Event type should be L7Request")

			assert.Equal(t, tc.expectedRequestTruncated, event.L7Request.RequestTruncated, "RequestTruncated flag mismatch")
			assert.Equal(t, tc.expectedResponseTruncated, event.L7Request.ResponseTruncated, "ResponseTruncated flag mismatch")

			// Check that the actual copied payload/response sizes match what was in l7Event (assuming no MAX_PAYLOAD_SIZE truncation for this test's purpose)
			// This also verifies that the payload slicing logic in processL7Record is correct with the provided sizes.
			assert.Equal(t, int(tc.payloadSize), len(event.L7Request.Payload), "Copied payload length mismatch")
			assert.Equal(t, int(tc.responseSize), len(event.L7Request.Response), "Copied response length mismatch")


			logOutput := logBuf.String()
			if len(tc.expectedLogSubstrings) > 0 {
				for _, sub := range tc.expectedLogSubstrings {
					assert.Contains(t, logOutput, sub, "Expected log substring not found")
				}
			} else {
				// If no specific log substrings are expected (e.g. no truncation),
				// ensure no truncation warnings appear.
				assert.NotContains(t, logOutput, "L7 Request payload potentially truncated", "Unexpected request truncation log")
				assert.NotContains(t, logOutput, "L7 Response payload potentially truncated", "Unexpected response truncation log")
			}
		})
	}
}

// Placeholder for TestMain if other setup/teardown is needed for the package
// func TestMain(m *testing.M) {
// 	// klog.InitFlags(nil) // if using klog flags
// 	os.Exit(m.Run())
// }

package ebpftracer

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Configuration for memory reading limits
const (
	// Size thresholds
	SmallResponseLimit  = 16 * 1024  // 16KB - full capture
	MediumResponseLimit = 64 * 1024  // 64KB - selective capture
	LargeResponseLimit  = 256 * 1024 // 256KB - headers only
	MaxCaptureLimit     = 1024 * 1024 // 1MB - skip completely
	
	// Header preview size for content-type detection
	HeaderPreviewSize = 8 * 1024 // 8KB
	
	// System call constants
	SYS_PROCESS_VM_READV = 310 // x86_64
)

// IOVec structure for process_vm_readv syscall
type IOVec struct {
	Base uintptr
	Len  uint64
}

// CaptureType defines how we should capture the data
type CaptureType int

const (
	CaptureComplete CaptureType = iota // Full data capture
	CaptureHeaders                     // Headers only (first 8KB)
	CaptureSkip                        // Skip completely
)

// CaptureDecision holds information about how to capture data
type CaptureDecision struct {
	Type        CaptureType
	MaxSize     uint32
	Reason      string
}

// MemoryReader handles complete data reading from process memory
type MemoryReader struct {
	// Configuration
	maxRequestSize  uint32
	maxResponseSize uint32
	headerPreviewSize uint32
	
	// Statistics
	totalReads       uint64
	successfulReads  uint64
	skippedReads     uint64
	headerOnlyReads  uint64
}

// NewMemoryReader creates a new memory reader with default limits
func NewMemoryReader() *MemoryReader {
	return &MemoryReader{
		maxRequestSize:    MediumResponseLimit,  // 64KB for requests
		maxResponseSize:   MediumResponseLimit,  // 64KB for responses  
		headerPreviewSize: HeaderPreviewSize,    // 8KB for headers
	}
}

// DecideCapture determines how to capture data based on size and type
func (mr *MemoryReader) DecideCapture(size uint32, isResponse bool) CaptureDecision {
	maxSize := mr.maxRequestSize
	if isResponse {
		maxSize = mr.maxResponseSize
	}
	
	switch {
	case size == 0:
		return CaptureDecision{CaptureSkip, 0, "empty data"}
		
	case size > MaxCaptureLimit:
		mr.skippedReads++
		return CaptureDecision{CaptureSkip, 0, "too large (>1MB)"}
		
	case size <= SmallResponseLimit:
		// Small data - always capture completely
		return CaptureDecision{CaptureComplete, size, "small data"}
		
	case size <= maxSize:
		// Medium data - capture completely for now, later add content-type filtering
		return CaptureDecision{CaptureComplete, size, "medium data"}
		
	case size <= LargeResponseLimit:
		// Large data - headers only
		mr.headerOnlyReads++
		return CaptureDecision{CaptureHeaders, mr.headerPreviewSize, "large data - headers only"}
		
	default:
		// Very large data - skip
		mr.skippedReads++
		return CaptureDecision{CaptureSkip, 0, "very large data"}
	}
}

// ReadProcessMemory reads data from another process using process_vm_readv
func (mr *MemoryReader) ReadProcessMemory(pid uint32, addr uint64, size uint32) ([]byte, error) {
	if addr == 0 || size == 0 {
		return nil, fmt.Errorf("invalid address or size")
	}
	
	mr.totalReads++
	
	// Allocate buffer for the data
	buffer := make([]byte, size)
	
	// Set up local iovec (where we want to read TO)
	localIov := IOVec{
		Base: uintptr(unsafe.Pointer(&buffer[0])),
		Len:  uint64(size),
	}
	
	// Set up remote iovec (where we want to read FROM)
	remoteIov := IOVec{
		Base: uintptr(addr),
		Len:  uint64(size),
	}
	
	// Call process_vm_readv syscall
	r1, _, errno := syscall.Syscall6(
		SYS_PROCESS_VM_READV,
		uintptr(pid),                              // pid
		uintptr(unsafe.Pointer(&localIov)),        // local_iov
		uintptr(1),                                // liovcnt
		uintptr(unsafe.Pointer(&remoteIov)),       // remote_iov
		uintptr(1),                                // riovcnt
		uintptr(0),                                // flags
	)
	
	if errno != 0 {
		return nil, fmt.Errorf("process_vm_readv failed: %v", errno)
	}
	
	bytesRead := int(r1)
	if bytesRead <= 0 {
		return nil, fmt.Errorf("process_vm_readv read %d bytes", bytesRead)
	}
	
	mr.successfulReads++
	
	// Return only the bytes that were actually read
	return buffer[:bytesRead], nil
}

// ReadCompleteHTTPData reads complete HTTP request or response data
func (mr *MemoryReader) ReadCompleteHTTPData(pid uint32, addr uint64, size uint32, isResponse bool) ([]byte, *CaptureDecision, error) {
	// Decide how to capture this data
	decision := mr.DecideCapture(size, isResponse)
	
	if decision.Type == CaptureSkip {
		return nil, &decision, nil
	}
	
	// Read the data according to decision
	data, err := mr.ReadProcessMemory(pid, addr, decision.MaxSize)
	if err != nil {
		return nil, &decision, fmt.Errorf("failed to read process memory: %w", err)
	}
	
	return data, &decision, nil
}

// ExtractHTTPHeaders extracts HTTP headers from data
func ExtractHTTPHeaders(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return data, nil
	}
	
	// Find the end of headers (double CRLF)
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return data[:i+4], nil // Include the double CRLF
		}
	}
	
	// If no double CRLF found, assume it's all headers (or incomplete)
	return data, nil
}

// DetectContentType extracts Content-Type from HTTP headers
func DetectContentType(headers []byte) string {
	headerStr := string(headers)
	
	// Look for Content-Type header (case insensitive)
	contentTypePatterns := []string{
		"Content-Type:",
		"content-type:",
		"Content-type:",
		"CONTENT-TYPE:",
	}
	
	for _, pattern := range contentTypePatterns {
		if idx := indexOf(headerStr, pattern); idx != -1 {
			start := idx + len(pattern)
			
			// Skip whitespace
			for start < len(headerStr) && (headerStr[start] == ' ' || headerStr[start] == '\t') {
				start++
			}
			
			// Find end of line
			end := start
			for end < len(headerStr) && headerStr[end] != '\r' && headerStr[end] != '\n' {
				end++
			}
			
			if end > start {
				return headerStr[start:end]
			}
		}
	}
	
	return ""
}

// ShouldSkipBinaryContent determines if we should skip based on content type
func ShouldSkipBinaryContent(contentType string) bool {
	binaryTypes := []string{
		"image/",
		"video/",
		"audio/",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"multipart/form-data", // File uploads
	}
	
	contentTypeLower := toLower(contentType)
	for _, binType := range binaryTypes {
		if contains(contentTypeLower, binType) {
			return true
		}
	}
	
	return false
}

// GetStatistics returns memory reader statistics
func (mr *MemoryReader) GetStatistics() map[string]uint64 {
	return map[string]uint64{
		"total_reads":       mr.totalReads,
		"successful_reads":  mr.successfulReads,
		"skipped_reads":     mr.skippedReads,
		"header_only_reads": mr.headerOnlyReads,
	}
}

// Helper functions
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func contains(s, substr string) bool {
	return indexOf(s, substr) != -1
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}
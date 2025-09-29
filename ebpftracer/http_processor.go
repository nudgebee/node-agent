package ebpftracer

import (
	"fmt"
	"strings"
	"time"
	
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
)

// HTTPProcessor handles complete HTTP request/response processing
type HTTPProcessor struct {
	memoryReader *MemoryReader
	
	// Statistics
	totalEvents       uint64
	httpEvents        uint64
	completeCaptures  uint64
	headerOnlyCaptures uint64
	skippedEvents     uint64
	utf8Errors        uint64
	binarySkipped     uint64
}

// NewHTTPProcessor creates a new HTTP processor
func NewHTTPProcessor() *HTTPProcessor {
	return &HTTPProcessor{
		memoryReader: NewMemoryReader(),
	}
}

// ProcessL7Event processes an L7 event with complete data reading
func (hp *HTTPProcessor) ProcessL7Event(event *l7Event) (*l7.RequestData, error) {
	hp.totalEvents++
	
	// Only process HTTP events
	if event.Protocol != 1 { // PROTOCOL_HTTP = 1
		return nil, nil
	}
	
	hp.httpEvents++
	
	// Read complete request data
	requestData, requestDecision, err := hp.readRequestData(event)
	if err != nil {
		return nil, fmt.Errorf("failed to read request data: %w", err)
	}
	
	// Read complete response data  
	responseData, responseDecision, err := hp.readResponseData(event)
	if err != nil {
		return nil, fmt.Errorf("failed to read response data: %w", err)
	}
	
	// Update statistics
	hp.updateStatistics(requestDecision, responseDecision)
	
	// Create L7 request data with complete information
	result := hp.createRequestData(event, requestData, responseData, requestDecision, responseDecision)
	
	return result, nil
}

// readRequestData reads complete HTTP request data from process memory
func (hp *HTTPProcessor) readRequestData(event *l7Event) ([]byte, *CaptureDecision, error) {
	if event.RequestBufferAddr == 0 || event.RequestDataSize == 0 {
		// Fall back to eBPF payload data
		payloadSize := int(event.PayloadSize)
		if payloadSize > len(event.Payload) {
			payloadSize = len(event.Payload)
		}
		
		// Find actual end of data (null terminator or first non-printable)
		actualSize := 0
		for i := 0; i < payloadSize; i++ {
			if event.Payload[i] == 0 {
				break
			}
			actualSize = i + 1
		}
		
		decision := CaptureDecision{CaptureComplete, uint32(actualSize), "fallback to eBPF payload"}
		return event.Payload[:actualSize], &decision, nil
	}
	
	// Use process_vm_readv for complete data
	return hp.memoryReader.ReadCompleteHTTPData(
		event.Pid,
		event.RequestBufferAddr,
		event.RequestDataSize,
		false, // isResponse = false
	)
}

// readResponseData reads complete HTTP response data from process memory
func (hp *HTTPProcessor) readResponseData(event *l7Event) ([]byte, *CaptureDecision, error) {
	if event.ResponseBufferAddr == 0 || event.ResponseDataSize == 0 {
		// Fall back to eBPF response data
		responseSize := int(event.ResponseSize)
		if responseSize > len(event.Response) {
			responseSize = len(event.Response)
		}
		
		// Find actual end of data
		actualSize := 0
		for i := 0; i < responseSize; i++ {
			if event.Response[i] == 0 {
				break
			}
			actualSize = i + 1
		}
		
		decision := CaptureDecision{CaptureComplete, uint32(actualSize), "fallback to eBPF response"}
		return event.Response[:actualSize], &decision, nil
	}
	
	// Use process_vm_readv for complete data
	return hp.memoryReader.ReadCompleteHTTPData(
		event.Pid,
		event.ResponseBufferAddr,
		event.ResponseDataSize,
		true, // isResponse = true
	)
}

// createRequestData creates L7 request data from complete HTTP data
func (hp *HTTPProcessor) createRequestData(event *l7Event, requestData, responseData []byte, 
	requestDecision, responseDecision *CaptureDecision) *l7.RequestData {
	
	// Extract status code from complete response data
	statusCode := hp.parseHTTPResponseStatus(responseData)
	
	// Create sanitized payloads (UTF-8 safe)
	requestPayload := hp.sanitizeForUTF8(requestData, "request")
	responsePayload := hp.sanitizeForUTF8(responseData, "response")
	
	return &l7.RequestData{
		Protocol:     l7.ProtocolHTTP,
		Status:       l7.Status(statusCode),
		Duration:     time.Duration(event.Duration),
		Method:       l7.MethodUnknown, // HTTP methods are not defined in Method enum
		StatementId:  event.StatementId,
		Payload:      []byte(requestPayload),
		PayloadSize:  uint64(len(requestData)),
		ResponseSize: uint64(len(responseData)),
		Response:     []byte(responsePayload),
	}
}

// parseHTTPRequest extracts method and URL from HTTP request data
func (hp *HTTPProcessor) parseHTTPRequest(data []byte) (method, url string) {
	if len(data) < 10 { // Minimum "GET / HTTP"
		return "UNKNOWN", ""
	}
	
	// Find first line (request line)
	firstLineEnd := 0
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			firstLineEnd = i
			break
		}
	}
	
	if firstLineEnd == 0 {
		firstLineEnd = len(data)
	}
	
	requestLine := string(data[:firstLineEnd])
	parts := strings.SplitN(requestLine, " ", 3)
	
	if len(parts) >= 2 {
		return parts[0], parts[1] // method, url
	}
	
	return "UNKNOWN", ""
}

// parseHTTPResponseStatus extracts status code from HTTP response data
func (hp *HTTPProcessor) parseHTTPResponseStatus(data []byte) int {
	if len(data) < 12 { // Minimum "HTTP/1.1 200"
		return 0
	}
	
	// Find first line (status line)
	firstLineEnd := 0
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			firstLineEnd = i
			break
		}
	}
	
	if firstLineEnd == 0 || firstLineEnd < 12 {
		return 0
	}
	
	statusLine := string(data[:firstLineEnd])
	parts := strings.SplitN(statusLine, " ", 3)
	
	if len(parts) >= 2 {
		// Parse status code
		statusStr := parts[1]
		if len(statusStr) == 3 {
			// Simple integer parsing
			status := 0
			for i := 0; i < 3; i++ {
				if statusStr[i] >= '0' && statusStr[i] <= '9' {
					status = status*10 + int(statusStr[i]-'0')
				} else {
					return 0 // Invalid status code
				}
			}
			return status
		}
	}
	
	return 0
}

// sanitizeForUTF8 creates UTF-8 safe payload strings
func (hp *HTTPProcessor) sanitizeForUTF8(data []byte, dataType string) string {
	if len(data) == 0 {
		return ""
	}
	
	// Check for binary data patterns - return empty instead of [BINARY] label
	if hp.isBinaryData(data) {
		return ""
	}
	
	// Convert to string and handle invalid UTF-8
	result := make([]rune, 0, len(data))
	
	for i := 0; i < len(data); {
		if data[i] < 0x80 {
			// ASCII character
			if data[i] >= 0x20 || data[i] == '\t' || data[i] == '\n' || data[i] == '\r' {
				result = append(result, rune(data[i]))
			} else {
				// Replace control characters
				result = append(result, '�')
			}
			i++
		} else {
			// Multi-byte UTF-8 - replace with replacement character for safety
			result = append(result, '�')
			i++
		}
	}
	
	return string(result)
}

// isBinaryData detects if data contains binary patterns
func (hp *HTTPProcessor) isBinaryData(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	
	// TLS patterns
	if (data[0] == 0x16 && data[1] == 0x03) || (data[0] == 0x17 && data[1] == 0x03) {
		return true
	}
	
	// High percentage of non-printable characters
	nonPrintable := 0
	for i := 0; i < len(data) && i < 100; i++ { // Check first 100 bytes
		if data[i] < 0x20 && data[i] != '\t' && data[i] != '\n' && data[i] != '\r' {
			nonPrintable++
		}
	}
	
	// If more than 30% non-printable, consider it binary
	checkSize := len(data)
	if checkSize > 100 {
		checkSize = 100
	}
	
	return float64(nonPrintable)/float64(checkSize) > 0.3
}

// updateStatistics updates processing statistics
func (hp *HTTPProcessor) updateStatistics(requestDecision, responseDecision *CaptureDecision) {
	if requestDecision != nil {
		switch requestDecision.Type {
		case CaptureComplete:
			hp.completeCaptures++
		case CaptureHeaders:
			hp.headerOnlyCaptures++
		case CaptureSkip:
			hp.skippedEvents++
		}
	}
	
	if responseDecision != nil {
		switch responseDecision.Type {
		case CaptureComplete:
			hp.completeCaptures++
		case CaptureHeaders:
			hp.headerOnlyCaptures++
		case CaptureSkip:
			hp.skippedEvents++
		}
	}
}

// GetStatistics returns HTTP processor statistics
func (hp *HTTPProcessor) GetStatistics() map[string]uint64 {
	stats := hp.memoryReader.GetStatistics()
	
	// Add HTTP processor specific stats
	stats["total_events"] = hp.totalEvents
	stats["http_events"] = hp.httpEvents
	stats["complete_captures"] = hp.completeCaptures
	stats["header_only_captures"] = hp.headerOnlyCaptures
	stats["skipped_events"] = hp.skippedEvents
	stats["utf8_errors"] = hp.utf8Errors
	stats["binary_skipped"] = hp.binarySkipped
	
	return stats
}
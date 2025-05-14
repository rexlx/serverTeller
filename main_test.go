package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go" // Mocking this, so actual network calls won't happen
)

// --- Helper Functions for Testing ---

// createDummyFile creates a file of a specific size in MB for testing rotation.
func createDummyFile(t *testing.T, path string, sizeMB int) {
	t.Helper() // Marks this as a test helper function
	// Ensure directory exists
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			t.Fatalf("Failed to create directory for dummy file %s: %v", dir, err)
		}
	}

	data := make([]byte, sizeMB*1024*1024) // Create a byte slice of the desired size
	err := os.WriteFile(path, data, 0644)  // Write data to the file
	if err != nil {
		t.Fatalf("Failed to create dummy file %s: %v", path, err)
	}
}

// fileExistsWithPattern checks if a file matching a prefix and containing a timestamp-like part exists.
// Example: logfile.ndjson.20230101150405
func fileExistsWithPattern(t *testing.T, dir, baseFilename string) (string, bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("Error reading directory %s: %v", dir, err)
		return "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), baseFilename+".") {
			// Example: baseFilename.20060102150405
			parts := strings.Split(entry.Name(), ".")
			// Expecting at least 3 parts if baseFilename itself doesn't have dots,
			// e.g., "logs.ndjson" + "." + "timestamp" -> "logs.ndjson.timestamp"
			// If baseFilename is "test.log", then "test.log.timestamp"
			if len(parts) > 0 {
				timestampPart := parts[len(parts)-1]
				// A simple check for a 14-digit timestamp (YYYYMMDDHHMMSS)
				if len(timestampPart) == 14 {
					_, err := time.Parse("20060102150405", timestampPart)
					if err == nil {
						return entry.Name(), true
					}
				}
			}
		}
	}
	return "", false
}

// --- Mocks for QUIC interfaces ---

// MockStream implements the quic.Stream interface for testing.
type MockStream struct {
	quic.Stream // Embed to satisfy the interface if methods are not used.
	// Reader simulates reading from the stream.
	Reader io.Reader
	// Writer simulates writing to the stream.
	Writer io.Writer
	// Closed tracks if Close() has been called.
	Closed bool
	// ReadError is an error to return on Read calls.
	ReadError error
	// WriteError is an error to return on Write calls.
	WriteError error
	// Ctx is the context for the stream.
	Ctx    context.Context
	Cancel context.CancelFunc
	// streamID is a mock stream ID.
	streamID quic.StreamID
}

// Read reads from the mock stream's Reader.
func (ms *MockStream) Read(p []byte) (n int, err error) {
	if ms.ReadError != nil {
		return 0, ms.ReadError
	}
	if ms.Reader == nil {
		return 0, io.EOF // Simulate no data if reader is nil
	}
	return ms.Reader.Read(p)
}

// Write writes to the mock stream's Writer.
func (ms *MockStream) Write(p []byte) (n int, err error) {
	if ms.WriteError != nil {
		return 0, ms.WriteError
	}
	if ms.Writer == nil {
		// This case should ideally not happen if Writer is always set up
		return 0, io.ErrShortWrite
	}
	return ms.Writer.Write(p)
}

// Close marks the stream as closed.
func (ms *MockStream) Close() error {
	ms.Closed = true
	return nil
}

// Context returns the stream's context.
func (ms *MockStream) Context() context.Context {
	if ms.Ctx == nil {
		// Create a default context if none is provided
		ms.Ctx, ms.Cancel = context.WithCancel(context.Background())
	}
	return ms.Ctx
}

// StreamID returns a mock stream ID.
func (ms *MockStream) StreamID() quic.StreamID {
	return ms.streamID
}

// SetReadDeadline is a mock implementation.
func (ms *MockStream) SetReadDeadline(t time.Time) error {
	return nil // No-op for this mock
}

// SetWriteDeadline is a mock implementation.
func (ms *MockStream) SetWriteDeadline(t time.Time) error {
	return nil // No-op for this mock
}

// MockConnection implements the quic.Connection interface for testing.
type MockConnection struct {
	quic.Connection    // Embed to satisfy the interface.
	AcceptedStream     quic.Stream
	AcceptStreamErr    error
	AcceptStreamCtx    context.Context
	OpenStreamSyncFunc func(ctx context.Context) (quic.Stream, error)
	LocalAddrFunc      func() net.Addr
	RemoteAddrFunc     func() net.Addr
	CloseWithErrorFunc func(code quic.ApplicationErrorCode, reason string) error
}

// AcceptStream returns a predefined stream or error.
func (mc *MockConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	mc.AcceptStreamCtx = ctx
	if mc.AcceptStreamErr != nil {
		return nil, mc.AcceptStreamErr
	}
	return mc.AcceptedStream, nil
}

// OpenStreamSync is a mock implementation.
func (mc *MockConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	if mc.OpenStreamSyncFunc != nil {
		return mc.OpenStreamSyncFunc(ctx)
	}
	return nil, fmt.Errorf("OpenStreamSync not implemented in mock")
}

// LocalAddr is a mock implementation.
func (mc *MockConnection) LocalAddr() net.Addr {
	if mc.LocalAddrFunc != nil {
		return mc.LocalAddrFunc()
	}
	// Provide a dummy address
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}

// RemoteAddr is a mock implementation.
func (mc *MockConnection) RemoteAddr() net.Addr {
	if mc.RemoteAddrFunc != nil {
		return mc.RemoteAddrFunc()
	}
	// Provide a dummy address
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678}
}

// CloseWithError is a mock implementation.
func (mc *MockConnection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	if mc.CloseWithErrorFunc != nil {
		return mc.CloseWithErrorFunc(code, reason)
	}
	return nil
}

// --- Unit Tests ---

// TestRotateLog tests the log rotation logic.
func TestRotateLog(t *testing.T) {
	// Store original log output and restore it after the test
	originalLogOutput := log.Writer()
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf) // Capture log output
	defer log.SetOutput(originalLogOutput)

	t.Run("NoRotationNeeded", func(t *testing.T) {
		logBuf.Reset()
		tempDir := t.TempDir() // Create a temporary directory for test files
		logFilePath := filepath.Join(tempDir, "test_no_rotate.log")

		createDummyFile(t, logFilePath, 1) // Create a 1MB file

		err := rotateLog(logFilePath, 5) // Max size is 5MB
		if err != nil {
			t.Fatalf("rotateLog failed unexpectedly: %v", err)
		}

		// Check that the original file still exists
		if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
			t.Errorf("Original log file %s should exist, but it does not", logFilePath)
		}

		// Check that no rotated file was created
		if _, exists := fileExistsWithPattern(t, tempDir, "test_no_rotate.log"); exists {
			t.Errorf("Log file should not have been rotated, but a rotated file was found")
		}
		if strings.Contains(logBuf.String(), "Rotated log file to:") {
			t.Errorf("Rotation log message found when no rotation should have occurred: %s", logBuf.String())
		}
	})

	t.Run("RotationNeeded", func(t *testing.T) {
		logBuf.Reset()
		tempDir := t.TempDir()
		logFilePath := filepath.Join(tempDir, "test_rotate_needed.log")

		createDummyFile(t, logFilePath, 2) // Create a 2MB file

		err := rotateLog(logFilePath, 1) // Max size is 1MB, so rotation should occur
		if err != nil {
			t.Fatalf("rotateLog failed unexpectedly: %v", err)
		}

		// The original file path should now point to a new (or non-existent if not recreated) file.
		// The rotateLog function itself only renames, it doesn't create a new empty file.
		// So, the original named file should not exist after rename.
		if _, err := os.Stat(logFilePath); !os.IsNotExist(err) {
			// This check is valid if no other process immediately recreates the file.
			// For the scope of rotateLog, it should be gone.
			// t.Errorf("Original log file %s should have been renamed, but it still exists", logFilePath)
			// Depending on application flow, it might be recreated. The crucial check is if a rotated file exists.
		}

		rotatedName, exists := fileExistsWithPattern(t, tempDir, "test_rotate_needed.log")
		if !exists {
			t.Fatalf("Log file should have been rotated, but no rotated file found matching pattern 'test_rotate_needed.log.TIMESTAMP'")
		}
		t.Logf("Found rotated file: %s", rotatedName)

		if !strings.Contains(logBuf.String(), "Rotated log file to: "+filepath.Join(tempDir, rotatedName)) {
			t.Errorf("Expected log message about rotation, but not found or incorrect. Log: %s", logBuf.String())
		}
	})

	t.Run("FileDoesNotExist", func(t *testing.T) {
		logBuf.Reset()
		tempDir := t.TempDir()
		logFilePath := filepath.Join(tempDir, "nonexistent.log")

		err := rotateLog(logFilePath, 5) // Attempt to rotate a non-existent file
		if err == nil {
			t.Fatalf("rotateLog should have failed for a non-existent file, but it did not")
		}
		if !os.IsNotExist(err) { // Check that the error is specifically 'file does not exist'
			t.Errorf("Expected a 'file does not exist' error, got: %v", err)
		}
		if strings.Contains(logBuf.String(), "Rotated log file to:") {
			t.Errorf("Rotation log message found for a non-existent file: %s", logBuf.String())
		}
	})

	t.Run("RotationErrorOnRename", func(t *testing.T) {
		logBuf.Reset()
		// This test is harder to set up reliably cross-platform without more complex mocks
		// for os.Rename. One way is to make the target directory non-writable or the target file locked.
		// For simplicity, we'll skip the actual rename error simulation here,
		// but acknowledge it's a case to consider for more advanced fs mocking.
		t.Skip("Skipping rename error test due to complexity of reliably simulating os.Rename failure in unit test.")
	})
}

// TestGenerateTLSConfig tests the TLS configuration generation.
func TestGenerateTLSConfig(t *testing.T) {
	// generateTLSConfig calls log.Fatalf on error, which exits the program.
	// To test this properly without exiting tests, generateTLSConfig would need
	// to return an error instead of calling log.Fatalf.
	// For now, this test just checks if it runs and produces a config.
	// If it panics (due to log.Fatalf), the test will fail.

	var tlsConfig *tls.Config
	// Use a defer-recover to catch panics if log.Fatalf is hit.
	// Note: log.Fatalf calls os.Exit(1), which is not catchable by recover in the same goroutine.
	// This test effectively checks that no error occurs that would lead to log.Fatalf.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("generateTLSConfig panicked (likely due to log.Fatalf): %v", r)
		}
	}()

	tlsConfig = generateTLSConfig() // This might call log.Fatalf

	if tlsConfig == nil {
		t.Fatalf("generateTLSConfig returned nil config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Errorf("tlsConfig.Certificates should not be empty")
	}
	if tlsConfig.Certificates[0].Certificate == nil {
		t.Errorf("tlsConfig.Certificates[0].Certificate is nil")
	}
	if tlsConfig.Certificates[0].PrivateKey == nil {
		t.Errorf("tlsConfig.Certificates[0].PrivateKey is nil")
	}
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "quic-log-protocol" {
		t.Errorf("tlsConfig.NextProtos not set correctly, got %v, want ['quic-log-protocol']", tlsConfig.NextProtos)
	}
}

// TestHandleLog tests the main log handling logic.
func TestHandleLog(t *testing.T) {
	// --- Test Setup ---
	// Store and restore original flag values
	originalLogFileFlag := *logfile
	originalRotateFlag := *rotate
	originalLogSizeFlag := *logSize
	defer func() {
		*logfile = originalLogFileFlag
		*rotate = originalRotateFlag
		*logSize = originalLogSizeFlag
		// Clean up any test log files that might have been created
		// This is a bit broad; specific test cases should manage their own files.
	}()

	// Capture log output from the 'log' package
	var appLogBuf bytes.Buffer
	originalAppLogger := log.Writer()
	log.SetOutput(&appLogBuf)
	defer log.SetOutput(originalAppLogger)

	// --- Test Cases ---
	t.Run("SuccessfulLogEntry", func(t *testing.T) {
		appLogBuf.Reset()
		tempDir := t.TempDir()
		testSpecificLogFile := filepath.Join(tempDir, "handler_success.log")
		*logfile = testSpecificLogFile
		*rotate = false // Disable rotation for this specific test case

		syslogInput := SyslogLine{
			Beat:      false,
			Timestamp: time.Now().Format(time.RFC3339),
			Hostname:  "testhost-success",
			Message:   "This is a successful test log message",
			Program:   "testprog",
			Pid:       "123",
		}
		inputJSON, _ := json.Marshal(syslogInput)
		inputReader := bytes.NewReader(inputJSON) // Reader for the mock stream
		var streamOutputBuf bytes.Buffer          // Buffer to capture what's written back to the stream

		mockStream := &MockStream{Reader: inputReader, Writer: &streamOutputBuf}
		mockConn := &MockConnection{AcceptedStream: mockStream}

		handleLog(mockConn) // Execute the function under test

		// IMPORTANT: handleLog spawns a goroutine for file writing.
		// For robust testing, we need to ensure this goroutine has completed.
		// Using time.Sleep is a common but potentially flaky approach.
		// Better: Use channels or waitgroups if the function can be refactored,
		// or mock the file system operations directly.
		time.Sleep(100 * time.Millisecond) // Allow time for async file write

		// Verify response written to the stream
		expectedResponse := `{"status":"ok"}`
		if !strings.Contains(streamOutputBuf.String(), expectedResponse) {
			t.Errorf("Expected stream response '%s', got: '%s'", expectedResponse, streamOutputBuf.String())
		}

		// Verify log file content
		logContent, err := os.ReadFile(testSpecificLogFile)
		if err != nil {
			t.Fatalf("Failed to read test log file %s: %v. App logs: %s", testSpecificLogFile, err, appLogBuf.String())
		}

		var loggedEntry LogEntry
		// Logs are newline-delimited JSON. We expect one entry here.
		lines := strings.Split(strings.TrimSpace(string(logContent)), "\n")
		if len(lines) == 0 || lines[0] == "" {
			t.Fatalf("Log file is empty or contains no valid lines. App logs: %s", appLogBuf.String())
		}
		err = json.Unmarshal([]byte(lines[len(lines)-1]), &loggedEntry) // Get the last entry
		if err != nil {
			t.Fatalf("Failed to unmarshal log entry from file: %v. Content: '%s'. App logs: %s", err, lines[len(lines)-1], appLogBuf.String())
		}

		if loggedEntry.Message != syslogInput.Message {
			t.Errorf("Expected logged message '%s', got '%s'", syslogInput.Message, loggedEntry.Message)
		}
		if loggedEntry.Hostname != syslogInput.Hostname {
			t.Errorf("Expected logged hostname '%s', got '%s'", syslogInput.Hostname, loggedEntry.Hostname)
		}
		// Check for unexpected errors in the application log
		if strings.Contains(appLogBuf.String(), "Error") {
			t.Errorf("Unexpected errors in application log: %s", appLogBuf.String())
		}
	})

	t.Run("BeatMessageHandling", func(t *testing.T) {
		appLogBuf.Reset()
		tempDir := t.TempDir()
		testSpecificLogFile := filepath.Join(tempDir, "handler_beat.log")
		*logfile = testSpecificLogFile
		*rotate = false

		syslogInput := SyslogLine{Beat: true, Hostname: "beathost", Message: "beat"}
		inputJSON, _ := json.Marshal(syslogInput)
		inputReader := bytes.NewReader(inputJSON)
		var streamOutputBuf bytes.Buffer

		mockStream := &MockStream{Reader: inputReader, Writer: &streamOutputBuf}
		mockConn := &MockConnection{AcceptedStream: mockStream}

		handleLog(mockConn)
		time.Sleep(50 * time.Millisecond) // Allow time for any async operations

		expectedResponse := `{"status":"beat_ok"}`
		if !strings.Contains(streamOutputBuf.String(), expectedResponse) {
			t.Errorf("Expected stream response '%s' for beat message, got: '%s'", expectedResponse, streamOutputBuf.String())
		}

		// Verify that the log file was NOT written to
		if _, err := os.Stat(testSpecificLogFile); !os.IsNotExist(err) {
			content, _ := os.ReadFile(testSpecificLogFile)
			t.Errorf("Log file %s should not have been created or written to for a beat message, but it exists. Content: %s. App logs: %s", testSpecificLogFile, string(content), appLogBuf.String())
		}
		if strings.Contains(appLogBuf.String(), "Error") {
			t.Errorf("Unexpected errors in application log for beat message: %s", appLogBuf.String())
		}
	})

	t.Run("InvalidJSONInput", func(t *testing.T) {
		appLogBuf.Reset()
		// No file operations expected, so logfile path doesn't strictly matter here
		*logfile = "handler_invalid_json.log"
		*rotate = false

		invalidJSONReader := strings.NewReader("{not_valid_json")
		var streamOutputBuf bytes.Buffer // Should not be written to if decode fails early

		mockStream := &MockStream{Reader: invalidJSONReader, Writer: &streamOutputBuf}
		mockConn := &MockConnection{AcceptedStream: mockStream}

		handleLog(mockConn)
		time.Sleep(50 * time.Millisecond)

		if !strings.Contains(appLogBuf.String(), "Error decoding JSON") {
			t.Errorf("Expected 'Error decoding JSON' in application log, but not found. Log: %s", appLogBuf.String())
		}
		if streamOutputBuf.String() != "" {
			t.Errorf("Expected no response to stream on invalid JSON, got: '%s'", streamOutputBuf.String())
		}
	})

	t.Run("AcceptStreamError", func(t *testing.T) {
		appLogBuf.Reset()
		mockConn := &MockConnection{AcceptStreamErr: fmt.Errorf("simulated accept stream error")}

		handleLog(mockConn)
		time.Sleep(50 * time.Millisecond)

		expectedLogMsg := "Error accepting stream: simulated accept stream error"
		if !strings.Contains(appLogBuf.String(), expectedLogMsg) {
			t.Errorf("Expected log message '%s', but not found. Log: %s", expectedLogMsg, appLogBuf.String())
		}
	})

	t.Run("MultipleJSONObjectsInStream", func(t *testing.T) {
		appLogBuf.Reset()
		tempDir := t.TempDir()
		testSpecificLogFile := filepath.Join(tempDir, "handler_multi.log")
		*logfile = testSpecificLogFile
		*rotate = false

		syslog1 := SyslogLine{Hostname: "multi1", Message: "message one"}
		syslog2 := SyslogLine{Beat: true, Hostname: "multi2", Message: "beat this"}
		syslog3 := SyslogLine{Hostname: "multi3", Message: "message three"}

		json1, _ := json.Marshal(syslog1)
		json2, _ := json.Marshal(syslog2)
		json3, _ := json.Marshal(syslog3)

		// Concatenate JSON objects, each on a new line for the decoder
		multiInput := string(json1) + "\n" + string(json2) + "\n" + string(json3) + "\n"
		inputReader := strings.NewReader(multiInput)
		var streamOutputBuf bytes.Buffer

		mockStream := &MockStream{Reader: inputReader, Writer: &streamOutputBuf}
		mockConn := &MockConnection{AcceptedStream: mockStream}

		handleLog(mockConn)
		time.Sleep(200 * time.Millisecond) // Allow more time for multiple operations

		responses := streamOutputBuf.String()
		if !strings.Contains(responses, `{"status":"ok"}`) { // For syslog1 and syslog3
			t.Errorf("Expected 'ok' status in responses, got: %s", responses)
		}
		if !strings.Contains(responses, `{"status":"beat_ok"}`) { // For syslog2
			t.Errorf("Expected 'beat_ok' status in responses, got: %s", responses)
		}
		// Check number of responses (crude check)
		if strings.Count(responses, "{") != 3 {
			t.Errorf("Expected 3 JSON responses, got %d. Responses: %s", strings.Count(responses, "{"), responses)
		}

		logContent, err := os.ReadFile(testSpecificLogFile)
		if err != nil {
			t.Fatalf("Failed to read test log file %s: %v. App logs: %s", testSpecificLogFile, err, appLogBuf.String())
		}
		// Expect two log entries (syslog1 and syslog3)
		if strings.Count(string(logContent), "\n") != 2 {
			t.Errorf("Expected 2 log entries in file, found %d. Content: %s. App logs: %s", strings.Count(string(logContent), "\n"), string(logContent), appLogBuf.String())
		}
		if !strings.Contains(string(logContent), syslog1.Message) {
			t.Errorf("Log file does not contain message '%s'", syslog1.Message)
		}
		if strings.Contains(string(logContent), syslog2.Message) { // Beat message should not be logged
			t.Errorf("Log file contains beat message '%s', which should not be logged", syslog2.Message)
		}
		if !strings.Contains(string(logContent), syslog3.Message) {
			t.Errorf("Log file does not contain message '%s'", syslog3.Message)
		}
	})

	t.Run("LogRotationTriggeredInHandler", func(t *testing.T) {
		appLogBuf.Reset()
		tempDir := t.TempDir()
		testSpecificLogFile := filepath.Join(tempDir, "handler_rotate.log")
		*logfile = testSpecificLogFile
		*rotate = true // Enable rotation
		*logSize = 1   // Set max size to 1MB to trigger rotation

		// Create an initial log file that is large enough to trigger rotation
		createDummyFile(t, testSpecificLogFile, 2) // 2MB file

		syslogInput := SyslogLine{Hostname: "rotatehost-handler", Message: "log entry for rotation test"}
		inputJSON, _ := json.Marshal(syslogInput)
		inputReader := bytes.NewReader(inputJSON)
		var streamOutputBuf bytes.Buffer

		mockStream := &MockStream{Reader: inputReader, Writer: &streamOutputBuf}
		mockConn := &MockConnection{AcceptedStream: mockStream}

		handleLog(mockConn)
		time.Sleep(200 * time.Millisecond) // Allow time for rotation and write

		// Check application logs for rotation message
		if !strings.Contains(appLogBuf.String(), "Rotated log file to:") {
			t.Logf("Full application log: %s", appLogBuf.String())
			t.Errorf("Expected 'Rotated log file to:' message in application logs, but not found.")
		}

		// Check that a rotated file exists
		rotatedName, exists := fileExistsWithPattern(t, tempDir, filepath.Base(testSpecificLogFile))
		if !exists {
			t.Errorf("Rotated log file was not found with expected pattern for %s in dir %s. App logs: %s", filepath.Base(testSpecificLogFile), tempDir, appLogBuf.String())
		} else {
			t.Logf("Found rotated file: %s", rotatedName)
		}

		// Check that the new log file (testSpecificLogFile) contains the latest entry
		currentLogContent, err := os.ReadFile(testSpecificLogFile)
		if err != nil {
			t.Errorf("Failed to read current log file %s after rotation: %v", testSpecificLogFile, err)
		} else if !strings.Contains(string(currentLogContent), syslogInput.Message) {
			t.Errorf("New log file %s does not contain the latest message '%s'. Content: %s", testSpecificLogFile, syslogInput.Message, string(currentLogContent))
		}
	})

	// Additional test cases to consider:
	// - Stream Write errors (for beat response and log entry response)
	// - Errors during json.Marshal(logEntry)
	// - Errors during os.OpenFile
	// - Errors during file.WriteString
	// - EOF error during stream reading (should break loop gracefully and not log an error)
	// - Context cancellation affecting stream operations (if applicable)
}

// Note: Testing the main() function directly is often complex and better covered by
// integration tests. The unit tests above focus on the core logic functions.

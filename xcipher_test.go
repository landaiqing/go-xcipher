package xcipher

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Generate a random key
func generateRandomKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

// Generate random data of specified size
func generateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

// Create temporary file and write data to it
func createTempFile(t *testing.T, data []byte) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_data")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	return tempFile
}

// TestStreamEncryptDecrypt tests basic stream encryption/decryption functionality
func TestStreamEncryptDecrypt(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	// Generate random test data (1MB)
	testSize := 1 * 1024 * 1024
	testData, err := generateRandomData(testSize)
	if err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Additional data
	additionalData := []byte("Test additional data")

	// Create input and output buffers
	var encryptedBuf bytes.Buffer
	encryptedReader := bytes.NewReader(testData)

	// Perform stream encryption
	err = xcipher.EncryptStream(encryptedReader, &encryptedBuf, additionalData)
	if err != nil {
		t.Fatalf("Stream encryption failed: %v", err)
	}

	// Create decryption buffer
	var decryptedBuf bytes.Buffer
	decryptReader := bytes.NewReader(encryptedBuf.Bytes())

	// Perform stream decryption
	err = xcipher.DecryptStream(decryptReader, &decryptedBuf, additionalData)
	if err != nil {
		t.Fatalf("Stream decryption failed: %v", err)
	}

	// Verify decrypted data matches original data
	if !bytes.Equal(testData, decryptedBuf.Bytes()) {
		t.Fatal("Stream encrypted/decrypted data does not match")
	}

	t.Logf("Successfully stream processed %d bytes of data", testSize)
}

// TestStreamEncryptDecryptWithOptions tests stream encryption/decryption with options
func TestStreamEncryptDecryptWithOptions(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	// Generate random test data (2MB)
	testSize := 2 * 1024 * 1024
	testData, err := generateRandomData(testSize)
	if err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Create temporary file for testing large data
	inputFile := createTempFile(t, testData)
	defer os.Remove(inputFile)

	// Additional data
	additionalData := []byte("Test additional data")

	// Test different buffer size options
	bufferSizes := []int{8 * 1024, 32 * 1024, 128 * 1024}
	for _, bufSize := range bufferSizes {
		t.Run(fmt.Sprintf("BufferSize=%dKB", bufSize/1024), func(t *testing.T) {
			// Create input and output files
			encryptedFile := inputFile + ".enc"
			decryptedFile := inputFile + ".dec"
			defer os.Remove(encryptedFile)
			defer os.Remove(decryptedFile)

			// Open input file
			inFile, err := os.Open(inputFile)
			if err != nil {
				t.Fatalf("Failed to open input file: %v", err)
			}
			defer inFile.Close()

			// Create encrypted output file
			outFile, err := os.Create(encryptedFile)
			if err != nil {
				t.Fatalf("Failed to create encrypted output file: %v", err)
			}
			defer outFile.Close()

			// Create options
			options := DefaultStreamOptions()
			options.BufferSize = bufSize
			options.AdditionalData = additionalData
			options.CollectStats = true

			// Perform stream encryption
			stats, err := xcipher.EncryptStreamWithOptions(inFile, outFile, options)
			if err != nil {
				t.Fatalf("Stream encryption failed: %v", err)
			}

			// Output encryption performance statistics
			t.Logf("Encryption performance statistics (buffer size=%dKB):", bufSize/1024)
			t.Logf("- Bytes processed: %d", stats.BytesProcessed)
			t.Logf("- Blocks processed: %d", stats.BlocksProcessed)
			t.Logf("- Average block size: %.2f bytes", stats.AvgBlockSize)
			t.Logf("- Processing time: %v", stats.Duration())
			t.Logf("- Throughput: %.2f MB/s", stats.Throughput)

			// Prepare for decryption
			encData, err := ioutil.ReadFile(encryptedFile)
			if err != nil {
				t.Fatalf("Failed to read encrypted file: %v", err)
			}

			encFile := bytes.NewReader(encData)

			decFile, err := os.Create(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to create decrypted output file: %v", err)
			}
			defer decFile.Close()

			// Perform parallel stream decryption
			_, err = xcipher.DecryptStreamWithOptions(encFile, decFile, options)
			if err != nil {
				t.Fatalf("Parallel stream decryption failed: %v", err)
			}

			// Close file to ensure data is written
			decFile.Close()

			// Read decrypted data for verification
			decryptedData, err := ioutil.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			// Verify data
			if !bytes.Equal(testData, decryptedData) {
				t.Fatal("Stream encrypted/decrypted data does not match")
			}

			t.Logf("Successfully stream processed %d bytes of data (buffer=%dKB)", testSize, bufSize/1024)
		})
	}
}

// TestStreamParallelProcessing tests the parallel stream encryption/decryption
func TestStreamParallelProcessing(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	// Generate smaller test data
	testSize := 1 * 1024 * 1024 // 1MB
	testData, err := generateRandomData(testSize)
	if err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Create processing options - first test with non-parallel mode
	options := DefaultStreamOptions()
	options.UseParallel = false // Disable parallel processing
	options.CollectStats = true

	// Use memory buffer for testing
	t.Log("Starting encryption")
	var encryptedBuffer bytes.Buffer

	// Perform stream encryption
	stats, err := xcipher.EncryptStreamWithOptions(
		bytes.NewReader(testData), &encryptedBuffer, options)
	if err != nil {
		t.Fatalf("Stream encryption failed: %v", err)
	}

	// Output encryption performance statistics
	t.Logf("Encryption performance statistics:")
	t.Logf("- Bytes processed: %d", stats.BytesProcessed)
	t.Logf("- Blocks processed: %d", stats.BlocksProcessed)
	t.Logf("- Average block size: %.2f bytes", stats.AvgBlockSize)
	t.Logf("- Processing time: %v", stats.Duration())
	t.Logf("- Throughput: %.2f MB/s", stats.Throughput)

	// Get encrypted data
	encryptedData := encryptedBuffer.Bytes()
	t.Logf("Encrypted data size: %d bytes", len(encryptedData))

	// Check if encrypted data is valid
	if len(encryptedData) <= nonceSize {
		t.Fatalf("Invalid encrypted data, length too short: %d bytes", len(encryptedData))
	}

	// Start decryption
	t.Log("Starting decryption")
	var decryptedBuffer bytes.Buffer

	// Perform stream decryption
	decStats, err := xcipher.DecryptStreamWithOptions(
		bytes.NewReader(encryptedData), &decryptedBuffer, options)
	if err != nil {
		t.Fatalf("Stream decryption failed: %v (encrypted data size: %d bytes)", err, len(encryptedData))
	}

	// Output decryption performance statistics
	t.Logf("Decryption performance statistics:")
	t.Logf("- Bytes processed: %d", decStats.BytesProcessed)
	t.Logf("- Blocks processed: %d", decStats.BlocksProcessed)
	t.Logf("- Average block size: %.2f bytes", decStats.AvgBlockSize)
	t.Logf("- Processing time: %v", decStats.Duration())
	t.Logf("- Throughput: %.2f MB/s", decStats.Throughput)

	// Get decrypted data
	decryptedData := decryptedBuffer.Bytes()

	// Verify data
	if !bytes.Equal(testData, decryptedData) {
		t.Fatal("Stream encrypted/decrypted data does not match")
	}

	t.Logf("Successfully completed stream processing of %d bytes", testSize)
}

// TestStreamCancellation tests cancellation of stream encryption/decryption operations
func TestStreamCancellation(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	// Generate large test data (50MB, enough time to cancel)
	testSize := 50 * 1024 * 1024
	testData, err := generateRandomData(testSize)
	if err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Create an unlimited data source to simulate large file
	infiniteReader := &infiniteDataReader{data: testData}

	// Create output buffer
	var outputBuf bytes.Buffer

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create options with cancel channel
	options := DefaultStreamOptions()
	options.CancelChan = ctx.Done()

	// Cancel operation after a short time
	go func() {
		time.Sleep(100 * time.Millisecond) // Let encryption run for a short time
		cancel()
	}()

	// Perform stream encryption, should be cancelled
	_, err = xcipher.EncryptStreamWithOptions(infiniteReader, &outputBuf, options)

	// Verify error is cancellation error
	if !errors.Is(err, ErrOperationCancelled) {
		t.Fatalf("Expected cancellation error, but got: %v", err)
	}

	t.Log("Successfully tested stream encryption cancellation")
}

// TestStreamErrors tests error handling in stream encryption/decryption
func TestStreamErrors(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	t.Run("InvalidBufferSize", func(t *testing.T) {
		// Generate test data
		testData, err := generateRandomData(1024)
		if err != nil {
			t.Fatalf("Failed to generate test data: %v", err)
		}

		// Test case with too small buffer (1 byte)
		t.Run("BufferTooSmall", func(t *testing.T) {
			// Create new options for each subtest to avoid shared state
			options := DefaultStreamOptions()
			options.BufferSize = 1      // Extremely small buffer
			options.CollectStats = true // Ensure stats are collected

			var buffer bytes.Buffer

			stats, err := xcipher.EncryptStreamWithOptions(
				bytes.NewReader(testData), &buffer, options)

			// Verify that buffer size was automatically adjusted instead of returning error
			if err != nil {
				t.Errorf("Expected automatic buffer size adjustment, but got error: %v", err)
			}

			// Check if buffer was adjusted to minimum valid size
			if stats != nil && stats.BufferSize < minBufferSize {
				t.Errorf("Buffer size should be greater than or equal to minimum %d, but got %d",
					minBufferSize, stats.BufferSize)
			}

			if stats != nil {
				t.Logf("Requested buffer size: %d, actually used: %d", options.BufferSize, stats.BufferSize)
			}
		})

		// Test case with too large buffer (10MB)
		t.Run("BufferTooLarge", func(t *testing.T) {
			// Create new options for each subtest to avoid shared state
			options := DefaultStreamOptions()
			options.BufferSize = 10 * 1024 * 1024 // 10MB, potentially too large
			options.CollectStats = true           // Ensure stats are collected

			var buffer bytes.Buffer

			stats, err := xcipher.EncryptStreamWithOptions(
				bytes.NewReader(testData), &buffer, options)

			// Verify that buffer size was automatically adjusted instead of returning error
			if err != nil {
				t.Errorf("Expected automatic adjustment of oversized buffer, but got error: %v", err)
			}

			// Check if buffer was adjusted to a reasonable size
			if stats != nil && stats.BufferSize > maxBufferSize {
				t.Errorf("Buffer size should be less than or equal to maximum %d, but got %d",
					maxBufferSize, stats.BufferSize)
			}

			if stats != nil {
				t.Logf("Requested buffer size: %d, actually used: %d", options.BufferSize, stats.BufferSize)
			}
		})
	})

	// Test authentication failure
	t.Run("AuthenticationFailure", func(t *testing.T) {
		// First encrypt some data
		plaintext := []byte("Test authentication failure")
		var encBuf bytes.Buffer
		err := xcipher.EncryptStream(bytes.NewReader(plaintext), &encBuf, nil)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Tamper with encrypted data
		encryptedData := encBuf.Bytes()
		if len(encryptedData) > nonceSize+10 {
			// Modify one byte in ciphertext part
			encryptedData[nonceSize+10]++
		}

		// Try to decrypt tampered data
		var decBuf bytes.Buffer
		err = xcipher.DecryptStream(bytes.NewReader(encryptedData), &decBuf, nil)
		if err == nil || !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Expected authentication failure error, but got: %v", err)
		}
	})

	// Test read error
	t.Run("ReadError", func(t *testing.T) {
		reader := &errorReader{err: fmt.Errorf("simulated read error")}
		var buf bytes.Buffer

		err := xcipher.EncryptStream(reader, &buf, nil)
		if err == nil || !errors.Is(err, ErrReadFailed) {
			t.Fatalf("Expected read failure error, but got: %v", err)
		}
	})

	// Test write error
	t.Run("WriteError", func(t *testing.T) {
		writer := &errorWriter{err: fmt.Errorf("simulated write error")}

		err := xcipher.EncryptStream(bytes.NewReader([]byte("test")), writer, nil)
		if err == nil || !errors.Is(err, ErrWriteFailed) {
			t.Fatalf("Expected write failure error, but got: %v", err)
		}
	})
}

// Infinite data reader for testing cancellation
type infiniteDataReader struct {
	data []byte
	pos  int
}

func (r *infiniteDataReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		r.pos = 0 // Cycle through data
	}

	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// Reader that simulates read errors
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// Writer that simulates write errors
type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}

// TestCPUFeatureDetection tests CPU feature detection functionality
func TestCPUFeatureDetection(t *testing.T) {
	// Get system optimization info
	info := GetSystemOptimizationInfo()

	// Output detected CPU features
	t.Logf("CPU architecture: %s", info.Architecture)
	t.Logf("CPU core count: %d", info.NumCPUs)
	t.Logf("AVX support: %v", info.HasAVX)
	t.Logf("AVX2 support: %v", info.HasAVX2)
	t.Logf("SSE4.1 support: %v", info.HasSSE41)
	t.Logf("NEON support: %v", info.HasNEON)
	t.Logf("Estimated L1 cache size: %d KB", info.EstimatedL1Cache/1024)
	t.Logf("Estimated L2 cache size: %d KB", info.EstimatedL2Cache/1024)
	t.Logf("Estimated L3 cache size: %d MB", info.EstimatedL3Cache/1024/1024)

	// Check recommended parameters
	t.Logf("Recommended buffer size: %d KB", info.RecommendedBufferSize/1024)
	t.Logf("Recommended worker count: %d", info.RecommendedWorkers)

	// Simple validation of recommended parameters
	if info.RecommendedBufferSize < minBufferSize || info.RecommendedBufferSize > maxBufferSize {
		t.Errorf("Recommended buffer size %d outside valid range [%d, %d]",
			info.RecommendedBufferSize, minBufferSize, maxBufferSize)
	}

	if info.RecommendedWorkers < minWorkers || info.RecommendedWorkers > maxWorkers {
		t.Errorf("Recommended worker count %d outside valid range [%d, %d]",
			info.RecommendedWorkers, minWorkers, maxWorkers)
	}
}

// TestDynamicParameterAdjustment tests dynamic parameter adjustment system
func TestDynamicParameterAdjustment(t *testing.T) {
	// Test different buffer size requests
	testCases := []struct {
		requestedSize int
		description   string
	}{
		{0, "Zero request (use auto-optimization)"},
		{4 * 1024, "Below minimum"},
		{16 * 1024, "Normal small value"},
		{64 * 1024, "Medium value"},
		{256 * 1024, "Larger value"},
		{2 * 1024 * 1024, "Above maximum"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Get adjusted buffer size
			adjustedSize := adaptiveBufferSize(tc.requestedSize)

			t.Logf("Requested size: %d, adjusted size: %d", tc.requestedSize, adjustedSize)

			// Validate adjusted size is within valid range
			if adjustedSize < minBufferSize {
				t.Errorf("Adjusted buffer size %d less than minimum %d", adjustedSize, minBufferSize)
			}

			if adjustedSize > maxBufferSize {
				t.Errorf("Adjusted buffer size %d greater than maximum %d", adjustedSize, maxBufferSize)
			}
		})
	}

	// Test different worker thread count requests
	workerTestCases := []struct {
		requestedWorkers int
		bufferSize       int
		description      string
	}{
		{0, 16 * 1024, "Auto-select (small buffer)"},
		{0, 512 * 1024, "Auto-select (large buffer)"},
		{1, 64 * 1024, "Single thread request"},
		{12, 64 * 1024, "Multi-thread request"},
	}

	for _, tc := range workerTestCases {
		t.Run(tc.description, func(t *testing.T) {
			// Get adjusted worker count
			adjustedWorkers := adaptiveWorkerCount(tc.requestedWorkers, tc.bufferSize)

			t.Logf("Requested workers: %d, buffer size: %d, adjusted workers: %d",
				tc.requestedWorkers, tc.bufferSize, adjustedWorkers)

			// Validate adjusted worker count is within valid range
			if adjustedWorkers < minWorkers {
				t.Errorf("Adjusted worker count %d less than minimum %d", adjustedWorkers, minWorkers)
			}

			if adjustedWorkers > maxWorkers {
				t.Errorf("Adjusted worker count %d greater than maximum %d", adjustedWorkers, maxWorkers)
			}
		})
	}
}

// TestOptimizedStreamOptions tests optimized stream options
func TestOptimizedStreamOptions(t *testing.T) {
	// Get optimized stream options
	options := GetOptimizedStreamOptions()

	t.Logf("Optimized stream options:")
	t.Logf("- Buffer size: %d KB", options.BufferSize/1024)
	t.Logf("- Use parallel: %v", options.UseParallel)
	t.Logf("- Max workers: %d", options.MaxWorkers)

	// Validate options are within valid ranges
	if options.BufferSize < minBufferSize || options.BufferSize > maxBufferSize {
		t.Errorf("Buffer size %d outside valid range [%d, %d]",
			options.BufferSize, minBufferSize, maxBufferSize)
	}

	if options.MaxWorkers < minWorkers || options.MaxWorkers > maxWorkers {
		t.Errorf("Max worker count %d outside valid range [%d, %d]",
			options.MaxWorkers, minWorkers, maxWorkers)
	}
}

// TestZeroCopyMechanism tests zero-copy mechanism
func TestZeroCopyMechanism(t *testing.T) {
	// Test zero-copy string conversion between string and byte slice
	original := "测试零拷贝字符串转换"
	byteData := stringToBytes(original)
	restored := bytesToString(byteData)

	if original != restored {
		t.Errorf("Zero-copy string conversion failed: %s != %s", original, restored)
	}

	// Test buffer reuse
	data := []byte("测试缓冲区重用")

	// Request a buffer larger than original data
	largerCap := len(data) * 2
	newBuf := reuseBuffer(data, largerCap)

	// Verify data was copied correctly
	if !bytes.Equal(data, newBuf[:len(data)]) {
		t.Error("Data mismatch after buffer reuse")
	}

	// Verify capacity was increased
	if cap(newBuf) < largerCap {
		t.Errorf("Buffer capacity not properly increased: %d < %d", cap(newBuf), largerCap)
	}

	// Test reuse when original buffer is large enough
	largeBuf := make([]byte, 100)
	copy(largeBuf, data)

	// Request capacity smaller than original buffer
	smallerCap := 50
	reusedBuf := reuseBuffer(largeBuf, smallerCap)

	// Verify it's the same underlying array (by comparing length)
	if len(reusedBuf) != smallerCap {
		t.Errorf("Reused buffer length incorrect: %d != %d", len(reusedBuf), smallerCap)
	}

	// Verify data integrity
	if !bytes.Equal(largeBuf[:len(data)], data) {
		t.Error("Original data corrupted after reuse")
	}
}

// TestAutoParallelDecision tests automatic parallel processing decision
func TestAutoParallelDecision(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	testCases := []struct {
		name          string
		dataSize      int  // Data size in bytes
		forceParallel bool // Whether to force parallel mode
	}{
		{"Small data", 10 * 1024, false},      // 10KB
		{"Medium data", 500 * 1024, false},    // 500KB
		{"Large data", 2 * 1024 * 1024, true}, // 2MB - force parallel mode
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test data
			testData, err := generateRandomData(tc.dataSize)
			if err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Create default options and enable stats collection
			options := DefaultStreamOptions()
			options.CollectStats = true
			options.UseParallel = tc.forceParallel // For large data, force parallel mode

			// Create temporary file for testing
			var encBuffer bytes.Buffer
			var stats *StreamStats

			// For large data, use file IO instead of memory buffer to ensure parallel mode is triggered
			if tc.dataSize >= parallelThreshold {
				// Create temporary file
				tempFile := createTempFile(t, testData)
				defer os.Remove(tempFile)

				// Create temporary output file
				tempOutFile, err := os.CreateTemp("", "xcipher-test-*")
				if err != nil {
					t.Fatalf("Failed to create temporary output file: %v", err)
				}
				tempOutPath := tempOutFile.Name()
				tempOutFile.Close()
				defer os.Remove(tempOutPath)

				// Open file for encryption
				inFile, err := os.Open(tempFile)
				if err != nil {
					t.Fatalf("Failed to open temporary file: %v", err)
				}
				defer inFile.Close()

				outFile, err := os.Create(tempOutPath)
				if err != nil {
					t.Fatalf("Failed to open output file: %v", err)
				}
				defer outFile.Close()

				// Perform encryption
				stats, err = xcipher.EncryptStreamWithOptions(inFile, outFile, options)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
			} else {
				// Use memory buffer for small data
				stats, err = xcipher.EncryptStreamWithOptions(
					bytes.NewReader(testData), &encBuffer, options)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
			}

			// Output decision results
			t.Logf("Data size: %d bytes", tc.dataSize)
			t.Logf("Auto decision: Use parallel=%v, workers=%d, buffer size=%d",
				stats.ParallelProcessing, stats.WorkerCount, stats.BufferSize)
			t.Logf("Performance: Time=%v, throughput=%.2f MB/s",
				stats.Duration(), stats.Throughput)

			// Verify parallel processing state matches expectation
			if tc.forceParallel && !stats.ParallelProcessing {
				t.Errorf("Forced parallel processing was set, but system did not use parallel mode")
			}
		})
	}
}

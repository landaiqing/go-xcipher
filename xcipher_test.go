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
	if err := ioutil.WriteFile(tempFile, data, 0644); err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	return tempFile
}

func TestEncryptDecryptImageWithLog(t *testing.T) {
	startTotal := time.Now()
	defer func() {
		t.Logf("Total time: %v", time.Since(startTotal))
	}()

	// Read original image
	imagePath := "test.jpg"
	start := time.Now()
	imageData, err := ioutil.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("Failed to read image: %v", err)
	}
	t.Logf("[1/7] Read image %s (%.2fKB) time: %v",
		imagePath, float64(len(imageData))/1024, time.Since(start))

	// Generate encryption key
	start = time.Now()
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("[2/7] Generated %d bytes key time: %v", len(key), time.Since(start))

	// Initialize cipher
	start = time.Now()
	xcipher := NewXCipher(key)
	t.Logf("[3/7] Initialized cipher time: %v", time.Since(start))

	// Perform encryption
	additionalData := []byte("Image metadata")
	start = time.Now()
	ciphertext, err := xcipher.Encrypt(imageData, additionalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	t.Logf("[4/7] Encrypted data (input: %d bytes, output: %d bytes) time: %v",
		len(imageData), len(ciphertext), time.Since(start))

	// Save encrypted file
	cipherPath := "encrypted.jpg"
	start = time.Now()
	if err := ioutil.WriteFile(cipherPath, ciphertext, 0644); err != nil {
		t.Fatalf("Failed to save encrypted file: %v", err)
	}
	t.Logf("[5/7] Wrote encrypted file %s time: %v", cipherPath, time.Since(start))

	// Perform decryption
	start = time.Now()
	decryptedData, err := xcipher.Decrypt(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	decryptDuration := time.Since(start)
	t.Logf("[6/7] Decrypted data (input: %d bytes, output: %d bytes) time: %v (%.2f MB/s)",
		len(ciphertext), len(decryptedData), decryptDuration,
		float64(len(ciphertext))/1e6/decryptDuration.Seconds())

	// Verify data integrity
	start = time.Now()
	if !bytes.Equal(imageData, decryptedData) {
		t.Fatal("Decrypted data verification failed")
	}
	t.Logf("[7/7] Data verification time: %v", time.Since(start))

	// Save decrypted image
	decryptedPath := "decrypted.jpg"
	start = time.Now()
	if err := ioutil.WriteFile(decryptedPath, decryptedData, 0644); err != nil {
		t.Fatalf("Failed to save decrypted image: %v", err)
	}
	t.Logf("Saved decrypted image %s (%.2fKB) time: %v",
		decryptedPath, float64(len(decryptedData))/1024, time.Since(start))
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
			encFile, err := os.Open(encryptedFile)
			if err != nil {
				t.Fatalf("Failed to open encrypted file: %v", err)
			}
			defer encFile.Close()

			decFile, err := os.Create(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to create decrypted output file: %v", err)
			}
			defer decFile.Close()

			// Perform stream decryption
			_, err = xcipher.DecryptStreamWithOptions(encFile, decFile, options)
			if err != nil {
				t.Fatalf("Stream decryption failed: %v", err)
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

// TestStreamParallelProcessing tests parallel stream encryption/decryption
func TestStreamParallelProcessing(t *testing.T) {
	// Generate random key
	key, err := generateRandomKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Initialize cipher
	xcipher := NewXCipher(key)

	// Generate large random test data (10MB, enough to trigger parallel processing)
	testSize := 10 * 1024 * 1024
	testData, err := generateRandomData(testSize)
	if err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Create temporary file
	inputFile := createTempFile(t, testData)
	defer os.Remove(inputFile)
	encryptedFile := inputFile + ".parallel.enc"
	decryptedFile := inputFile + ".parallel.dec"
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

	// Create parallel processing options
	options := DefaultStreamOptions()
	options.UseParallel = true
	options.MaxWorkers = 4 // Use 4 worker threads
	options.CollectStats = true

	// Perform parallel stream encryption
	stats, err := xcipher.EncryptStreamWithOptions(inFile, outFile, options)
	if err != nil {
		t.Fatalf("Parallel stream encryption failed: %v", err)
	}

	// Ensure file is written completely
	outFile.Close()

	// Output encryption performance statistics
	t.Logf("Parallel encryption performance statistics:")
	t.Logf("- Bytes processed: %d", stats.BytesProcessed)
	t.Logf("- Blocks processed: %d", stats.BlocksProcessed)
	t.Logf("- Average block size: %.2f bytes", stats.AvgBlockSize)
	t.Logf("- Processing time: %v", stats.Duration())
	t.Logf("- Throughput: %.2f MB/s", stats.Throughput)
	t.Logf("- Worker threads: %d", stats.WorkerCount)

	// Prepare for decryption
	encFile, err := os.Open(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to open encrypted file: %v", err)
	}
	defer encFile.Close()

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
		t.Fatal("Parallel stream encrypted/decrypted data does not match")
	}

	t.Logf("Successfully parallel stream processed %d bytes of data", testSize)
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

	// Test invalid buffer size
	t.Run("InvalidBufferSize", func(t *testing.T) {
		var buf bytes.Buffer
		options := DefaultStreamOptions()
		options.BufferSize = 1 // Too small buffer

		_, err := xcipher.EncryptStreamWithOptions(bytes.NewReader([]byte("test")), &buf, options)
		if err == nil || !errors.Is(err, ErrBufferSizeTooSmall) {
			t.Fatalf("Expected buffer too small error, but got: %v", err)
		}

		options.BufferSize = 10 * 1024 * 1024 // Too large buffer
		_, err = xcipher.EncryptStreamWithOptions(bytes.NewReader([]byte("test")), &buf, options)
		if err == nil || !errors.Is(err, ErrBufferSizeTooLarge) {
			t.Fatalf("Expected buffer too large error, but got: %v", err)
		}
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

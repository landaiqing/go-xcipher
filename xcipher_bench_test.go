package xcipher

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

// genRandomDataForBench generates random data of specified size (for benchmarks only)
func genRandomDataForBench(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return data
}

// Create temporary file
func createBenchTempFile(b *testing.B, data []byte) string {
	tempFile, err := os.CreateTemp("", "xcipher-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temporary file: %v", err)
	}

	if _, err := tempFile.Write(data); err != nil {
		b.Fatalf("Failed to write to temporary file: %v", err)
	}

	tempFile.Close()
	return tempFile.Name()
}

// BenchmarkEncrypt tests encryption performance for different data sizes
func BenchmarkEncrypt(b *testing.B) {
	sizes := []int{
		1 * 1024,        // 1KB
		16 * 1024,       // 16KB
		64 * 1024,       // 64KB
		256 * 1024,      // 256KB
		1 * 1024 * 1024, // 1MB
		4 * 1024 * 1024, // 4MB
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)
			b.ResetTimer()

			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecrypt tests decryption performance for different data sizes
func BenchmarkDecrypt(b *testing.B) {
	sizes := []int{
		1 * 1024,        // 1KB
		16 * 1024,       // 16KB
		64 * 1024,       // 64KB
		256 * 1024,      // 256KB
		1 * 1024 * 1024, // 1MB
		4 * 1024 * 1024, // 4MB
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)
			encrypted, err := cipher.Encrypt(data, nil)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := cipher.Decrypt(encrypted, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncryptLarge benchmark large data encryption performance
func BenchmarkEncryptLarge(b *testing.B) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	x := NewXCipher(key)
	plaintext := make([]byte, 1<<20) // 1MB data
	additionalData := []byte("test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = x.Encrypt(plaintext, additionalData)
	}
}

// BenchmarkDecryptLarge benchmark large data decryption performance
func BenchmarkDecryptLarge(b *testing.B) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	x := NewXCipher(key)
	plaintext := make([]byte, 1<<20) // 1MB data
	additionalData := []byte("test")
	ciphertext, _ := x.Encrypt(plaintext, additionalData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = x.Decrypt(ciphertext, additionalData)
	}
}

// Stream encryption/decryption benchmarks

// BenchmarkStreamEncrypt tests stream encryption performance with different data sizes
func BenchmarkStreamEncrypt(b *testing.B) {
	// Test different data sizes
	sizes := []int{
		1 << 10, // 1KB
		1 << 14, // 16KB
		1 << 16, // 64KB
		1 << 18, // 256KB
		1 << 20, // 1MB
		1 << 22, // 4MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%dKB", size/1024), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)

			plaintext := genRandomDataForBench(size)
			additionalData := []byte("stream-test")

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(plaintext)
				writer := ioutil.Discard
				b.StartTimer()

				_ = x.EncryptStream(reader, writer, additionalData)
			}
		})
	}
}

// BenchmarkStreamDecrypt tests stream decryption performance with different data sizes
func BenchmarkStreamDecrypt(b *testing.B) {
	// Test different data sizes
	sizes := []int{
		1 << 10, // 1KB
		1 << 14, // 16KB
		1 << 16, // 64KB
		1 << 18, // 256KB
		1 << 20, // 1MB
		1 << 22, // 4MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%dKB", size/1024), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)

			plaintext := genRandomDataForBench(size)
			additionalData := []byte("stream-test")

			// Encrypt data first
			var encBuf bytes.Buffer
			_ = x.EncryptStream(bytes.NewReader(plaintext), &encBuf, additionalData)
			encData := encBuf.Bytes()

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(encData)
				writer := ioutil.Discard
				b.StartTimer()

				_ = x.DecryptStream(reader, writer, additionalData)
			}
		})
	}
}

// BenchmarkStreamParallelVsSerial compares parallel and serial stream encryption performance
func BenchmarkStreamParallelVsSerial(b *testing.B) {
	// Use larger data to test parallel advantage (10MB)
	dataSize := 10 * 1024 * 1024

	benchCases := []struct {
		name        string
		useParallel bool
		bufferSize  int
	}{
		{"Serial_Default", false, streamBufferSize},
		{"Serial_SmallBuffer", false, 16 * 1024},
		{"Serial_LargeBuffer", false, 256 * 1024},
		{"Parallel_Default", true, streamBufferSize},
		{"Parallel_SmallBuffer", true, 16 * 1024},
		{"Parallel_LargeBuffer", true, 256 * 1024},
	}

	// Prepare benchmark data
	data := genRandomDataForBench(dataSize)
	tempFile := createBenchTempFile(b, data)
	defer os.Remove(tempFile)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)
			additionalData := []byte("parallel-test")

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Open input file
				inFile, err := os.Open(tempFile)
				if err != nil {
					b.Fatalf("Failed to open test file: %v", err)
				}

				// Create a temporary discard writer, but use buffer to avoid frequent GC
				discardBuf := bytes.NewBuffer(make([]byte, 0, 64*1024))
				discardWriter := &writerDiscardButBuffer{buf: discardBuf}

				// Set options
				options := DefaultStreamOptions()
				options.UseParallel = bc.useParallel
				options.BufferSize = bc.bufferSize
				options.AdditionalData = additionalData

				b.StartTimer()

				// Perform encryption
				if _, err := x.EncryptStreamWithOptions(inFile, discardWriter, options); err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}

				b.StopTimer()
				inFile.Close()
			}
		})
	}
}

// writerDiscardButBuffer test writer that discards data but uses buffer to avoid frequent GC
type writerDiscardButBuffer struct {
	buf *bytes.Buffer
}

func (w *writerDiscardButBuffer) Write(p []byte) (n int, err error) {
	// Reset buffer if too large to avoid unlimited growth
	if w.buf.Len() > 1024*1024 {
		w.buf.Reset()
	}
	return w.buf.Write(p)
}

// BenchmarkStreamDifferentBufferSizes tests the impact of different buffer sizes on performance
func BenchmarkStreamDifferentBufferSizes(b *testing.B) {
	dataSize := 5 * 1024 * 1024 // 5MB

	bufferSizes := []int{
		8 * 1024,   // 8KB
		16 * 1024,  // 16KB
		32 * 1024,  // 32KB
		64 * 1024,  // 64KB (default)
		128 * 1024, // 128KB
		256 * 1024, // 256KB
		512 * 1024, // 512KB
	}

	// Prepare test data
	data := genRandomDataForBench(dataSize)

	for _, bufSize := range bufferSizes {
		b.Run(fmt.Sprintf("BufferSize_%dKB", bufSize/1024), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)
			additionalData := []byte("buffer-test")

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(data)
				options := DefaultStreamOptions()
				options.BufferSize = bufSize
				options.AdditionalData = additionalData
				b.StartTimer()

				_, _ = x.EncryptStreamWithOptions(reader, io.Discard, options)
			}
		})
	}
}

// BenchmarkStreamWorkerCount tests the impact of different worker thread counts on parallel processing performance
func BenchmarkStreamWorkerCount(b *testing.B) {
	dataSize := 20 * 1024 * 1024 // 20MB

	// Test different worker thread counts
	workerCounts := []int{1, 2, 4, 8, 16}

	// Prepare test data
	data := genRandomDataForBench(dataSize)
	tempFile := createBenchTempFile(b, data)
	defer os.Remove(tempFile)

	for _, workerCount := range workerCounts {
		b.Run(fmt.Sprintf("Workers_%d", workerCount), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)
			additionalData := []byte("worker-test")

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Open input file
				inFile, err := os.Open(tempFile)
				if err != nil {
					b.Fatalf("Failed to open test file: %v", err)
				}

				// Set options
				options := DefaultStreamOptions()
				options.UseParallel = true
				options.MaxWorkers = workerCount
				options.AdditionalData = additionalData

				b.StartTimer()

				// Perform encryption
				_, _ = x.EncryptStreamWithOptions(inFile, ioutil.Discard, options)

				b.StopTimer()
				inFile.Close()
			}
		})
	}
}

// BenchmarkStreamFileVsMemory compares file and memory stream encryption/decryption performance
func BenchmarkStreamFileVsMemory(b *testing.B) {
	dataSize := 5 * 1024 * 1024 // 5MB

	// Prepare test data
	data := genRandomDataForBench(dataSize)
	tempFile := createBenchTempFile(b, data)
	defer os.Remove(tempFile)

	benchCases := []struct {
		name    string
		useFile bool
	}{
		{"Memory", false},
		{"File", true},
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)
			additionalData := []byte("io-test")

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()

				var reader io.Reader
				var writer io.Writer
				var tempOutFile *os.File

				if bc.useFile {
					// Use file IO
					inFile, err := os.Open(tempFile)
					if err != nil {
						b.Fatalf("Failed to open test file: %v", err)
					}
					defer inFile.Close()

					tempOutFile, err = os.CreateTemp("", "xcipher-bench-out-*")
					if err != nil {
						b.Fatalf("Failed to create output file: %v", err)
					}
					defer func() {
						tempOutFile.Close()
						os.Remove(tempOutFile.Name())
					}()

					reader = inFile
					writer = tempOutFile
				} else {
					// Use memory IO
					reader = bytes.NewReader(data)
					writer = ioutil.Discard
				}

				b.StartTimer()

				// Perform encryption
				_ = x.EncryptStream(reader, writer, additionalData)

				b.StopTimer()
			}
		})
	}
}

// Generate fixed test key
func generateBenchTestKey() []byte {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

var benchTestKey = generateBenchTestKey() // Use fixed key to reduce test variables

// BenchmarkEncryptStream tests stream encryption performance
func BenchmarkEncryptStream(b *testing.B) {
	sizes := []int{
		1 * 1024 * 1024,  // 1MB
		16 * 1024 * 1024, // 16MB
		64 * 1024 * 1024, // 64MB - performance for large files
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r := bytes.NewReader(data)
				w := &bytes.Buffer{}
				b.StartTimer()

				err := cipher.EncryptStream(r, w, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncryptStreamParallel tests parallel stream encryption performance
func BenchmarkEncryptStreamParallel(b *testing.B) {
	sizes := []int{
		1 * 1024 * 1024,  // 1MB
		16 * 1024 * 1024, // 16MB
		64 * 1024 * 1024, // 64MB - performance for large files
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)
			options := DefaultStreamOptions()
			options.UseParallel = true
			options.BufferSize = calculateOptimalBufferSize(options)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r := bytes.NewReader(data)
				w := &bytes.Buffer{}
				b.StartTimer()

				_, err := cipher.EncryptStreamWithOptions(r, w, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecryptStream tests stream decryption performance
func BenchmarkDecryptStream(b *testing.B) {
	sizes := []int{
		1 * 1024 * 1024,  // 1MB
		16 * 1024 * 1024, // 16MB
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			// Encrypt data first
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)
			encBuf := &bytes.Buffer{}
			err := cipher.EncryptStream(bytes.NewReader(data), encBuf, nil)
			if err != nil {
				b.Fatal(err)
			}
			encData := encBuf.Bytes()

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r := bytes.NewReader(encData)
				w := io.Discard // Use Discard to avoid buffer allocation and write overhead
				b.StartTimer()

				err := cipher.DecryptStream(r, w, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecryptStreamParallel tests parallel stream decryption performance
func BenchmarkDecryptStreamParallel(b *testing.B) {
	sizes := []int{
		1 * 1024 * 1024,  // 1MB
		16 * 1024 * 1024, // 16MB
	}

	for _, size := range sizes {
		b.Run(byteCountToString(int64(size)), func(b *testing.B) {
			// Encrypt data using parallel mode first
			data := genRandomDataForBench(size)
			cipher := NewXCipher(benchTestKey)
			encBuf := &bytes.Buffer{}
			options := DefaultStreamOptions()
			options.UseParallel = true

			_, err := cipher.EncryptStreamWithOptions(bytes.NewReader(data), encBuf, options)
			if err != nil {
				b.Fatal(err)
			}
			encData := encBuf.Bytes()

			// Decryption test
			decOptions := DefaultStreamOptions()
			decOptions.UseParallel = true

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r := bytes.NewReader(encData)
				w := io.Discard // Use Discard to avoid buffer allocation and write overhead
				b.StartTimer()

				_, err := cipher.DecryptStreamWithOptions(r, w, decOptions)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// byteCountToString converts byte count to human-readable string
func byteCountToString(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// BenchmarkZeroCopyVsCopy compares performance of zero-copy and standard copy methods
func BenchmarkZeroCopyVsCopy(b *testing.B) {
	// Prepare original data
	data := genRandomDataForBench(1024 * 1024) // 1MB data

	// Test string conversion performance
	b.Run("BytesToString_ZeroCopy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s := bytesToString(data)
			_ = len(s) // Prevent compiler optimization
		}
	})

	b.Run("BytesToString_StandardCopy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s := string(data)
			_ = len(s) // Prevent compiler optimization
		}
	})

	// Test buffer reuse performance
	b.Run("BufferReuse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Get buffer
			buffer := getBuffer(64 * 1024)
			// Simulate buffer usage
			copy(buffer, data[:64*1024])
			// Release buffer
			putBuffer(buffer)
		}
	})

	b.Run("BufferAllocate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Allocate new buffer each time
			buffer := make([]byte, 64*1024)
			// Simulate buffer usage
			copy(buffer, data[:64*1024])
			// GC will handle release
		}
	})
}

// BenchmarkAdaptiveParameters tests dynamic parameter adjustment system performance
func BenchmarkAdaptiveParameters(b *testing.B) {
	// Generate test data
	sizes := []int{
		64 * 1024,       // 64KB
		1 * 1024 * 1024, // 1MB
		8 * 1024 * 1024, // 8MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%s", byteCountToString(int64(size))), func(b *testing.B) {
			data := genRandomDataForBench(size)
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			x := NewXCipher(key)

			// Test with adaptive parameters
			b.Run("AdaptiveParams", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					reader := bytes.NewReader(data)
					writer := ioutil.Discard

					// Use optimized options
					options := GetOptimizedStreamOptions()
					options.CollectStats = false

					b.StartTimer()

					_, _ = x.EncryptStreamWithOptions(reader, writer, options)
				}
			})

			// Test with fixed parameters
			b.Run("FixedParams", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					reader := bytes.NewReader(data)
					writer := ioutil.Discard

					// Use fixed standard options
					options := DefaultStreamOptions()

					b.StartTimer()

					_, _ = x.EncryptStreamWithOptions(reader, writer, options)
				}
			})
		})
	}
}

// BenchmarkCPUArchitectureOptimization tests optimizations for different CPU architectures
func BenchmarkCPUArchitectureOptimization(b *testing.B) {
	// Get CPU optimization info
	info := GetSystemOptimizationInfo()

	// Log CPU architecture information
	b.Logf("Benchmark running on %s architecture", info.Architecture)
	b.Logf("CPU features: AVX=%v, AVX2=%v, SSE41=%v, NEON=%v",
		info.HasAVX, info.HasAVX2, info.HasSSE41, info.HasNEON)

	// Prepare test data
	dataSize := 10 * 1024 * 1024 // 10MB
	data := genRandomDataForBench(dataSize)

	// Create temporary file
	tempFile := createBenchTempFile(b, data)
	defer os.Remove(tempFile)

	// Define different buffer sizes
	bufferSizes := []int{
		16 * 1024,  // 16KB
		64 * 1024,  // 64KB (default)
		128 * 1024, // 128KB (AVX optimized size)
		256 * 1024, // 256KB
	}

	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	x := NewXCipher(key)

	for _, bufSize := range bufferSizes {
		name := fmt.Sprintf("BufferSize_%dKB", bufSize/1024)

		// Add indication if this is architecture-optimized size
		if (info.HasAVX2 && bufSize == avxBufferSize) ||
			(info.HasSSE41 && !info.HasAVX2 && bufSize == sseBufferSize) ||
			(info.HasNEON && bufSize == armBufferSize) {
			name += "_ArchOptimized"
		}

		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Open input file
				inFile, err := os.Open(tempFile)
				if err != nil {
					b.Fatalf("Failed to open test file: %v", err)
				}

				// Set options
				options := DefaultStreamOptions()
				options.BufferSize = bufSize
				options.UseParallel = true
				// Use dynamic worker thread count
				options.MaxWorkers = adaptiveWorkerCount(0, bufSize)

				b.StartTimer()

				// Perform encryption
				_, err = x.EncryptStreamWithOptions(inFile, ioutil.Discard, options)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}

				b.StopTimer()
				inFile.Close()
			}
		})
	}
}

// BenchmarkStreamPerformanceMatrix tests performance matrix with different parameter combinations
func BenchmarkStreamPerformanceMatrix(b *testing.B) {
	// Prepare test data
	dataSize := 5 * 1024 * 1024 // 5MB
	data := genRandomDataForBench(dataSize)

	// Create temporary file
	tempFile := createBenchTempFile(b, data)
	defer os.Remove(tempFile)

	// Parameter matrix test
	testCases := []struct {
		name        string
		useAdaptive bool // Whether to use adaptive parameters
		useParallel bool // Whether to use parallel processing
		zeroCopy    bool // Whether to use zero-copy optimization
		bufferSize  int  // Buffer size, 0 means auto-select
	}{
		{"FullyOptimized", true, true, true, 0},
		{"AdaptiveParams", true, true, false, 0},
		{"ParallelOnly", false, true, false, 64 * 1024},
		{"ZeroCopyOnly", false, false, true, 64 * 1024},
		{"BasicProcessing", false, false, false, 64 * 1024},
	}

	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	x := NewXCipher(key)

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(dataSize))

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Open input file
				inFile, err := os.Open(tempFile)
				if err != nil {
					b.Fatalf("Failed to open test file: %v", err)
				}

				// Configure options
				var options StreamOptions
				if tc.useAdaptive {
					options = GetOptimizedStreamOptions()
				} else {
					options = DefaultStreamOptions()
					options.UseParallel = tc.useParallel
					options.BufferSize = tc.bufferSize
				}

				b.StartTimer()

				// Perform encryption
				stats, err := x.EncryptStreamWithOptions(inFile, ioutil.Discard, options)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}

				b.StopTimer()
				inFile.Close()

				// Check if stats is not nil before logging
				if i == 0 && stats != nil {
					// Log parameter information
					b.Logf("Parameters: Parallel=%v, Buffer=%dKB, Workers=%d",
						stats.ParallelProcessing, stats.BufferSize/1024, stats.WorkerCount)

					// Only print throughput if it's been calculated
					if stats.Throughput > 0 {
						b.Logf("Performance: Throughput=%.2f MB/s", stats.Throughput)
					}
				}
			}
		})
	}
}

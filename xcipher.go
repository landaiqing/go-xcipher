package xcipher

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

const (
	nonceSize         = chacha20poly1305.NonceSizeX
	minCiphertextSize = nonceSize + 16  // 16 is the minimum size of Poly1305 authentication tag
	poolBufferSize    = 32 * 1024       // 32KB memory pool unit
	largeBufferSize   = 256 * 1024      // 256KB large buffer pool unit
	parallelThreshold = 1 * 1024 * 1024 // 1MB parallel processing threshold
	streamBufferSize  = 64 * 1024       // 64KB stream processing buffer size
	minWorkers        = 2               // Minimum number of parallel workers
	maxWorkers        = 8               // Maximum number of parallel workers (increased from 4)
	minBufferSize     = 8 * 1024        // Minimum buffer size (8KB)
	maxBufferSize     = 1024 * 1024     // Maximum buffer size (1MB)
	optimalBlockSize  = 64 * 1024       // 64KB is typically optimal for ChaCha20-Poly1305
	batchSize         = 8               // Batch processing queue size

	// New CPU architecture related constants
	avxBufferSize = 128 * 1024 // Larger buffer size when using AVX optimization
	sseBufferSize = 64 * 1024  // Buffer size when using SSE optimization
	armBufferSize = 32 * 1024  // Buffer size when using ARM optimization
)

// Define error constants for consistent error handling
var (
	ErrInvalidKeySize       = errors.New("xcipher: invalid key size")
	ErrCiphertextShort      = errors.New("xcipher: ciphertext too short")
	ErrNonceGeneration      = errors.New("xcipher: nonce generation failed")
	ErrEmptyPlaintext       = errors.New("xcipher: empty plaintext")
	ErrAuthenticationFailed = errors.New("xcipher: authentication failed")
	ErrReadFailed           = errors.New("xcipher: read from input stream failed")
	ErrWriteFailed          = errors.New("xcipher: write to output stream failed")
	ErrBufferSizeTooSmall   = errors.New("xcipher: buffer size too small")
	ErrBufferSizeTooLarge   = errors.New("xcipher: buffer size too large")
	ErrOperationCancelled   = errors.New("xcipher: operation was cancelled")
)

// Global memory pool to reduce small object allocations
var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, poolBufferSize)
	},
}

// Global memory pool for large buffers used in parallel processing
var largeBufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, largeBufferSize)
	},
}

// Get buffer with specified capacity, prioritize getting from object pool
func getBuffer(capacity int) []byte {
	// Small buffers directly from regular pool
	if capacity <= poolBufferSize {
		buf := bufferPool.Get().([]byte)
		if cap(buf) >= capacity {
			return buf[:capacity]
		}
		bufferPool.Put(buf[:0]) // Return buffer that's too small
	} else if capacity <= largeBufferSize {
		// Large buffers from large buffer pool
		buf := largeBufferPool.Get().([]byte)
		if cap(buf) >= capacity {
			return buf[:capacity]
		}
		largeBufferPool.Put(buf[:0]) // Return buffer that's too small
	}

	// Pool doesn't have large enough buffer, create new one
	return make([]byte, capacity)
}

// Return buffer to appropriate pool
func putBuffer(buf []byte) {
	if buf == nil {
		return
	}

	c := cap(buf)
	if c <= poolBufferSize {
		bufferPool.Put(buf[:0])
	} else if c <= largeBufferSize {
		largeBufferPool.Put(buf[:0])
	}
	// Oversized buffers are not returned to the pool
}

type XCipher struct {
	aead     cipher.AEAD
	overhead int // Cache overhead to reduce repeated calls
}

func NewXCipher(key []byte) *XCipher {
	if len(key) != chacha20poly1305.KeySize {
		log.Panic(fmt.Errorf("%w: expected %d bytes, got %d",
			ErrInvalidKeySize, chacha20poly1305.KeySize, len(key)))
		return nil
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Panic(fmt.Errorf("xcipher: create aead failed: %w", err))
		return nil
	}

	return &XCipher{
		aead:     aead,
		overhead: aead.Overhead(),
	}
}

func (x *XCipher) Encrypt(data, additionalData []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyPlaintext
	}

	// Check if above threshold to use direct allocation
	if len(data) > parallelThreshold {
		return x.encryptDirect(data, additionalData)
	}

	// Use new buffer pool function to get buffer
	requiredCapacity := nonceSize + len(data) + x.overhead
	buf := getBuffer(nonceSize) // First get buffer of nonceSize
	defer func() {
		// If error occurs, ensure buffer is returned to pool
		if len(buf) == nonceSize {
			putBuffer(buf)
		}
	}()

	// Generate random nonce
	if _, err := rand.Read(buf); err != nil {
		return nil, ErrNonceGeneration
	}

	// Expand buffer to accommodate encrypted data
	if cap(buf) < requiredCapacity {
		// Current buffer too small, get a larger one
		oldBuf := buf
		buf = make([]byte, nonceSize, requiredCapacity)
		copy(buf, oldBuf)
		putBuffer(oldBuf) // Return old buffer to pool
	}

	// Use optimized AEAD.Seal call
	result := x.aead.Seal(buf, buf[:nonceSize], data, additionalData)
	return result, nil
}

func (x *XCipher) encryptDirect(data, additionalData []byte) ([]byte, error) {
	// Pre-allocate nonce buffer
	nonce := getBuffer(nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		putBuffer(nonce)
		return nil, ErrNonceGeneration
	}

	// Pre-allocate large enough ciphertext buffer
	ciphertext := make([]byte, nonceSize+len(data)+x.overhead)
	copy(ciphertext, nonce)
	putBuffer(nonce) // No longer need separate nonce buffer

	// Encrypt directly on target buffer
	x.aead.Seal(
		ciphertext[nonceSize:nonceSize],
		ciphertext[:nonceSize],
		data,
		additionalData,
	)
	return ciphertext, nil
}

// Decrypt decrypts data
func (x *XCipher) Decrypt(cipherData, additionalData []byte) ([]byte, error) {
	if len(cipherData) < minCiphertextSize {
		return nil, ErrCiphertextShort
	}

	nonce := cipherData[:nonceSize]
	data := cipherData[nonceSize:]

	// Estimate plaintext size and pre-allocate buffer
	plaintextSize := len(data) - x.overhead
	if plaintextSize <= 0 {
		return nil, ErrCiphertextShort
	}

	// For small data, use memory pool - but don't reuse input buffer to avoid overlap
	if plaintextSize <= largeBufferSize {
		// Note: We always create a new buffer for the result
		// instead of trying to decrypt in-place on the input buffer, which would cause buffer overlap errors
		resultBuf := make([]byte, 0, plaintextSize)
		plaintext, err := x.aead.Open(resultBuf, nonce, data, additionalData)
		if err != nil {
			return nil, ErrAuthenticationFailed
		}
		return plaintext, nil
	}

	// For large data, directly allocate and return
	return x.aead.Open(nil, nonce, data, additionalData)
}

// StreamStats contains statistics for stream encryption/decryption
type StreamStats struct {
	// Start time
	StartTime time.Time
	// End time
	EndTime time.Time
	// Total processed bytes
	BytesProcessed int64
	// Number of blocks
	BlocksProcessed int
	// Average block size
	AvgBlockSize float64
	// Processing speed (MB/s)
	Throughput float64
	// Whether parallel processing was used
	ParallelProcessing bool
	// Number of worker threads
	WorkerCount int
	// Buffer size
	BufferSize int
}

// Duration returns the processing duration
func (s *StreamStats) Duration() time.Duration {
	return s.EndTime.Sub(s.StartTime)
}

// StreamOptions used to configure stream encryption/decryption options
type StreamOptions struct {
	// Buffer size
	BufferSize int
	// Whether to use parallel processing
	UseParallel bool
	// Maximum number of worker threads
	MaxWorkers int
	// Additional authenticated data
	AdditionalData []byte
	// Whether to collect statistics
	CollectStats bool
	// Cancel signal
	CancelChan <-chan struct{}
}

// DefaultStreamOptions returns default stream encryption/decryption options
func DefaultStreamOptions() StreamOptions {
	return StreamOptions{
		BufferSize:     streamBufferSize,
		UseParallel:    false,
		MaxWorkers:     maxWorkers,
		AdditionalData: nil,
		CollectStats:   false,
		CancelChan:     nil,
	}
}

// EncryptStreamWithOptions performs stream encryption using configuration options
func (x *XCipher) EncryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (stats *StreamStats, err error) {
	// Use dynamic parameter system to adjust parameters
	if options.BufferSize <= 0 {
		options.BufferSize = adaptiveBufferSize(0)
	} else {
		options.BufferSize = adaptiveBufferSize(options.BufferSize)
	}

	// Automatically decide whether to use parallel processing based on buffer size
	if !options.UseParallel && options.BufferSize >= parallelThreshold/2 {
		options.UseParallel = true
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = adaptiveWorkerCount(0, options.BufferSize)
		}
	} else if options.MaxWorkers <= 0 {
		options.MaxWorkers = adaptiveWorkerCount(0, options.BufferSize)
	}

	// Initialize statistics
	if options.CollectStats {
		stats = &StreamStats{
			StartTime:          time.Now(),
			ParallelProcessing: options.UseParallel,
			WorkerCount:        options.MaxWorkers,
			BufferSize:         options.BufferSize,
		}
		defer func() {
			stats.EndTime = time.Now()
			if stats.BytesProcessed > 0 {
				durationSec := stats.Duration().Seconds()
				if durationSec > 0 {
					stats.Throughput = float64(stats.BytesProcessed) / durationSec / 1e6 // MB/s
					// Update system metrics - record throughput for future optimization
					updateSystemMetrics(0, 0, stats.Throughput)
				}
				if stats.BlocksProcessed > 0 {
					stats.AvgBlockSize = float64(stats.BytesProcessed) / float64(stats.BlocksProcessed)
				}
			}
		}()
	}

	// Validate options
	if options.BufferSize < minBufferSize {
		return stats, fmt.Errorf("%w: %d is less than minimum %d",
			ErrBufferSizeTooSmall, options.BufferSize, minBufferSize)
	} else if options.BufferSize > maxBufferSize {
		return stats, fmt.Errorf("%w: %d is greater than maximum %d",
			ErrBufferSizeTooLarge, options.BufferSize, maxBufferSize)
	}

	// Parallel processing path
	if options.UseParallel {
		// Adaptively adjust worker thread count based on current CPU architecture
		workerCount := adaptiveWorkerCount(options.MaxWorkers, options.BufferSize)
		options.MaxWorkers = workerCount

		// Update statistics to reflect actual worker count used
		if stats != nil {
			stats.WorkerCount = workerCount
		}

		// Use parallel implementation
		return x.encryptStreamParallelWithOptions(reader, writer, options, stats)
	}

	// Sequential processing path with zero-copy optimizations
	// ----------------------------------------------------------

	// Generate random nonce - use global constants to avoid compile-time recalculation
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
	}

	// Write nonce first - write at once to reduce system calls
	if _, err := writer.Write(nonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	// Use buffer from pool with CPU-aware optimal size
	bufferSize := options.BufferSize
	bufferFromPool := getBuffer(bufferSize)
	defer putBuffer(bufferFromPool)

	// Pre-allocate a large enough encryption result buffer, avoid allocation each time
	sealed := make([]byte, 0, bufferSize+x.overhead)

	// Use counter to track block sequence
	var counter uint64 = 0
	var bytesProcessed int64 = 0
	var blocksProcessed = 0

	// Optimize batch processing based on CPU features
	useDirectWrite := cpuFeatures.hasAVX2 || cpuFeatures.hasAVX

	// Pre-allocate pending write queue to reduce system calls
	pendingWrites := make([][]byte, 0, 8)
	totalPendingBytes := 0
	flushThreshold := 256 * 1024 // 256KB batch write threshold

	// Flush buffered write data
	flushWrites := func() error {
		if len(pendingWrites) == 0 {
			return nil
		}

		// Optimization: For single data block, write directly
		if len(pendingWrites) == 1 {
			if _, err := writer.Write(pendingWrites[0]); err != nil {
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
			pendingWrites = pendingWrites[:0]
			totalPendingBytes = 0
			return nil
		}

		// Optimization: For multiple data blocks, batch write
		// Pre-allocate buffer large enough for batch write
		batchBuffer := getBuffer(totalPendingBytes)
		offset := 0

		// Copy all pending data to batch buffer
		for _, data := range pendingWrites {
			copy(batchBuffer[offset:], data)
			offset += len(data)
		}

		// Write all data at once, reducing system calls
		if _, err := writer.Write(batchBuffer[:offset]); err != nil {
			putBuffer(batchBuffer)
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}

		putBuffer(batchBuffer)
		pendingWrites = pendingWrites[:0]
		totalPendingBytes = 0
		return nil
	}

	// Defer to ensure all data is flushed
	defer func() {
		if err2 := flushWrites(); err2 != nil && err == nil {
			err = err2
		}
	}()

	for {
		// Check cancel signal
		if options.CancelChan != nil {
			select {
			case <-options.CancelChan:
				return stats, ErrOperationCancelled
			default:
				// Continue processing
			}
		}

		// Read plaintext data
		n, err := reader.Read(bufferFromPool)
		if err != nil && err != io.EOF {
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Update statistics
			bytesProcessed += int64(n)
			blocksProcessed++

			// Update nonce - use counter with little-endian encoding
			binary.LittleEndian.PutUint64(nonce, counter)
			counter++

			// Encrypt data block - use pre-allocated buffer
			// Note: ChaCha20-Poly1305's Seal operation is already highly optimized internally, using zero-copy mechanism
			encrypted := x.aead.Seal(sealed[:0], nonce, bufferFromPool[:n], options.AdditionalData)

			// Optimize writing - decide to write directly or buffer based on conditions
			if useDirectWrite && n >= 16*1024 { // Large blocks write directly
				if err := flushWrites(); err != nil { // Flush waiting data first
					return stats, err
				}

				// Write large data block directly
				if _, err := writer.Write(encrypted); err != nil {
					return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}
			} else {
				// Small data blocks use batch processing
				// Copy encrypted data to new buffer, since encrypted is based on temporary buffer
				encryptedCopy := getBuffer(len(encrypted))
				copy(encryptedCopy, encrypted)

				pendingWrites = append(pendingWrites, encryptedCopy)
				totalPendingBytes += len(encryptedCopy)

				// Execute batch write when enough data accumulates
				if totalPendingBytes >= flushThreshold {
					if err := flushWrites(); err != nil {
						return stats, err
					}
				}
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Ensure all data is written
	if err := flushWrites(); err != nil {
		return stats, err
	}

	// Update statistics
	if stats != nil {
		stats.BytesProcessed = bytesProcessed
		stats.BlocksProcessed = blocksProcessed
	}

	return stats, nil
}

// Internal method for parallel encryption with options
func (x *XCipher) encryptStreamParallelWithOptions(reader io.Reader, writer io.Writer, options StreamOptions, stats *StreamStats) (*StreamStats, error) {
	// Use CPU-aware parameter optimization
	bufferSize := adaptiveBufferSize(options.BufferSize)
	workerCount := adaptiveWorkerCount(options.MaxWorkers, bufferSize)

	// Update the options to use the optimized values
	options.BufferSize = bufferSize
	options.MaxWorkers = workerCount

	// Update statistics
	if stats != nil {
		stats.BufferSize = bufferSize
		stats.WorkerCount = workerCount
	}

	// Generate random base nonce
	baseNonce := make([]byte, nonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return stats, ErrNonceGeneration
	}

	// Write base nonce first
	if _, err := writer.Write(baseNonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	// Adjust job queue size to reduce contention - based on CPU features
	workerQueueSize := workerCount * 4
	if cpuFeatures.hasAVX2 || cpuFeatures.hasAVX {
		workerQueueSize = workerCount * 8 // AVX processors can handle more tasks
	}

	// Create worker pool
	jobs := make(chan job, workerQueueSize)
	results := make(chan result, workerQueueSize)
	errorsChannel := make(chan error, 1)
	var wg sync.WaitGroup

	// Pre-allocate a consistent location to store processed results
	var bytesProcessed int64 = 0
	var blocksProcessed = 0

	// Start worker threads
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each worker thread pre-allocates its own encryption buffer to avoid allocation each time
			// Adjust buffer size based on CPU features
			var encBufSize int
			if cpuFeatures.hasAVX2 {
				encBufSize = bufferSize + x.overhead + 64 // AVX2 needs extra alignment space
			} else {
				encBufSize = bufferSize + x.overhead
			}
			encBuf := make([]byte, 0, encBufSize)

			for job := range jobs {
				// Create unique nonce for each block using shared base nonce
				blockNonce := make([]byte, nonceSize)
				copy(blockNonce, baseNonce)
				binary.LittleEndian.PutUint64(blockNonce, job.id)

				// Encrypt data block using pre-allocated buffer
				encrypted := x.aead.Seal(encBuf[:0], blockNonce, job.data, options.AdditionalData)

				// Use zero-copy technique - directly pass encryption result
				// Note: We no longer copy data to a new buffer, but use the encryption result directly
				results <- result{
					id:   job.id,
					data: encrypted,
				}

				// Release input buffer after completion
				putBuffer(job.data)
			}
		}()
	}

	// Start result collection and writing thread
	resultsDone := make(chan struct{})
	go func() {
		pendingResults := make(map[uint64][]byte)
		nextID := uint64(0)

		// Batch write optimization
		var pendingWrites [][]byte
		var totalPendingSize int
		const flushThreshold = 256 * 1024 // 256KB

		// Flush buffered writes
		flushWrites := func() error {
			if len(pendingWrites) == 0 {
				return nil
			}

			// Write single data block directly
			if len(pendingWrites) == 1 {
				// Write block size
				sizeBytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(sizeBytes, uint32(len(pendingWrites[0])))

				if _, err := writer.Write(sizeBytes); err != nil {
					return fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}

				// Write data
				if _, err := writer.Write(pendingWrites[0]); err != nil {
					return fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}

				// Update statistics
				if stats != nil {
					bytesProcessed += int64(len(pendingWrites[0]))
				}

				pendingWrites = pendingWrites[:0]
				totalPendingSize = 0
				return nil
			}

			// Combine multiple data blocks for writing
			// First calculate total size, including size headers for each block
			headerSize := 4 * len(pendingWrites)
			dataSize := totalPendingSize
			batchBuffer := getBuffer(headerSize + dataSize)

			// Write all block sizes
			headerOffset := 0
			dataOffset := headerSize

			for _, data := range pendingWrites {
				// Write block size
				binary.LittleEndian.PutUint32(batchBuffer[headerOffset:], uint32(len(data)))
				headerOffset += 4

				// Copy data
				copy(batchBuffer[dataOffset:], data)
				dataOffset += len(data)
			}

			// Write all data at once
			if _, err := writer.Write(batchBuffer[:headerSize+dataSize]); err != nil {
				putBuffer(batchBuffer)
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}

			// Update statistics
			if stats != nil {
				bytesProcessed += int64(dataSize)
			}

			putBuffer(batchBuffer)
			pendingWrites = pendingWrites[:0]
			totalPendingSize = 0
			return nil
		}

		// Ensure final data is flushed
		defer func() {
			if err := flushWrites(); err != nil {
				errorsChannel <- err
			}
		}()

		for r := range results {
			pendingResults[r.id] = r.data

			// Write results in order
			for {
				if data, ok := pendingResults[nextID]; ok {
					// Add to pending write queue
					pendingWrites = append(pendingWrites, data)
					totalPendingSize += len(data)

					// Execute batch write when enough data accumulates
					if totalPendingSize >= flushThreshold || len(pendingWrites) >= 32 {
						if err := flushWrites(); err != nil {
							errorsChannel <- err
							return
						}
					}

					// Update statistics
					if stats != nil {
						blocksProcessed++
					}

					delete(pendingResults, nextID)
					nextID++
				} else {
					break
				}
			}
		}

		// Ensure all data is written
		if err := flushWrites(); err != nil {
			errorsChannel <- err
			return
		}

		close(resultsDone) // Signal that result processing is complete
	}()

	// Read and assign work - use optimized batch processing mechanism
	// Adjust batch size based on CPU features and buffer size
	batchCount := batchSize
	if cpuFeatures.hasAVX2 {
		batchCount = batchSize * 2 // AVX2 can process larger batches
	} else if cpuFeatures.hasNEON {
		batchCount = batchSize + 2 // Optimized batch size for ARM processors
	}

	// Batch preparation
	dataBatch := make([][]byte, 0, batchCount)
	idBatch := make([]uint64, 0, batchCount)
	var jobID uint64 = 0

	// Use CPU-aware buffer
	buffer := getBuffer(bufferSize)
	defer putBuffer(buffer)

	for {
		// Check cancel signal
		if options.CancelChan != nil {
			select {
			case <-options.CancelChan:
				// Clean up resources and return
				close(jobs)
				wg.Wait()
				close(results)
				<-resultsDone
				return stats, ErrOperationCancelled
			default:
				// Continue processing
			}
		}

		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			// Error handling
			close(jobs)
			wg.Wait()
			close(results)
			<-resultsDone
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Zero-copy optimization: use exact size buffer to avoid extra copying
			data := getBuffer(n)
			copy(data, buffer[:n])

			// Add to batch
			dataBatch = append(dataBatch, data)
			idBatch = append(idBatch, jobID)
			jobID++

			// Send when batch is full or EOF is reached
			if len(dataBatch) >= batchCount || err == io.EOF {
				for i := range dataBatch {
					// Send work with timeout protection
					select {
					case jobs <- job{
						id:   idBatch[i],
						data: dataBatch[i],
					}:
					case <-options.CancelChan:
						// Clean up resources in case of cancellation
						for _, d := range dataBatch[i:] {
							putBuffer(d)
						}

						// Gracefully close all goroutines
						close(jobs)
						wg.Wait()
						close(results)
						<-resultsDone
						return stats, ErrOperationCancelled
					}
				}
				// Clear batch
				dataBatch = dataBatch[:0]
				idBatch = idBatch[:0]
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Send remaining batch
	for i := range dataBatch {
		jobs <- job{
			id:   idBatch[i],
			data: dataBatch[i],
		}
	}

	// Close jobs channel and wait for all workers to complete
	close(jobs)
	wg.Wait()

	// Close results channel after all workers are done
	close(results)

	// Wait for result processing to complete
	<-resultsDone

	// Update statistics
	if stats != nil {
		stats.BytesProcessed = bytesProcessed
		stats.BlocksProcessed = blocksProcessed
	}

	// Check for errors
	select {
	case err := <-errorsChannel:
		return stats, err
	default:
		return stats, nil
	}
}

// DecryptStreamWithOptions performs stream decryption with configuration options
func (x *XCipher) DecryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error) {
	// Use dynamic parameter system optimization
	if options.BufferSize <= 0 {
		options.BufferSize = adaptiveBufferSize(0)
	} else {
		options.BufferSize = adaptiveBufferSize(options.BufferSize)
	}

	// Automatically decide whether to use parallel processing based on buffer size
	if !options.UseParallel && options.BufferSize >= parallelThreshold/2 {
		options.UseParallel = true
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = adaptiveWorkerCount(0, options.BufferSize)
		}
	} else if options.MaxWorkers <= 0 {
		options.MaxWorkers = adaptiveWorkerCount(0, options.BufferSize)
	}

	// Initialize statistics
	var stats *StreamStats
	if options.CollectStats {
		stats = &StreamStats{
			StartTime:          time.Now(),
			ParallelProcessing: options.UseParallel,
			WorkerCount:        options.MaxWorkers,
			BufferSize:         options.BufferSize,
		}
		defer func() {
			stats.EndTime = time.Now()
			if stats.BytesProcessed > 0 {
				durationSec := stats.Duration().Seconds()
				if durationSec > 0 {
					stats.Throughput = float64(stats.BytesProcessed) / durationSec / 1e6 // MB/s
					// Update system metrics
					updateSystemMetrics(0, 0, stats.Throughput)
				}
				if stats.BlocksProcessed > 0 {
					stats.AvgBlockSize = float64(stats.BytesProcessed) / float64(stats.BlocksProcessed)
				}
			}
		}()
	}

	// Validate parameters
	if options.BufferSize < minBufferSize {
		return stats, fmt.Errorf("%w: %d is less than minimum %d",
			ErrBufferSizeTooSmall, options.BufferSize, minBufferSize)
	} else if options.BufferSize > maxBufferSize {
		return stats, fmt.Errorf("%w: %d is greater than maximum %d",
			ErrBufferSizeTooLarge, options.BufferSize, maxBufferSize)
	}

	// Parallel processing path
	if options.UseParallel {
		// Adaptively adjust worker thread count
		workerCount := adaptiveWorkerCount(options.MaxWorkers, options.BufferSize)
		options.MaxWorkers = workerCount

		// Update statistics
		if stats != nil {
			stats.WorkerCount = workerCount
		}

		// Use parallel implementation
		return x.decryptStreamParallelWithOptions(reader, writer, options)
	}

	// Sequential processing path - use zero-copy optimization
	// ----------------------------------------------------------

	// Read nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return stats, fmt.Errorf("%w: failed to read nonce: %v", ErrReadFailed, err)
	}

	// Use CPU-aware optimal buffer size
	bufferSize := options.BufferSize

	// Get encrypted data buffer from pool
	encBuffer := getBuffer(bufferSize + x.overhead)
	defer putBuffer(encBuffer)

	// Pre-allocate decryption result buffer, avoid repeated allocation
	decBuffer := make([]byte, 0, bufferSize)

	// Counter for tracking data block sequence
	var counter uint64 = 0
	var bytesProcessed int64 = 0
	var blocksProcessed = 0

	// Optimize batch processing based on CPU features
	useDirectWrite := cpuFeatures.hasAVX2 || cpuFeatures.hasAVX

	// Pre-allocate pending write queue to reduce system calls
	pendingWrites := make([][]byte, 0, 8)
	totalPendingBytes := 0
	flushThreshold := 256 * 1024 // 256KB batch write threshold

	// Flush buffered write data
	flushWrites := func() error {
		if len(pendingWrites) == 0 {
			return nil
		}

		// Single data block write directly
		if len(pendingWrites) == 1 {
			if _, err := writer.Write(pendingWrites[0]); err != nil {
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
			// Update statistics
			if stats != nil {
				bytesProcessed += int64(len(pendingWrites[0]))
			}
			pendingWrites = pendingWrites[:0]
			totalPendingBytes = 0
			return nil
		}

		// Multiple data blocks batch write
		batchBuffer := getBuffer(totalPendingBytes)
		offset := 0

		for _, data := range pendingWrites {
			copy(batchBuffer[offset:], data)
			offset += len(data)
		}

		// Write all data at once
		if _, err := writer.Write(batchBuffer[:offset]); err != nil {
			putBuffer(batchBuffer)
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}

		// Update statistics
		if stats != nil {
			bytesProcessed += int64(offset)
		}

		putBuffer(batchBuffer)
		pendingWrites = pendingWrites[:0]
		totalPendingBytes = 0
		return nil
	}

	// Defer to ensure all data is flushed
	defer func() {
		if err := flushWrites(); err != nil {
			log.Printf("Warning: failed to flush remaining writes: %v", err)
		}
	}()

	for {
		// Check cancel signal
		if options.CancelChan != nil {
			select {
			case <-options.CancelChan:
				return stats, ErrOperationCancelled
			default:
				// Continue processing
			}
		}

		// Read encrypted data
		n, err := reader.Read(encBuffer)
		if err != nil && err != io.EOF {
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			blocksProcessed++

			// Update nonce - use counter
			binary.LittleEndian.PutUint64(nonce, counter)
			counter++

			// Decrypt data block - zero-copy operation
			decrypted, err := x.aead.Open(decBuffer[:0], nonce, encBuffer[:n], options.AdditionalData)
			if err != nil {
				return stats, ErrAuthenticationFailed
			}

			// Optimize writing strategy - decide based on data size
			if useDirectWrite && len(decrypted) >= 16*1024 { // Large blocks write directly
				if err := flushWrites(); err != nil { // Flush waiting data first
					return stats, err
				}

				// Write large data block directly
				if _, err := writer.Write(decrypted); err != nil {
					return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}

				// Update statistics
				if stats != nil {
					bytesProcessed += int64(len(decrypted))
				}
			} else {
				// Small data blocks batch processing
				// Because decrypted may point to temporary buffer, we need to copy data
				decryptedCopy := getBuffer(len(decrypted))
				copy(decryptedCopy, decrypted)

				pendingWrites = append(pendingWrites, decryptedCopy)
				totalPendingBytes += len(decryptedCopy)

				// Execute batch write when enough data accumulates
				if totalPendingBytes >= flushThreshold {
					if err := flushWrites(); err != nil {
						return stats, err
					}
				}
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Ensure all data is written
	if err := flushWrites(); err != nil {
		return stats, err
	}

	// Update statistics
	if stats != nil {
		stats.BlocksProcessed = blocksProcessed
	}

	return stats, nil
}

// EncryptStream performs stream encryption with default options
func (x *XCipher) EncryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error {
	options := DefaultStreamOptions()
	options.AdditionalData = additionalData
	_, err := x.EncryptStreamWithOptions(reader, writer, options)
	return err
}

func (x *XCipher) DecryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error {
	options := DefaultStreamOptions()
	options.AdditionalData = additionalData
	_, err := x.DecryptStreamWithOptions(reader, writer, options)
	return err
}

// Job and result structures
type job struct {
	id   uint64
	data []byte
}

type result struct {
	id   uint64
	data []byte
}

// New function - optimized worker count calculation
func calculateOptimalWorkers(dataSize int, maxWorkers int) int {
	cpuCount := runtime.NumCPU()

	// For small data amount, use fewer worker threads
	if dataSize < 4*1024*1024 { // 4MB
		workers := cpuCount / 2
		if workers < minWorkers {
			return minWorkers
		}
		if workers > maxWorkers {
			return maxWorkers
		}
		return workers
	}

	// For large data amount, use more worker threads but not more than CPU count
	workers := cpuCount
	if workers > maxWorkers {
		return maxWorkers
	}
	return workers
}

// New function - calculate optimal buffer size
func calculateOptimalBufferSize(options StreamOptions) int {
	// Check user-specified buffer size
	if options.BufferSize > 0 {
		if options.BufferSize < minBufferSize {
			return minBufferSize
		}
		if options.BufferSize > maxBufferSize {
			return maxBufferSize
		}
		return options.BufferSize
	}

	// Default value when unspecified
	return optimalBlockSize
}

// CPUFeatures stores current CPU support feature information
type CPUFeatures struct {
	hasAVX        bool
	hasAVX2       bool
	hasSSE41      bool
	hasNEON       bool // ARM NEON instruction set
	cacheLineSize int
	l1CacheSize   int
	l2CacheSize   int
	l3CacheSize   int
}

// Global CPU feature variable
var cpuFeatures = detectCPUFeatures()

// Detect CPU features and capabilities
func detectCPUFeatures() CPUFeatures {
	features := CPUFeatures{
		hasAVX:        cpu.X86.HasAVX,
		hasAVX2:       cpu.X86.HasAVX2,
		hasSSE41:      cpu.X86.HasSSE41,
		hasNEON:       cpu.ARM64.HasASIMD,
		cacheLineSize: 64, // Default cache line size
	}

	// Estimate CPU cache size (using conservative estimates)
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		features.l1CacheSize = 32 * 1024       // 32KB
		features.l2CacheSize = 256 * 1024      // 256KB
		features.l3CacheSize = 8 * 1024 * 1024 // 8MB
	} else if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		features.l1CacheSize = 32 * 1024       // 32KB
		features.l2CacheSize = 1024 * 1024     // 1MB
		features.l3CacheSize = 4 * 1024 * 1024 // 4MB
	}

	return features
}

// Get current CPU architecture optimal buffer size
func getOptimalBufferSize() int {
	if cpuFeatures.hasAVX2 {
		return avxBufferSize
	} else if cpuFeatures.hasSSE41 {
		return sseBufferSize
	} else if cpuFeatures.hasNEON {
		return armBufferSize
	}
	return optimalBlockSize // Default size
}

// Get optimal parallel worker count based on CPU architecture
func getOptimalWorkerCount() int {
	cpuCount := runtime.NumCPU()

	// Different architecture optimization thread count
	if cpuFeatures.hasAVX2 || cpuFeatures.hasAVX {
		// AVX architecture efficiency higher, can use fewer threads
		return max(minWorkers, min(cpuCount-1, maxWorkers))
	} else if cpuFeatures.hasNEON {
		// ARM architecture may require different optimization strategy
		return max(minWorkers, min(cpuCount, maxWorkers))
	}

	// Default strategy
	return max(minWorkers, min(cpuCount, maxWorkers))
}

// Simple min and max functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Zero-copy technique related helper functions
// ---------------------------------

// Use unsafe.Pointer to implement memory zero-copy conversion
// Warning: This may cause very subtle problems, must be used carefully
func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func stringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			cap int
		}{s, len(s)},
	))
}

// Provide safe memory reuse method to avoid unnecessary allocation
func reuseBuffer(data []byte, newCapacity int) []byte {
	// If existing buffer capacity is enough, reuse
	if cap(data) >= newCapacity {
		return data[:newCapacity]
	}

	// Otherwise create new buffer and copy data
	newBuf := make([]byte, newCapacity)
	copy(newBuf, data)
	return newBuf
}

// Internal method for parallel decryption with options
func (x *XCipher) decryptStreamParallelWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error) {
	// Initialize statistics
	var stats *StreamStats
	if options.CollectStats {
		stats = &StreamStats{
			StartTime:          time.Now(),
			ParallelProcessing: true,
			WorkerCount:        options.MaxWorkers,
			BufferSize:         options.BufferSize,
		}
		defer func() {
			stats.EndTime = time.Now()
			if stats.BytesProcessed > 0 {
				durationSec := stats.Duration().Seconds()
				if durationSec > 0 {
					stats.Throughput = float64(stats.BytesProcessed) / durationSec / 1e6 // MB/s
				}
				if stats.BlocksProcessed > 0 {
					stats.AvgBlockSize = float64(stats.BytesProcessed) / float64(stats.BlocksProcessed)
				}
			}
		}()
	}

	// Use CPU-aware parameters optimization
	bufferSize := adaptiveBufferSize(options.BufferSize)
	workerCount := adaptiveWorkerCount(options.MaxWorkers, bufferSize)

	// Read base nonce
	baseNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, baseNonce); err != nil {
		return stats, fmt.Errorf("%w: failed to read nonce: %v", ErrReadFailed, err)
	}

	// Adjust job queue size to reduce contention - based on CPU features
	workerQueueSize := workerCount * 4
	if cpuFeatures.hasAVX2 || cpuFeatures.hasAVX {
		workerQueueSize = workerCount * 8 // AVX processors can handle more tasks
	}

	// Create worker pool
	jobs := make(chan job, workerQueueSize)
	results := make(chan result, workerQueueSize)
	errorsChannel := make(chan error, 1)
	var wg sync.WaitGroup

	// Start worker threads
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each worker thread pre-allocates its own decryption buffer to avoid allocation each time
			decBuf := make([]byte, 0, bufferSize)

			for job := range jobs {
				// Create unique nonce for each block
				blockNonce := make([]byte, nonceSize)
				copy(blockNonce, baseNonce)
				binary.LittleEndian.PutUint64(blockNonce, job.id)

				// Decrypt data block - try zero-copy operation
				decrypted, err := x.aead.Open(decBuf[:0], blockNonce, job.data, options.AdditionalData)
				if err != nil {
					select {
					case errorsChannel <- ErrAuthenticationFailed:
					default:
						// If an error is already sent, don't send another one
					}
					putBuffer(job.data) // Release buffer
					continue            // Continue processing other blocks instead of returning immediately
				}

				// Zero-copy method pass result - directly use decryption result without copying
				// Here we pass decryption result through queue, but not copy to new buffer
				results <- result{
					id:   job.id,
					data: decrypted,
				}

				// Release input buffer
				putBuffer(job.data)
			}
		}()
	}

	// Start result collection and writing thread
	resultsDone := make(chan struct{})
	go func() {
		pendingResults := make(map[uint64][]byte)
		nextID := uint64(0)

		for r := range results {
			pendingResults[r.id] = r.data

			// Write results in order - zero-copy batch write
			for {
				if data, ok := pendingResults[nextID]; ok {
					if _, err := writer.Write(data); err != nil {
						errorsChannel <- fmt.Errorf("%w: %v", ErrWriteFailed, err)
						return
					}

					if stats != nil {
						stats.BytesProcessed += int64(len(data))
						stats.BlocksProcessed++
					}

					// Note: We no longer return buffer to pool, because these buffers are directly obtained from AEAD.Open
					// Lower layer implementation is responsible for memory management
					delete(pendingResults, nextID)
					nextID++
				} else {
					break
				}
			}
		}
		close(resultsDone)
	}()

	// Read and assign work
	sizeBytes := make([]byte, 4)
	var jobID uint64 = 0

	// Optimize batch processing size based on CPU features and buffer size
	batchCount := batchSize
	if cpuFeatures.hasAVX2 {
		batchCount = batchSize * 2 // AVX2 can process larger batches
	}

	// Add batch processing mechanism to reduce channel contention
	dataBatch := make([][]byte, 0, batchCount)
	idBatch := make([]uint64, 0, batchCount)

	for {
		// Check cancel signal
		if options.CancelChan != nil {
			select {
			case <-options.CancelChan:
				// Gracefully handle cancellation
				close(jobs)
				wg.Wait()
				close(results)
				<-resultsDone
				return stats, ErrOperationCancelled
			default:
				// Continue processing
			}
		}

		// Read block size - use shared buffer to reduce small object allocation
		_, err := io.ReadFull(reader, sizeBytes)
		if err != nil {
			if err == io.EOF {
				break
			}
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		blockSize := binary.LittleEndian.Uint32(sizeBytes)
		encryptedBlock := getBuffer(int(blockSize))

		// Read encrypted data block - use pre-allocated buffer
		_, err = io.ReadFull(reader, encryptedBlock)
		if err != nil {
			putBuffer(encryptedBlock) // Release buffer
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		// Add to batch
		dataBatch = append(dataBatch, encryptedBlock)
		idBatch = append(idBatch, jobID)
		jobID++

		// Send when batch is full
		if len(dataBatch) >= batchCount {
			for i := range dataBatch {
				select {
				case jobs <- job{
					id:   idBatch[i],
					data: dataBatch[i],
				}:
				case <-options.CancelChan:
					// Clean up resources in case of cancellation
					for _, d := range dataBatch {
						putBuffer(d)
					}
					return stats, ErrOperationCancelled
				}
			}
			// Clear batch
			dataBatch = dataBatch[:0]
			idBatch = idBatch[:0]
		}
	}

	// Send remaining batch
	for i := range dataBatch {
		jobs <- job{
			id:   idBatch[i],
			data: dataBatch[i],
		}
	}

	// Close jobs channel and wait for all workers to complete
	close(jobs)
	wg.Wait()

	// Close results channel after all workers are done
	close(results)

	// Wait for result processing to complete
	<-resultsDone

	// Check for errors
	select {
	case err := <-errorsChannel:
		return stats, err
	default:
		return stats, nil
	}
}

// Intelligent dynamic parameter adjustment system
// ----------------------------------

// Dynamic system parameter structure
type DynamicSystemParams struct {
	lastCPUUsage       float64
	lastMemoryUsage    float64
	lastThroughput     float64
	samplesCount       int
	bufferSizeHistory  []int
	workerCountHistory []int
	mutex              sync.Mutex
}

// Global dynamic parameter system instance
var dynamicParams = &DynamicSystemParams{
	bufferSizeHistory:  make([]int, 0, 10),
	workerCountHistory: make([]int, 0, 10),
}

// Based on runtime environment, dynamically adjust buffer size
func adaptiveBufferSize(requestedSize int) int {
	dynamicParams.mutex.Lock()
	defer dynamicParams.mutex.Unlock()

	// If no size specified, use default value
	if requestedSize <= 0 {
		return optimalBlockSize
	}

	// Check and adjust to valid range
	if requestedSize < minBufferSize {
		// Buffer too small, automatically adjust to minimum valid value
		return minBufferSize
	}

	if requestedSize > maxBufferSize {
		// Buffer too large, automatically adjust to maximum valid value
		return maxBufferSize
	}

	// Record historical usage for future optimization
	if len(dynamicParams.bufferSizeHistory) >= 10 {
		dynamicParams.bufferSizeHistory = dynamicParams.bufferSizeHistory[1:]
	}
	dynamicParams.bufferSizeHistory = append(dynamicParams.bufferSizeHistory, requestedSize)

	// Return requested size (already in valid range)
	return requestedSize
}

// Dynamically adjust worker count
func adaptiveWorkerCount(requestedCount int, bufferSize int) int {
	dynamicParams.mutex.Lock()
	defer dynamicParams.mutex.Unlock()

	// If specific count requested, verify and use
	if requestedCount > 0 {
		if requestedCount < minWorkers {
			requestedCount = minWorkers
		} else if requestedCount > maxWorkers {
			requestedCount = maxWorkers
		}

		// Record history
		dynamicParams.workerCountHistory = append(dynamicParams.workerCountHistory, requestedCount)
		if len(dynamicParams.workerCountHistory) > 10 {
			dynamicParams.workerCountHistory = dynamicParams.workerCountHistory[1:]
		}

		return requestedCount
	}

	cpuCount := runtime.NumCPU()

	// Basic strategy: Smaller buffer uses more worker threads, Larger buffer uses fewer worker threads
	var optimalCount int
	if bufferSize < 64*1024 {
		// Small buffer: Use more CPU
		optimalCount = max(minWorkers, min(cpuCount, maxWorkers))
	} else if bufferSize >= 512*1024 {
		// Large buffer: Reduce CPU count to avoid memory bandwidth saturation
		optimalCount = max(minWorkers, min(cpuCount/2, maxWorkers))
	} else {
		// Medium buffer: Balance processing
		optimalCount = max(minWorkers, min(cpuCount*3/4, maxWorkers))
	}

	// Further adjust based on CPU architecture
	if cpuFeatures.hasAVX2 {
		// AVX2 processor efficiency higher, may need fewer threads
		optimalCount = max(minWorkers, optimalCount*3/4)
	} else if cpuFeatures.hasNEON {
		// ARM processor may have different characteristics
		optimalCount = max(minWorkers, min(optimalCount+1, maxWorkers))
	}

	// If historical record exists, use average value to stabilize parameters
	if len(dynamicParams.workerCountHistory) > 0 {
		sum := 0
		for _, count := range dynamicParams.workerCountHistory {
			sum += count
		}
		avgCount := sum / len(dynamicParams.workerCountHistory)

		// Move towards historical average value
		optimalCount = (optimalCount*2 + avgCount) / 3
	}

	// Ensure final result within valid range
	optimalCount = max(minWorkers, min(optimalCount, maxWorkers))

	// Record history
	dynamicParams.workerCountHistory = append(dynamicParams.workerCountHistory, optimalCount)
	if len(dynamicParams.workerCountHistory) > 10 {
		dynamicParams.workerCountHistory = dynamicParams.workerCountHistory[1:]
	}

	return optimalCount
}

// Update dynamic system performance metrics
func updateSystemMetrics(cpuUsage, memoryUsage, throughput float64) {
	dynamicParams.mutex.Lock()
	defer dynamicParams.mutex.Unlock()

	dynamicParams.lastCPUUsage = cpuUsage
	dynamicParams.lastMemoryUsage = memoryUsage
	dynamicParams.lastThroughput = throughput
	dynamicParams.samplesCount++
}

// Get current system optimal parameter set
func GetOptimalParameters() (bufferSize, workerCount int) {
	// Get current optimal parameters
	bufferSize = adaptiveBufferSize(0)
	workerCount = adaptiveWorkerCount(0, bufferSize)
	return
}

// Get optimized Options for Stream encryption/decryption operations
func GetOptimizedStreamOptions() StreamOptions {
	bufferSize, workerCount := GetOptimalParameters()
	return StreamOptions{
		BufferSize:     bufferSize,
		UseParallel:    workerCount > 1,
		MaxWorkers:     workerCount,
		AdditionalData: nil,
		CollectStats:   false,
		CancelChan:     nil,
	}
}

// OptimizationInfo stores system optimization information and suggestions
type OptimizationInfo struct {
	// CPU architecture information
	Architecture     string
	NumCPUs          int
	HasAVX           bool
	HasAVX2          bool
	HasSSE41         bool
	HasNEON          bool
	EstimatedL1Cache int
	EstimatedL2Cache int
	EstimatedL3Cache int

	// Recommended system parameters
	RecommendedBufferSize int
	RecommendedWorkers    int
	ParallelThreshold     int

	// Performance statistics
	LastMeasuredThroughput float64
	SamplesCount           int
}

// GetSystemOptimizationInfo returns current system optimization information and suggestions
func GetSystemOptimizationInfo() *OptimizationInfo {
	// Get current CPU architecture
	arch := runtime.GOARCH

	// Get optimal parameters
	bufferSize, workerCount := GetOptimalParameters()

	// Build optimization information
	info := &OptimizationInfo{
		Architecture:     arch,
		NumCPUs:          runtime.NumCPU(),
		HasAVX:           cpuFeatures.hasAVX,
		HasAVX2:          cpuFeatures.hasAVX2,
		HasSSE41:         cpuFeatures.hasSSE41,
		HasNEON:          cpuFeatures.hasNEON,
		EstimatedL1Cache: cpuFeatures.l1CacheSize,
		EstimatedL2Cache: cpuFeatures.l2CacheSize,
		EstimatedL3Cache: cpuFeatures.l3CacheSize,

		RecommendedBufferSize: bufferSize,
		RecommendedWorkers:    workerCount,
		ParallelThreshold:     parallelThreshold,
	}

	// Get performance data
	dynamicParams.mutex.Lock()
	info.LastMeasuredThroughput = dynamicParams.lastThroughput
	info.SamplesCount = dynamicParams.samplesCount
	dynamicParams.mutex.Unlock()

	return info
}

// GetDefaultOptions returns default parameters based on system optimization
func GetDefaultOptions() StreamOptions {
	return GetOptimizedStreamOptions()
}

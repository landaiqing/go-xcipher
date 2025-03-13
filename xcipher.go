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

	"golang.org/x/crypto/chacha20poly1305"
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
	batchSize         = 8               // 批处理队列大小
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

// 获取指定容量的缓冲区，优先从对象池获取
func getBuffer(capacity int) []byte {
	// 小缓冲区直接从常规池获取
	if capacity <= poolBufferSize {
		buf := bufferPool.Get().([]byte)
		if cap(buf) >= capacity {
			return buf[:capacity]
		}
		bufferPool.Put(buf[:0]) // 返回太小的缓冲区
	} else if capacity <= largeBufferSize {
		// 大缓冲区从大缓冲池获取
		buf := largeBufferPool.Get().([]byte)
		if cap(buf) >= capacity {
			return buf[:capacity]
		}
		largeBufferPool.Put(buf[:0]) // 返回太小的缓冲区
	}

	// 池中没有足够大的缓冲区，创建新的
	return make([]byte, capacity)
}

// 返回缓冲区到适当的池
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
	// 超过大小的不放回池中
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

	// 检查是否超过阈值使用直接分配
	if len(data) > parallelThreshold {
		return x.encryptDirect(data, additionalData)
	}

	// 使用新的缓冲区池函数获取缓冲区
	requiredCapacity := nonceSize + len(data) + x.overhead
	buf := getBuffer(nonceSize) // 先获取nonceSize大小的缓冲区
	defer func() {
		// 如果发生错误，确保缓冲区被返回到池中
		if len(buf) == nonceSize {
			putBuffer(buf)
		}
	}()

	// 生成随机nonce
	if _, err := rand.Read(buf); err != nil {
		return nil, ErrNonceGeneration
	}

	// 扩展缓冲区以容纳加密数据
	if cap(buf) < requiredCapacity {
		// 当前缓冲区太小，获取一个更大的
		oldBuf := buf
		buf = make([]byte, nonceSize, requiredCapacity)
		copy(buf, oldBuf)
		putBuffer(oldBuf) // 返回旧缓冲区到池中
	}

	// 使用优化的AEAD.Seal调用
	result := x.aead.Seal(buf, buf[:nonceSize], data, additionalData)
	return result, nil
}

func (x *XCipher) encryptDirect(data, additionalData []byte) ([]byte, error) {
	// 预分配nonce缓冲区
	nonce := getBuffer(nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		putBuffer(nonce)
		return nil, ErrNonceGeneration
	}

	// 预分配足够大的ciphertext缓冲区
	ciphertext := make([]byte, nonceSize+len(data)+x.overhead)
	copy(ciphertext, nonce)
	putBuffer(nonce) // 不再需要单独的nonce缓冲区

	// 直接在目标缓冲区上执行加密操作
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

	// 估算明文大小并预分配缓冲区
	plaintextSize := len(data) - x.overhead
	if plaintextSize <= 0 {
		return nil, ErrCiphertextShort
	}

	// 对于小数据，使用内存池 - 但不重用输入缓冲区，避免重叠
	if plaintextSize <= largeBufferSize {
		// 注意：这里我们总是创建一个新的缓冲区用于结果
		// 而不是尝试在输入缓冲区上原地解密，这会导致缓冲区重叠错误
		resultBuf := make([]byte, 0, plaintextSize)
		plaintext, err := x.aead.Open(resultBuf, nonce, data, additionalData)
		if err != nil {
			return nil, ErrAuthenticationFailed
		}
		return plaintext, nil
	}

	// 对于大数据，直接分配并返回
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
	// 自动检测是否应该使用并行处理
	if options.UseParallel == false && options.BufferSize >= parallelThreshold/2 {
		// 如果缓冲区很大但未启用并行，自动启用
		options.UseParallel = true
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = calculateOptimalWorkers(options.BufferSize, maxWorkers)
		}
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
				}
				if stats.BlocksProcessed > 0 {
					stats.AvgBlockSize = float64(stats.BytesProcessed) / float64(stats.BlocksProcessed)
				}
			}
		}()
	}

	// Validate and adjust options
	if options.BufferSize <= 0 {
		options.BufferSize = streamBufferSize
	} else if options.BufferSize < minBufferSize {
		return stats, fmt.Errorf("%w: %d is less than minimum %d",
			ErrBufferSizeTooSmall, options.BufferSize, minBufferSize)
	} else if options.BufferSize > maxBufferSize {
		return stats, fmt.Errorf("%w: %d is greater than maximum %d",
			ErrBufferSizeTooLarge, options.BufferSize, maxBufferSize)
	}

	if options.UseParallel {
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = maxWorkers
		} else if options.MaxWorkers > runtime.NumCPU()*2 {
			log.Printf("Warning: Number of worker threads %d exceeds twice the number of CPU cores (%d)",
				options.MaxWorkers, runtime.NumCPU()*2)
		}

		// Use parallel implementation
		return x.encryptStreamParallelWithOptions(reader, writer, options, stats)
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
	}

	// Write nonce first
	if _, err := writer.Write(nonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	// Get buffer from memory pool or create a new one
	var buffer []byte
	var sealed []byte

	// Check if buffer in memory pool is large enough
	bufFromPool := bufferPool.Get().([]byte)
	if cap(bufFromPool) >= options.BufferSize {
		buffer = bufFromPool[:options.BufferSize]
	} else {
		bufferPool.Put(bufFromPool[:0]) // Return buffer that's not large enough
		buffer = make([]byte, options.BufferSize)
	}
	defer bufferPool.Put(buffer[:0])

	// Allocate ciphertext buffer
	sealed = make([]byte, 0, options.BufferSize+x.overhead)

	// Use counter to track block sequence
	var counter uint64 = 0
	var bytesProcessed int64 = 0
	var blocksProcessed = 0

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
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Update statistics
			bytesProcessed += int64(n)
			blocksProcessed++

			// Update nonce - use counter
			binary.LittleEndian.PutUint64(nonce, counter)
			counter++

			// Encrypt data block
			encrypted := x.aead.Seal(sealed[:0], nonce, buffer[:n], options.AdditionalData)

			// Write encrypted data
			if _, err := writer.Write(encrypted); err != nil {
				return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
		}

		if err == io.EOF {
			break
		}
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
	// Generate random base nonce
	baseNonce := make([]byte, nonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return stats, ErrNonceGeneration
	}

	// Write base nonce first
	if _, err := writer.Write(baseNonce); err != nil {
		return stats, fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	// Set the number of worker threads, not exceeding CPU count and option limit
	workers := runtime.NumCPU()
	if workers > options.MaxWorkers {
		workers = options.MaxWorkers
	}

	// 调整作业队列大小以减少争用，使用更大的值
	workerQueueSize := workers * 4

	// Create worker pool
	jobs := make(chan job, workerQueueSize)
	results := make(chan result, workerQueueSize)
	errorsChannel := make(chan error, 1)
	var wg sync.WaitGroup

	// 预先分配一个一致的位置用于存储已处理的结果
	var bytesProcessed int64 = 0
	var blocksProcessed = 0

	// Start worker threads
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 每个工作线程预分配自己的加密缓冲区，避免每次分配
			encBuf := make([]byte, 0, options.BufferSize+x.overhead)

			for job := range jobs {
				// Create unique nonce for each block
				blockNonce := make([]byte, nonceSize)
				copy(blockNonce, baseNonce)
				binary.LittleEndian.PutUint64(blockNonce, job.id)

				// Encrypt data block - 重用预分配的缓冲区而不是每次创建新的
				encrypted := x.aead.Seal(encBuf[:0], blockNonce, job.data, options.AdditionalData)

				// 把数据复制到中间结果，避免缓冲区被后续操作覆盖
				resultData := getBuffer(len(encrypted))
				copy(resultData, encrypted)

				// Send result
				results <- result{
					id:   job.id,
					data: resultData,
				}

				// 完成后释放缓冲区
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

			// Write results in order
			for {
				if data, ok := pendingResults[nextID]; ok {
					// Write block size
					sizeBytes := make([]byte, 4)
					binary.LittleEndian.PutUint32(sizeBytes, uint32(len(data)))
					if _, err := writer.Write(sizeBytes); err != nil {
						errorsChannel <- fmt.Errorf("%w: %v", ErrWriteFailed, err)
						return
					}

					// Write data
					if _, err := writer.Write(data); err != nil {
						errorsChannel <- fmt.Errorf("%w: %v", ErrWriteFailed, err)
						return
					}

					// 更新统计数据
					if stats != nil {
						bytesProcessed += int64(len(data))
						blocksProcessed++
					}

					// 返回缓冲区到池中
					putBuffer(data)
					delete(pendingResults, nextID)
					nextID++
				} else {
					break
				}
			}
		}
		close(resultsDone) // Signal that result processing is complete
	}()

	// Read and assign work
	buffer := getBuffer(options.BufferSize)
	defer putBuffer(buffer)
	var jobID uint64 = 0

	// 添加批处理机制，减少通道争用
	const batchSize = 16 // 根据实际情况调整
	dataBatch := make([][]byte, 0, batchSize)
	idBatch := make([]uint64, 0, batchSize)

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

		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Copy data to prevent overwriting
			data := getBuffer(n)
			copy(data, buffer[:n])

			// 添加到批次
			dataBatch = append(dataBatch, data)
			idBatch = append(idBatch, jobID)
			jobID++

			// 当批次满了或到达EOF时发送
			if len(dataBatch) >= batchSize || err == io.EOF {
				for i := range dataBatch {
					// Send work
					select {
					case jobs <- job{
						id:   idBatch[i],
						data: dataBatch[i],
					}:
					case <-options.CancelChan:
						// 被取消的情况下清理资源
						for _, d := range dataBatch {
							putBuffer(d)
						}
						return stats, ErrOperationCancelled
					}
				}
				// 清空批次
				dataBatch = dataBatch[:0]
				idBatch = idBatch[:0]
			}
		}

		if err == io.EOF {
			break
		}
	}

	// 发送剩余批次
	for i := range dataBatch {
		jobs <- job{
			id:   idBatch[i],
			data: dataBatch[i],
		}
	}

	// Close jobs channel and wait for all workers to complete
	close(jobs)
	wg.Wait()

	// Close results channel after all work is done
	close(results)

	// Wait for result processing to complete
	<-resultsDone

	// 更新统计信息
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
	// 自动检测是否应该使用并行处理
	if options.UseParallel == false && options.BufferSize >= parallelThreshold/2 {
		// 如果缓冲区很大但未启用并行，自动启用
		options.UseParallel = true
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = calculateOptimalWorkers(options.BufferSize, maxWorkers)
		}
	}

	// Validate and adjust options, similar to encryption
	if options.BufferSize <= 0 {
		options.BufferSize = streamBufferSize
	} else if options.BufferSize < minBufferSize {
		options.BufferSize = minBufferSize
	} else if options.BufferSize > maxBufferSize {
		options.BufferSize = maxBufferSize
	}

	if options.UseParallel {
		if options.MaxWorkers <= 0 {
			options.MaxWorkers = maxWorkers
		}
		// Use parallel implementation
		return x.decryptStreamParallelWithOptions(reader, writer, options)
	}

	// Read nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: failed to read nonce: %v", ErrReadFailed, err)
	}

	// Get buffer from memory pool or create a new one
	var encBuffer []byte
	var decBuffer []byte

	// Check if buffer in memory pool is large enough
	bufFromPool := bufferPool.Get().([]byte)
	if cap(bufFromPool) >= options.BufferSize+x.overhead {
		encBuffer = bufFromPool[:options.BufferSize+x.overhead]
	} else {
		bufferPool.Put(bufFromPool[:0]) // Return buffer that's not large enough
		encBuffer = make([]byte, options.BufferSize+x.overhead)
	}
	defer bufferPool.Put(encBuffer[:0])

	// Allocate decryption buffer
	decBuffer = make([]byte, 0, options.BufferSize)

	// Use counter to track block sequence
	var counter uint64 = 0

	for {
		// Read encrypted data
		n, err := reader.Read(encBuffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Update nonce - use counter
			binary.LittleEndian.PutUint64(nonce, counter)
			counter++

			// Decrypt data block
			decrypted, err := x.aead.Open(decBuffer[:0], nonce, encBuffer[:n], options.AdditionalData)
			if err != nil {
				return nil, ErrAuthenticationFailed
			}

			// Write decrypted data
			if _, err := writer.Write(decrypted); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
		}

		if err == io.EOF {
			break
		}
	}

	return nil, nil
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

	// Read base nonce
	baseNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, baseNonce); err != nil {
		return stats, fmt.Errorf("%w: failed to read nonce: %v", ErrReadFailed, err)
	}

	// Set the number of worker threads - 使用优化的工作线程计算
	workers := calculateOptimalWorkers(options.BufferSize, options.MaxWorkers)

	// 调整作业队列大小以减少争用
	workerQueueSize := workers * 4

	// Create worker pool
	jobs := make(chan job, workerQueueSize)
	results := make(chan result, workerQueueSize)
	errorsChannel := make(chan error, 1)
	var wg sync.WaitGroup

	// Start worker threads
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 每个工作线程预分配自己的解密缓冲区，避免每次分配
			decBuf := make([]byte, 0, options.BufferSize)

			for job := range jobs {
				// Create unique nonce for each block
				blockNonce := make([]byte, nonceSize)
				copy(blockNonce, baseNonce)
				binary.LittleEndian.PutUint64(blockNonce, job.id)

				// Decrypt data block
				decrypted, err := x.aead.Open(decBuf[:0], blockNonce, job.data, options.AdditionalData)
				if err != nil {
					select {
					case errorsChannel <- ErrAuthenticationFailed:
					default:
						// If an error is already sent, don't send another one
					}
					putBuffer(job.data) // 释放缓冲区
					continue            // Continue processing other blocks instead of returning immediately
				}

				// 把数据复制到中间结果，避免缓冲区被后续操作覆盖
				resultData := getBuffer(len(decrypted))
				copy(resultData, decrypted)

				// Send result
				results <- result{
					id:   job.id,
					data: resultData,
				}

				// 释放输入缓冲区
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

			// Write results in order
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

					// 返回缓冲区到池中
					putBuffer(data)
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

	// 添加批处理机制，减少通道争用
	dataBatch := make([][]byte, 0, batchSize)
	idBatch := make([]uint64, 0, batchSize)

	for {
		// Check cancel signal
		if options.CancelChan != nil {
			select {
			case <-options.CancelChan:
				// 优雅地处理取消
				close(jobs)
				wg.Wait()
				close(results)
				<-resultsDone
				return stats, ErrOperationCancelled
			default:
				// Continue processing
			}
		}

		// Read block size
		_, err := io.ReadFull(reader, sizeBytes)
		if err != nil {
			if err == io.EOF {
				break
			}
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		blockSize := binary.LittleEndian.Uint32(sizeBytes)
		encryptedBlock := getBuffer(int(blockSize))

		// Read encrypted data block
		_, err = io.ReadFull(reader, encryptedBlock)
		if err != nil {
			putBuffer(encryptedBlock) // 释放缓冲区
			return stats, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		// 添加到批次
		dataBatch = append(dataBatch, encryptedBlock)
		idBatch = append(idBatch, jobID)
		jobID++

		// 当批次满了时发送
		if len(dataBatch) >= batchSize {
			for i := range dataBatch {
				select {
				case jobs <- job{
					id:   idBatch[i],
					data: dataBatch[i],
				}:
				case <-options.CancelChan:
					// 被取消的情况下清理资源
					for _, d := range dataBatch {
						putBuffer(d)
					}
					return stats, ErrOperationCancelled
				}
			}
			// 清空批次
			dataBatch = dataBatch[:0]
			idBatch = idBatch[:0]
		}
	}

	// 发送剩余批次
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

// 新增函数 - 优化的工作线程数目计算
func calculateOptimalWorkers(dataSize int, maxWorkers int) int {
	cpuCount := runtime.NumCPU()

	// 对于小数据量，使用较少的工作线程
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

	// 对于大数据量，使用更多工作线程但不超过CPU数
	workers := cpuCount
	if workers > maxWorkers {
		return maxWorkers
	}
	return workers
}

// 新增函数 - 计算最佳的缓冲区大小
func calculateOptimalBufferSize(options StreamOptions) int {
	// 检查用户指定的缓冲区大小
	if options.BufferSize > 0 {
		if options.BufferSize < minBufferSize {
			return minBufferSize
		}
		if options.BufferSize > maxBufferSize {
			return maxBufferSize
		}
		return options.BufferSize
	}

	// 未指定时使用默认值
	return optimalBlockSize
}

# go-xcipher

<div align="center">

<img src="golang_logo.png" alt="go-xcipher Logo" height="150">

[![Go Reference](https://pkg.go.dev/badge/github.com/landaiqing/go-xcipher.svg)](https://pkg.go.dev/github.com/landaiqing/go-xcipher)
[![Go Report Card](https://goreportcard.com/badge/github.com/landaiqing/go-xcipher)](https://goreportcard.com/report/github.com/landaiqing/go-xcipher)
[![License](https://img.shields.io/github/license/landaiqing/go-xcipher.svg)](LICENSE)
[![Release](https://img.shields.io/github/release/landaiqing/go-xcipher.svg)](https://github.com/landaiqing/go-xcipher/releases/latest)

</div>

[中文文档](README_CN.md) | English

## Project Overview

go-xcipher is a high-performance, easy-to-use Go encryption library based on the ChaCha20-Poly1305 algorithm that provides secure data encryption and decryption. The library is specially optimized for handling large files and data streams, supporting parallel encryption/decryption, memory optimization, and cancellable operations.

## ✨ Features

- 🔒 High-strength encryption using the proven ChaCha20-Poly1305 algorithm
- 🚀 Performance optimized for large data and streaming data
- 🧵 Automatic parallel processing for large datasets to increase throughput
- 📊 Detailed statistics for performance monitoring and optimization
- 🧠 Intelligent memory management to reduce memory allocation and GC pressure
- ⏹️ Support for cancellable operations suitable for long-running tasks
- 🛡️ Comprehensive error handling and security checks
- 🖥️ CPU architecture-aware optimizations that automatically adjust parameters for different hardware platforms

## 🔧 Installation

```bash
go get -u github.com/landaiqing/go-xcipher
```

Ensure you are using Go 1.18 or higher.

## 📝 Usage Examples

### Simple Encryption/Decryption

```go
package main

import (
    "fmt"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a 32-byte key (this is just an example; in real applications, keys should be securely generated and stored)
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Data to encrypt
    plaintext := []byte("sensitive data")
    
    // Optional additional authenticated data
    additionalData := []byte("header")
    
    // Encrypt
    ciphertext, err := cipher.Encrypt(plaintext, additionalData)
    if err != nil {
        panic(err)
    }
    
    // Decrypt
    decrypted, err := cipher.Decrypt(ciphertext, additionalData)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Decrypted:", string(decrypted))
}
```

### Stream Encryption (Basic Usage)

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a key
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Open the file to encrypt
    inputFile, _ := os.Open("largefile.dat")
    defer inputFile.Close()
    
    // Create the output file
    outputFile, _ := os.Create("largefile.encrypted")
    defer outputFile.Close()
    
    // Encrypt stream with default options
    err := cipher.EncryptStream(inputFile, outputFile, nil)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("File encryption completed")
}
```

### Parallel Processing for Large Files

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a key
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Open the file to encrypt
    inputFile, _ := os.Open("largefile.dat")
    defer inputFile.Close()
    
    // Create the output file
    outputFile, _ := os.Create("largefile.encrypted")
    defer outputFile.Close()
    
    // Set stream options - enable parallel processing
    options := xcipher.DefaultStreamOptions()
    options.UseParallel = true       // Enable parallel processing
    options.MaxWorkers = 8           // Set maximum worker threads
    options.BufferSize = 256 * 1024  // Set larger buffer size
    options.CollectStats = true      // Collect performance statistics
    
    // Encrypt stream
    stats, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
    if err != nil {
        panic(err)
    }
    
    // Display performance statistics
    fmt.Printf("Processing time: %v\n", stats.Duration())
    fmt.Printf("Throughput: %.2f MB/s\n", stats.Throughput)
    fmt.Printf("Parallel processing: %v, Worker count: %d\n", stats.ParallelProcessing, stats.WorkerCount)
    fmt.Printf("Data processed: %.2f MB\n", float64(stats.BytesProcessed) / 1024 / 1024)
    fmt.Printf("Blocks processed: %d, Average block size: %.2f KB\n", stats.BlocksProcessed, stats.AvgBlockSize / 1024)
}
```

### Using Adaptive Parameter Optimization

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a key
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Open the file to encrypt
    inputFile, _ := os.Open("largefile.dat")
    defer inputFile.Close()
    
    // Create the output file
    outputFile, _ := os.Create("largefile.encrypted")
    defer outputFile.Close()
    
    // Get optimized stream options - automatically selects best parameters based on system environment
    options := xcipher.GetOptimizedStreamOptions()
    options.CollectStats = true
    
    // View system optimization information
    sysInfo := xcipher.GetSystemOptimizationInfo()
    fmt.Printf("CPU architecture: %s, Core count: %d\n", sysInfo.Architecture, sysInfo.NumCPUs)
    fmt.Printf("AVX support: %v, AVX2 support: %v\n", sysInfo.HasAVX, sysInfo.HasAVX2)
    fmt.Printf("Recommended buffer size: %d KB\n", sysInfo.RecommendedBufferSize / 1024)
    fmt.Printf("Recommended worker count: %d\n", sysInfo.RecommendedWorkers)
    
    // Encrypt stream
    stats, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
    if err != nil {
        panic(err)
    }
    
    // Display performance statistics
    fmt.Printf("Processing time: %v\n", stats.Duration())
    fmt.Printf("Throughput: %.2f MB/s\n", stats.Throughput)
}
```

### Cancellable Long-Running Operations

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a key
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Open the file to encrypt
    inputFile, _ := os.Open("very_large_file.dat")
    defer inputFile.Close()
    
    // Create the output file
    outputFile, _ := os.Create("very_large_file.encrypted")
    defer outputFile.Close()
    
    // Create cancellable context
    ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
    defer cancel() // Ensure resources are released
    
    // Set stream options with cancellation support
    options := xcipher.DefaultStreamOptions()
    options.UseParallel = true
    options.CancelChan = ctx.Done() // Set cancel signal
    
    // Perform encryption in a separate goroutine
    resultChan := make(chan error, 1)
    go func() {
        _, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
        resultChan <- err
    }()
    
    // Wait for result or timeout
    select {
    case err := <-resultChan:
        if err != nil {
            fmt.Printf("Encryption error: %v\n", err)
        } else {
            fmt.Println("Encryption completed successfully")
        }
    case <-ctx.Done():
        fmt.Println("Operation timed out or was cancelled")
        // Wait for operation to actually stop
        err := <-resultChan
        fmt.Printf("Result after cancellation: %v\n", err)
    }
}
```

### Memory Buffer Processing Example

```go
package main

import (
    "bytes"
    "fmt"
    "io"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Create a key
    key := make([]byte, chacha20poly1305.KeySize)
    
    // Initialize the cipher
    cipher := xcipher.NewXCipher(key)
    
    // Prepare data to encrypt
    data := []byte("This is some sensitive data to encrypt, using memory buffers instead of files for processing")
    
    // Create source reader and destination writer
    source := bytes.NewReader(data)
    var encrypted bytes.Buffer
    
    // Encrypt data
    if err := cipher.EncryptStream(source, &encrypted, nil); err != nil {
        panic(err)
    }
    
    fmt.Printf("Original data size: %d bytes\n", len(data))
    fmt.Printf("Encrypted size: %d bytes\n", encrypted.Len())
    
    // Decrypt data
    var decrypted bytes.Buffer
    if err := cipher.DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, nil); err != nil {
        panic(err)
    }
    
    fmt.Printf("Decrypted size: %d bytes\n", decrypted.Len())
    fmt.Printf("Decrypted content: %s\n", decrypted.String())
}
```

## 📋 API Documentation

### Core Types

```go
type XCipher struct {
    // Fields unexported
}

// Statistics for stream processing
type StreamStats struct {
    StartTime time.Time          // Start time
    EndTime time.Time            // End time
    BytesProcessed int64         // Number of bytes processed
    BlocksProcessed int          // Number of blocks processed
    AvgBlockSize float64         // Average block size
    Throughput float64           // Throughput (MB/s)
    ParallelProcessing bool      // Whether parallel processing was used
    WorkerCount int              // Number of worker threads
    BufferSize int               // Buffer size
}

// Stream processing options
type StreamOptions struct {
    BufferSize int               // Buffer size
    UseParallel bool             // Whether to use parallel processing
    MaxWorkers int               // Maximum number of worker threads
    AdditionalData []byte        // Additional authenticated data
    CollectStats bool            // Whether to collect performance statistics
    CancelChan <-chan struct{}   // Cancellation signal channel
}

// System optimization information
type OptimizationInfo struct {
    Architecture string          // CPU architecture
    NumCPUs int                  // Number of CPU cores
    HasAVX bool                  // Whether AVX instruction set is supported
    HasAVX2 bool                 // Whether AVX2 instruction set is supported
    HasSSE41 bool                // Whether SSE4.1 instruction set is supported
    HasNEON bool                 // Whether ARM NEON instruction set is supported
    EstimatedL1Cache int         // Estimated L1 cache size
    EstimatedL2Cache int         // Estimated L2 cache size
    EstimatedL3Cache int         // Estimated L3 cache size
    RecommendedBufferSize int    // Recommended buffer size
    RecommendedWorkers int       // Recommended worker thread count
    ParallelThreshold int        // Parallel processing threshold
    LastMeasuredThroughput float64 // Last measured throughput
    SamplesCount int             // Sample count
}
```

### Main Functions and Methods

- `NewXCipher(key []byte) *XCipher` - Create a new cipher instance
- `(x *XCipher) Encrypt(data, additionalData []byte) ([]byte, error)` - Encrypt data
- `(x *XCipher) Decrypt(cipherData, additionalData []byte) ([]byte, error)` - Decrypt data
- `(x *XCipher) EncryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error` - Encrypt a stream with default options
- `(x *XCipher) DecryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error` - Decrypt a stream with default options
- `(x *XCipher) EncryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error)` - Encrypt a stream with custom options
- `(x *XCipher) DecryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error)` - Decrypt a stream with custom options
- `DefaultStreamOptions() StreamOptions` - Get default stream processing options
- `GetOptimizedStreamOptions() StreamOptions` - Get optimized stream options (automatically adapted to the current system)
- `GetSystemOptimizationInfo() *OptimizationInfo` - Get system optimization information

## 🧪 Testing and Benchmarks

### Running Unit Tests

```bash
# Run all tests
go test

# Run all tests with verbose output
go test -v

# Run a specific test
go test -run TestStreamParallelProcessing

# Run a specific test group
go test -run TestStream
```

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=.

# Run a specific benchmark
go test -bench=BenchmarkEncrypt

# Run stream performance matrix benchmark
go test -bench=BenchmarkStreamPerformanceMatrix

# Run benchmarks with memory allocation statistics
go test -bench=. -benchmem

# Run multiple times for more accurate results
go test -bench=. -count=5
```

### Performance Profiling

```bash
# CPU profiling
go test -bench=BenchmarkStreamPerformanceMatrix -cpuprofile=cpu.prof

# Memory profiling
go test -bench=BenchmarkStreamPerformanceMatrix -memprofile=mem.prof

# View profiling results with pprof
go tool pprof cpu.prof
go tool pprof mem.prof
```

## 🚀 Performance Optimization Highlights

go-xcipher is optimized in multiple ways to handle data of various scales, from small messages to large files. Here are the main optimization highlights:

### Adaptive Parameter Optimization
- Automatically adjusts buffer size and worker thread count based on CPU architecture and system characteristics
- Dynamically adjusts parameters at runtime based on data processing characteristics for optimal performance
- Specialized optimizations for different instruction sets (AVX, AVX2, SSE4.1, NEON)

### Efficient Parallel Processing
- Smart decision-making on when to use parallel processing, avoiding overhead for small data
- Worker thread allocation optimized based on CPU cores and cache characteristics
- Uses worker pools and task queues to reduce thread creation/destruction overhead
- Automatic data block balancing ensures even workload distribution among threads

### Memory Optimization
- Zero-copy techniques reduce memory data copying operations
- Memory buffer pooling significantly reduces GC pressure
- Batch processing and write buffering reduce system call frequency
- Buffer size optimized according to L1/L2/L3 cache characteristics for improved cache hit rates

### Performance Data
- Small data packet encryption: ~1.5 GB/s
- Large file parallel encryption: ~4.0 GB/s (depending on CPU cores and hardware)
- Memory efficiency: Memory usage remains stable when processing large files, avoiding OOM risks
- Benchmark results show 2-10x speed improvement over standard library implementations (depending on data size and processing method)

## 🤝 Contributing

Issues and Pull Requests are welcome to help improve go-xcipher. You can contribute by:

1. Reporting bugs
2. Submitting feature requests
3. Submitting code improvements
4. Improving documentation

## 📜 License

go-xcipher is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.


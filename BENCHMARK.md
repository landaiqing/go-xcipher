# go-xcipher Performance Benchmark Guide

[中文版本](BENCHMARK_CN.md)

This document provides guidelines for running performance benchmarks of the go-xcipher library and interpreting the test results.

## Test Overview

These benchmarks aim to comprehensively compare the performance of the go-xcipher library with the encryption functions in the Go standard library. The tests include:

1. Basic encryption/decryption performance tests
2. Stream encryption/decryption performance tests
3. Multi-core scaling performance tests
4. Hardware acceleration performance tests
5. Memory usage efficiency tests
6. Performance matrix tests for different algorithms and data sizes

## Running Tests

You can run the complete benchmark suite using:

```bash
go test -bench=Benchmark -benchmem -benchtime=3s
```

Or run specific tests:

```bash
# Basic encryption performance test
go test -bench=BenchmarkCompareEncrypt -benchmem

# Basic decryption performance test
go test -bench=BenchmarkCompareDecrypt -benchmem

# Stream encryption performance test
go test -bench=BenchmarkCompareStreamEncrypt -benchmem

# Stream decryption performance test
go test -bench=BenchmarkCompareStreamDecrypt -benchmem

# Multi-core scaling performance test
go test -bench=BenchmarkMultiCoreScaling -benchmem

# Hardware acceleration performance test
go test -bench=BenchmarkHardwareAcceleration -benchmem

# Memory usage efficiency test
go test -bench=BenchmarkMemoryUsage -benchmem

# Performance matrix test
go test -bench=BenchmarkPerformanceMatrix -benchmem
```

Get test guide and system information:

```bash
go test -run=TestPrintBenchmarkGuide
```

## Test Files Description

### 1. xcipher_bench_test.go

This file contains basic performance benchmarks, including:

- Encryption/decryption performance tests for different data sizes
- Stream encryption/decryption performance tests
- Parallel vs serial processing performance comparison
- Performance tests with different buffer sizes
- Impact of worker thread count on performance
- File vs memory operation performance comparison
- Zero-copy vs copy operation performance comparison
- Adaptive parameter performance tests
- CPU architecture optimization performance tests

### 2. stdlib_comparison_test.go

This file contains performance comparison tests with the standard library, including:

- Performance comparison with standard library ChaCha20Poly1305
- Performance comparison with AES-GCM
- Stream encryption/decryption performance comparison
- Multi-core scaling tests
- Hardware acceleration performance tests
- Memory usage efficiency tests
- Performance matrix tests

### 3. stability_test.go

This file contains stability tests, including:

- Long-running stability tests
- Concurrent load tests
- Fault tolerance tests
- Resource constraint tests
- Large data processing tests
- Error handling tests

## Interpreting Test Results

Benchmark results typically have the following format:

```
BenchmarkName-NumCPU    iterations    time/op    B/op    allocs/op
```

Where:
- `BenchmarkName`: Test name
- `NumCPU`: Number of CPU cores used in the test
- `iterations`: Number of iterations
- `time/op`: Time per operation
- `B/op`: Bytes allocated per operation
- `allocs/op`: Number of memory allocations per operation

### Performance Evaluation Criteria

1. **Throughput (B/s)**: The `B/s` value in the test report indicates bytes processed per second, higher values indicate better performance.
2. **Latency (ns/op)**: Average time per operation, lower values indicate better performance.
3. **Memory Usage (B/op)**: Bytes allocated per operation, lower values indicate better memory efficiency.
4. **Memory Allocations (allocs/op)**: Number of memory allocations per operation, lower values indicate less GC pressure.

### Key Performance Metrics Interpretation

1. **Small Data Performance**: For small data (1KB-4KB), low latency (low ns/op) is the key metric.
2. **Large Data Performance**: For large data (1MB+), high throughput (high B/s) is the key metric.
3. **Parallel Scalability**: The ratio of performance improvement as CPU cores increase reflects parallel scaling capability.

## Key Performance Comparisons

### XCipher vs Standard Library ChaCha20Poly1305

This comparison reflects the performance differences between XCipher's optimized ChaCha20Poly1305 implementation and the standard library implementation. XCipher should show advantages in:

1. Large data encryption/decryption throughput
2. Multi-core parallel processing capability
3. Memory usage efficiency
4. Real-time stream processing capability

### XCipher vs AES-GCM

This comparison reflects performance differences between different encryption algorithms. On modern CPUs (especially those supporting AES-NI instruction set), AES-GCM may perform better in some cases, but ChaCha20Poly1305 shows more consistent performance across different hardware platforms.

## Influencing Factors

Test results may be affected by:

1. CPU architecture and instruction set support (AVX2, AVX, SSE4.1, NEON, AES-NI)
2. Operating system scheduling and I/O state
3. Go runtime version
4. Other programs running simultaneously

## Special Test Descriptions

### Multi-core Scalability Test

This test demonstrates parallel processing capability by gradually increasing the number of CPU cores used. Ideally, performance should increase linearly with the number of cores.

### Stream Processing Tests

These tests simulate real-world stream data encryption/decryption scenarios by processing data in chunks. This is particularly important for handling large files or network traffic.

### Hardware Acceleration Test

This test shows performance comparisons of various algorithms on CPUs with specific hardware acceleration features (e.g., AVX2, AES-NI).

## Result Analysis Example

Here's a simplified result analysis example:

```
BenchmarkCompareEncrypt/XCipher_Medium_64KB-8         10000       120000 ns/op     545.33 MB/s    65536 B/op       1 allocs/op
BenchmarkCompareEncrypt/StdChaCha20Poly1305_Medium_64KB-8   8000       150000 ns/op     436.27 MB/s    131072 B/op      2 allocs/op
```

Analysis:
- XCipher processes 64KB data about 25% faster than the standard library (120000 ns/op vs 150000 ns/op)
- XCipher's memory allocation is half that of the standard library (65536 B/op vs 131072 B/op)
- XCipher has fewer memory allocations than the standard library (1 allocs/op vs 2 allocs/op)

## Continuous Optimization

Benchmarks are an important tool for continuously optimizing library performance. By regularly running these tests, you can detect performance regressions and guide further optimization work. 
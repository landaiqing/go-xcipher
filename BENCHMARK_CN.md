# go-xcipher 性能基准测试指南

[English Version](BENCHMARK.md)

本文档提供了如何运行 go-xcipher 库性能基准测试的指南，以及如何解读测试结果的说明。

## 测试概述

这些基准测试旨在全面比较 go-xcipher 库与 Go 标准库中的加密功能的性能。测试包括：

1. 基本加密/解密性能测试
2. 流式加密/解密性能测试
3. 多核心扩展性能测试
4. 硬件加速性能测试
5. 内存使用效率测试
6. 不同算法和数据大小的性能矩阵测试

## 运行测试

可以使用以下命令运行完整的基准测试：

```bash
go test -bench=Benchmark -benchmem -benchtime=3s
```

或者运行特定的测试：

```bash
# 基本加密性能测试
go test -bench=BenchmarkCompareEncrypt -benchmem

# 基本解密性能测试
go test -bench=BenchmarkCompareDecrypt -benchmem

# 流式加密性能测试
go test -bench=BenchmarkCompareStreamEncrypt -benchmem

# 流式解密性能测试
go test -bench=BenchmarkCompareStreamDecrypt -benchmem

# 多核心扩展性能测试
go test -bench=BenchmarkMultiCoreScaling -benchmem

# 硬件加速性能测试
go test -bench=BenchmarkHardwareAcceleration -benchmem

# 内存使用效率测试
go test -bench=BenchmarkMemoryUsage -benchmem

# 性能矩阵测试
go test -bench=BenchmarkPerformanceMatrix -benchmem
```

获取测试指南和系统信息：

```bash
go test -run=TestPrintBenchmarkGuide
```

## 测试文件说明

### 1. xcipher_bench_test.go

该文件包含基本的性能基准测试，包括：

- 不同数据大小的加密/解密性能测试
- 流式加密/解密性能测试
- 并行与串行处理性能对比
- 不同缓冲区大小的性能测试
- 工作线程数量对性能的影响
- 文件与内存操作的性能对比
- 零拷贝与复制操作的性能对比
- 自适应参数性能测试
- CPU架构优化性能测试

### 2. stdlib_comparison_test.go

该文件包含与标准库的性能对比测试，包括：

- 与标准库 ChaCha20Poly1305 的性能对比
- 与 AES-GCM 的性能对比
- 流式加密/解密性能对比
- 多核心扩展性测试
- 硬件加速性能测试
- 内存使用效率测试
- 性能矩阵测试

### 3. stability_test.go

该文件包含稳定性测试，包括：

- 长时间运行稳定性测试
- 并发负载测试
- 故障容错测试
- 资源约束测试
- 大数据处理测试
- 错误处理测试

## 解读测试结果

基准测试结果通常具有以下格式：

```
BenchmarkName-NumCPU    iterations    time/op    B/op    allocs/op
```

其中：
- `BenchmarkName`：测试名称
- `NumCPU`：测试使用的 CPU 核心数
- `iterations`：运行次数
- `time/op`：每次操作的时间
- `B/op`：每次操作分配的字节数
- `allocs/op`：每次操作的内存分配次数

### 性能评估标准

1. **吞吐量 (B/s)**：测试报告中的 `B/s` 值表示每秒处理的字节数，数值越高表示性能越好。
2. **延迟 (ns/op)**：每次操作的平均时间，数值越低表示性能越好。
3. **内存使用 (B/op)**：每次操作分配的内存量，数值越低表示内存效率越高。
4. **内存分配 (allocs/op)**：每次操作的内存分配次数，数值越低表示 GC 压力越小。

### 重要性能指标解读

1. **小数据性能**：对于 1KB-4KB 的小数据，低延迟（低 ns/op）是关键指标。
2. **大数据性能**：对于 1MB+ 的大数据，高吞吐量（高 B/s）是关键指标。
3. **并行扩展性**：随着 CPU 核心数增加，性能提升的比例反映并行扩展能力。

## 性能比较重点

### XCipher vs 标准库 ChaCha20Poly1305

这个比较反映了 XCipher 优化后的 ChaCha20Poly1305 实现与标准库实现的性能差异。XCipher 应该在以下方面表现出优势：

1. 大数据加密/解密吞吐量
2. 多核心并行处理能力
3. 内存使用效率
4. 实时流处理能力

### XCipher vs AES-GCM

这个比较反映了不同加密算法之间的性能差异。在现代 CPU（特别是支持 AES-NI 指令集的CPU）上，AES-GCM 可能在某些情况下性能更好，但 ChaCha20Poly1305 在不同硬件平台上表现更一致。

## 影响因素

测试结果可能受以下因素影响：

1. CPU 架构和指令集支持（AVX2, AVX, SSE4.1, NEON, AES-NI）
2. 操作系统调度和 I/O 状态
3. Go 运行时版本
4. 同时运行的其他程序

## 特殊测试说明

### 多核心扩展性测试

这个测试通过逐步增加使用的 CPU 核心数，展示并行处理能力。理想情况下，性能应该随着核心数的增加而线性提升。

### 流式处理测试

这些测试通过将数据分块处理，模拟真实世界中的流式数据加密/解密场景。这对于处理大型文件或网络流量特别重要。

### 硬件加速测试

这个测试展示了在具有特定硬件加速功能（如 AVX2, AES-NI）的 CPU 上各种算法的性能比较。

## 结果分析示例

以下是一个简化的结果分析示例：

```
BenchmarkCompareEncrypt/XCipher_Medium_64KB-8         10000       120000 ns/op     545.33 MB/s    65536 B/op       1 allocs/op
BenchmarkCompareEncrypt/StdChaCha20Poly1305_Medium_64KB-8   8000       150000 ns/op     436.27 MB/s    131072 B/op      2 allocs/op
```

分析：
- XCipher 处理 64KB 数据的速度比标准库快约 25%（120000 ns/op vs 150000 ns/op）
- XCipher 的内存分配量只有标准库的一半（65536 B/op vs 131072 B/op）
- XCipher 的内存分配次数少于标准库（1 allocs/op vs 2 allocs/op）

## 持续优化

基准测试是持续优化库性能的重要工具。通过定期运行这些测试，可以检测性能回归并指导进一步的优化工作。 
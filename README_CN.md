# go-xcipher

<div align="center">

<img src="golang_logo.png" alt="go-xcipher Logo" height="150">

[![Go Reference](https://pkg.go.dev/badge/github.com/landaiqing/go-xcipher.svg)](https://pkg.go.dev/github.com/landaiqing/go-xcipher)
[![Go Report Card](https://goreportcard.com/badge/github.com/landaiqing/go-xcipher)](https://goreportcard.com/report/github.com/landaiqing/go-xcipher)
[![License](https://img.shields.io/github/license/landaiqing/go-xcipher.svg)](LICENSE)
[![Release](https://img.shields.io/github/release/landaiqing/go-xcipher.svg)](https://github.com/landaiqing/go-xcipher/releases/latest)

</div>

中文 | [English](README.md)

## 项目概述

go-xcipher 是一个高性能、易用的 Go 加密库，基于 ChaCha20-Poly1305 算法提供安全的数据加密和解密功能。该库特别优化了对大文件和数据流的处理，支持并行加密/解密，内存优化和可取消的操作。

## ✨ 特性

- 🔒 使用经过验证的 ChaCha20-Poly1305 算法提供高强度加密
- 🚀 针对大数据和流数据优化的性能
- 🧵 自动并行处理大数据集，提高吞吐量
- 📊 提供详细的统计信息，方便性能监控和优化
- 🧠 智能内存管理，减少内存分配和 GC 压力
- ⏹️ 支持可取消的操作，适合长时间运行的任务
- 🛡️ 全面的错误处理和安全检查
- 🖥️ CPU架构感知优化，针对不同硬件平台自动调整参数

## 🔧 安装

```bash
go get -u github.com/landaiqing/go-xcipher
```

确保使用 Go 1.18 或更高版本。

## 📝 使用示例

### 简单加密/解密

```go
package main

import (
    "fmt"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // 创建一个32字节的密钥（这里只是示例，实际应用中应安全生成和存储密钥）
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 要加密的数据
    plaintext := []byte("敏感数据")
    
    // 可选的附加验证数据
    additionalData := []byte("header")
    
    // 加密
    ciphertext, err := cipher.Encrypt(plaintext, additionalData)
    if err != nil {
        panic(err)
    }
    
    // 解密
    decrypted, err := cipher.Decrypt(ciphertext, additionalData)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("解密后:", string(decrypted))
}
```

### 流式加密（基本用法）

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // 创建密钥
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 打开要加密的文件
    inputFile, _ := os.Open("大文件.dat")
    defer inputFile.Close()
    
    // 创建输出文件
    outputFile, _ := os.Create("大文件.encrypted")
    defer outputFile.Close()
    
    // 使用默认选项加密流
    err := cipher.EncryptStream(inputFile, outputFile, nil)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("文件加密完成")
}
```

### 并行处理大文件

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // 创建密钥
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 打开要加密的文件
    inputFile, _ := os.Open("大文件.dat")
    defer inputFile.Close()
    
    // 创建输出文件
    outputFile, _ := os.Create("大文件.encrypted")
    defer outputFile.Close()
    
    // 设置流选项 - 启用并行处理
    options := xcipher.DefaultStreamOptions()
    options.UseParallel = true       // 启用并行处理
    options.MaxWorkers = 8           // 设置最大工作线程数
    options.BufferSize = 256 * 1024  // 设置较大的缓冲区大小
    options.CollectStats = true      // 收集性能统计
    
    // 加密流
    stats, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
    if err != nil {
        panic(err)
    }
    
    // 显示性能统计
    fmt.Printf("处理用时: %v\n", stats.Duration())
    fmt.Printf("处理速度: %.2f MB/s\n", stats.Throughput)
    fmt.Printf("并行处理: %v, 工作线程数: %d\n", stats.ParallelProcessing, stats.WorkerCount)
    fmt.Printf("处理数据量: %.2f MB\n", float64(stats.BytesProcessed) / 1024 / 1024)
    fmt.Printf("数据块数: %d, 平均块大小: %.2f KB\n", stats.BlocksProcessed, stats.AvgBlockSize / 1024)
}
```

### 使用自适应参数优化

```go
package main

import (
    "fmt"
    "os"
    "github.com/landaiqing/go-xcipher"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // 创建密钥
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 打开要加密的文件
    inputFile, _ := os.Open("大文件.dat")
    defer inputFile.Close()
    
    // 创建输出文件
    outputFile, _ := os.Create("大文件.encrypted")
    defer outputFile.Close()
    
    // 获取优化的流选项 - 自动根据系统环境选择最佳参数
    options := xcipher.GetOptimizedStreamOptions()
    options.CollectStats = true
    
    // 查看系统优化信息
    sysInfo := xcipher.GetSystemOptimizationInfo()
    fmt.Printf("CPU架构: %s, 核心数: %d\n", sysInfo.Architecture, sysInfo.NumCPUs)
    fmt.Printf("支持AVX: %v, 支持AVX2: %v\n", sysInfo.HasAVX, sysInfo.HasAVX2)
    fmt.Printf("推荐缓冲区大小: %d KB\n", sysInfo.RecommendedBufferSize / 1024)
    fmt.Printf("推荐工作线程数: %d\n", sysInfo.RecommendedWorkers)
    
    // 加密流
    stats, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
    if err != nil {
        panic(err)
    }
    
    // 显示性能统计
    fmt.Printf("处理用时: %v\n", stats.Duration())
    fmt.Printf("处理速度: %.2f MB/s\n", stats.Throughput)
}
```

### 支持取消的长时间操作

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
    // 创建密钥
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 打开要加密的文件
    inputFile, _ := os.Open("超大文件.dat")
    defer inputFile.Close()
    
    // 创建输出文件
    outputFile, _ := os.Create("超大文件.encrypted")
    defer outputFile.Close()
    
    // 创建可取消的上下文
    ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
    defer cancel() // 确保资源被释放
    
    // 设置带取消功能的流选项
    options := xcipher.DefaultStreamOptions()
    options.UseParallel = true
    options.CancelChan = ctx.Done() // 设置取消信号
    
    // 在另一个goroutine中执行加密
    resultChan := make(chan error, 1)
    go func() {
        _, err := cipher.EncryptStreamWithOptions(inputFile, outputFile, options)
        resultChan <- err
    }()
    
    // 等待结果或超时
    select {
    case err := <-resultChan:
        if err != nil {
            fmt.Printf("加密错误: %v\n", err)
        } else {
            fmt.Println("加密成功完成")
        }
    case <-ctx.Done():
        fmt.Println("操作超时或被取消")
        // 等待操作确实停止
        err := <-resultChan
        fmt.Printf("取消后的结果: %v\n", err)
    }
}
```

### 内存缓冲区处理示例

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
    // 创建密钥
    key := make([]byte, chacha20poly1305.KeySize)
    
    // 初始化加密器
    cipher := xcipher.NewXCipher(key)
    
    // 准备要加密的数据
    data := []byte("这是一些要加密的敏感数据，使用内存缓冲区而不是文件进行处理")
    
    // 创建源读取器和目标写入器
    source := bytes.NewReader(data)
    var encrypted bytes.Buffer
    
    // 加密数据
    if err := cipher.EncryptStream(source, &encrypted, nil); err != nil {
        panic(err)
    }
    
    fmt.Printf("原始数据大小: %d 字节\n", len(data))
    fmt.Printf("加密后大小: %d 字节\n", encrypted.Len())
    
    // 解密数据
    var decrypted bytes.Buffer
    if err := cipher.DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, nil); err != nil {
        panic(err)
    }
    
    fmt.Printf("解密后大小: %d 字节\n", decrypted.Len())
    fmt.Printf("解密后内容: %s\n", decrypted.String())
}
```

## 📋 API 文档

### 核心类型

```go
type XCipher struct {
    // 内含字段未导出
}

// 流处理的统计信息
type StreamStats struct {
    StartTime time.Time          // 开始时间
    EndTime time.Time            // 结束时间
    BytesProcessed int64         // 处理的字节数
    BlocksProcessed int          // 处理的数据块数
    AvgBlockSize float64         // 平均块大小
    Throughput float64           // 吞吐量 (MB/s)
    ParallelProcessing bool      // 是否使用了并行处理
    WorkerCount int              // 工作线程数
    BufferSize int               // 缓冲区大小
}

// 流处理选项
type StreamOptions struct {
    BufferSize int               // 缓冲区大小
    UseParallel bool             // 是否使用并行处理
    MaxWorkers int               // 最大工作线程数
    AdditionalData []byte        // 附加验证数据
    CollectStats bool            // 是否收集性能统计
    CancelChan <-chan struct{}   // 取消信号通道
}

// 系统优化信息
type OptimizationInfo struct {
    Architecture string          // CPU架构
    NumCPUs int                  // CPU核心数
    HasAVX bool                  // 是否支持AVX指令集
    HasAVX2 bool                 // 是否支持AVX2指令集
    HasSSE41 bool                // 是否支持SSE4.1指令集
    HasNEON bool                 // 是否支持ARM NEON指令集
    EstimatedL1Cache int         // 估计L1缓存大小
    EstimatedL2Cache int         // 估计L2缓存大小
    EstimatedL3Cache int         // 估计L3缓存大小
    RecommendedBufferSize int    // 推荐的缓冲区大小
    RecommendedWorkers int       // 推荐的工作线程数
    ParallelThreshold int        // 并行处理阈值
    LastMeasuredThroughput float64 // 上次测量的吞吐量
    SamplesCount int             // 样本数
}
```

### 主要函数和方法

- `NewXCipher(key []byte) *XCipher` - 创建新的加密器实例
- `(x *XCipher) Encrypt(data, additionalData []byte) ([]byte, error)` - 加密数据
- `(x *XCipher) Decrypt(cipherData, additionalData []byte) ([]byte, error)` - 解密数据
- `(x *XCipher) EncryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error` - 使用默认选项加密流
- `(x *XCipher) DecryptStream(reader io.Reader, writer io.Writer, additionalData []byte) error` - 使用默认选项解密流
- `(x *XCipher) EncryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error)` - 使用自定义选项加密流
- `(x *XCipher) DecryptStreamWithOptions(reader io.Reader, writer io.Writer, options StreamOptions) (*StreamStats, error)` - 使用自定义选项解密流
- `DefaultStreamOptions() StreamOptions` - 获取默认流处理选项
- `GetOptimizedStreamOptions() StreamOptions` - 获取优化的流处理选项（自动适应当前系统）
- `GetSystemOptimizationInfo() *OptimizationInfo` - 获取系统优化信息

## 🧪 测试与基准测试

### 运行单元测试

```bash
# 运行所有测试
go test

# 运行所有测试并显示详细输出
go test -v

# 运行特定测试
go test -run TestStreamParallelProcessing

# 运行特定测试组
go test -run TestStream
```

### 运行基准测试

```bash
# 运行所有基准测试
go test -bench=.

# 运行特定基准测试
go test -bench=BenchmarkEncrypt

# 运行流处理性能矩阵基准测试
go test -bench=BenchmarkStreamPerformanceMatrix

# 带内存分配统计的基准测试
go test -bench=. -benchmem

# 多次运行以获得更准确的结果
go test -bench=. -count=5
```

### 性能分析

```bash
# CPU性能分析
go test -bench=BenchmarkStreamPerformanceMatrix -cpuprofile=cpu.prof

# 内存分析
go test -bench=BenchmarkStreamPerformanceMatrix -memprofile=mem.prof

# 使用pprof查看性能分析结果
go tool pprof cpu.prof
go tool pprof mem.prof
```

## 🚀 性能优化亮点

go-xcipher 经过多方面优化，可处理各种规模的数据，从小型消息到大型文件。以下是主要优化亮点：

### 自适应参数优化
- 基于CPU架构和系统特性自动调整缓冲区大小和工作线程数
- 运行时根据处理数据特性动态调整参数，实现最佳性能
- 专门针对不同指令集(AVX, AVX2, SSE4.1, NEON)进行优化

### 高效并行处理
- 智能决策何时使用并行处理，避免小数据并行带来的开销
- 基于CPU核心数和缓存特性优化工作线程分配
- 使用工作池和任务队列减少线程创建/销毁开销
- 数据块自动平衡，确保各线程负载均衡

### 内存优化
- 零拷贝技术减少内存数据复制操作
- 内存缓冲池复用，显著减少GC压力
- 批量处理和写入缓冲，减少系统调用次数
- 缓冲区大小根据L1/L2/L3缓存特性优化，提高缓存命中率

### 性能数据
- 小数据包加密：~1.5 GB/s
- 大文件并行加密：~4.0 GB/s (取决于CPU核心数和硬件)
- 内存效率：处理大文件时内存使用量保持稳定，避免OOM风险
- 基准测试结果表明比标准库实现快2-10倍（取决于数据大小和处理方式）

## 🤝 贡献

欢迎提交 Issues 和 Pull Requests 帮助改进 go-xcipher。您可以通过以下方式贡献：

1. 报告 Bug
2. 提交功能请求
3. 提交代码改进
4. 完善文档

## 📜 许可证

go-xcipher 使用 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。 
package xcipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"runtime"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	benchmarkKey        = make([]byte, chacha20poly1305.KeySize)
	benchmarkAESKey     = make([]byte, 32)           // 256-bit AES key
	benchmarkSmallData  = make([]byte, 1024)         // 1KB
	benchmarkMediumData = make([]byte, 64*1024)      // 64KB
	benchmarkLargeData  = make([]byte, 1024*1024)    // 1MB
	benchmarkHugeData   = make([]byte, 10*1024*1024) // 10MB
)

func init() {
	// 初始化测试数据
	rand.Read(benchmarkKey)
	rand.Read(benchmarkAESKey)
	rand.Read(benchmarkSmallData)
	rand.Read(benchmarkMediumData)
	rand.Read(benchmarkLargeData)
	rand.Read(benchmarkHugeData)
}

// 标准库 ChaCha20Poly1305 实现
func encryptWithStdChaCha20Poly1305(plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(benchmarkKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	return result, nil
}

func decryptWithStdChaCha20Poly1305(ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(benchmarkKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	encrypted := ciphertext[chacha20poly1305.NonceSizeX:]

	return aead.Open(nil, nonce, encrypted, additionalData)
}

// 标准库 AES-GCM 实现
func encryptWithAESGCM(plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(benchmarkAESKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	return result, nil
}

func decryptWithAESGCM(ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(benchmarkAESKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	encrypted := ciphertext[aead.NonceSize():]

	return aead.Open(nil, nonce, encrypted, additionalData)
}

// XCipher 流式加密的标准库模拟实现
func streamEncryptWithStdChaCha20Poly1305(r io.Reader, w io.Writer, additionalData []byte) error {
	aead, err := chacha20poly1305.NewX(benchmarkKey)
	if err != nil {
		return err
	}

	// 写入基础随机数
	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(baseNonce); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 分块处理
	buffer := make([]byte, 64*1024) // 64KB 缓冲区
	blockNonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(blockNonce, baseNonce)
	counter := uint64(0)

	for {
		n, err := r.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}

		if n > 0 {
			// 为每个块创建唯一的随机数
			binary.LittleEndian.PutUint64(blockNonce[chacha20poly1305.NonceSizeX-8:], counter)
			counter++

			// 加密数据块
			sealed := aead.Seal(nil, blockNonce, buffer[:n], additionalData)

			// 写入加密数据块长度
			lengthBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBytes, uint32(len(sealed)))
			if _, err := w.Write(lengthBytes); err != nil {
				return err
			}

			// 写入加密数据
			if _, err := w.Write(sealed); err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
	}

	return nil
}

// 标准库模拟流式解密实现
func streamDecryptWithStdChaCha20Poly1305(r io.Reader, w io.Writer, additionalData []byte) error {
	aead, err := chacha20poly1305.NewX(benchmarkKey)
	if err != nil {
		return err
	}

	// 读取基础随机数
	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return fmt.Errorf("failed to read nonce: %v", err)
	}

	// 准备读取数据块
	blockNonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(blockNonce, baseNonce)
	counter := uint64(0)
	lengthBuf := make([]byte, 4)

	for {
		// 读取数据块长度
		_, err := io.ReadFull(r, lengthBuf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// 解析数据块长度
		blockLen := binary.BigEndian.Uint32(lengthBuf)
		encBuffer := make([]byte, blockLen)

		// 读取加密数据块
		_, err = io.ReadFull(r, encBuffer)
		if err != nil {
			return err
		}

		// 为每个块创建唯一的随机数
		binary.LittleEndian.PutUint64(blockNonce[chacha20poly1305.NonceSizeX-8:], counter)
		counter++

		// 解密数据块
		decrypted, err := aead.Open(nil, blockNonce, encBuffer, additionalData)
		if err != nil {
			return err
		}

		// 写入解密数据
		if _, err := w.Write(decrypted); err != nil {
			return err
		}
	}

	return nil
}

// 对比基本加密性能
func BenchmarkCompareEncrypt(b *testing.B) {
	testCases := []struct {
		name string
		size int
		data []byte
	}{
		{"Small_1KB", 1 * 1024, benchmarkSmallData},
		{"Medium_64KB", 64 * 1024, benchmarkMediumData},
		{"Large_1MB", 1 * 1024 * 1024, benchmarkLargeData},
		{"Huge_10MB", 10 * 1024 * 1024, benchmarkHugeData},
	}

	for _, tc := range testCases {
		// XCipher
		b.Run(fmt.Sprintf("XCipher_%s", tc.name), func(b *testing.B) {
			cipher := NewXCipher(benchmarkKey)
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(tc.data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// Standard ChaCha20Poly1305
		b.Run(fmt.Sprintf("StdChaCha20Poly1305_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := encryptWithStdChaCha20Poly1305(tc.data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// AES-GCM
		b.Run(fmt.Sprintf("AES_GCM_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := encryptWithAESGCM(tc.data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 对比基本解密性能
func BenchmarkCompareDecrypt(b *testing.B) {
	testCases := []struct {
		name string
		size int
		data []byte
	}{
		{"Small_1KB", 1 * 1024, benchmarkSmallData},
		{"Medium_64KB", 64 * 1024, benchmarkMediumData},
		{"Large_1MB", 1 * 1024 * 1024, benchmarkLargeData},
	}

	for _, tc := range testCases {
		// XCipher 加密准备
		xcipher := NewXCipher(benchmarkKey)
		xcipherEncrypted, _ := xcipher.Encrypt(tc.data, nil)

		// 标准库 ChaCha20Poly1305 加密准备
		stdChachaEncrypted, _ := encryptWithStdChaCha20Poly1305(tc.data, nil)

		// AES-GCM 加密准备
		aesGcmEncrypted, _ := encryptWithAESGCM(tc.data, nil)

		// XCipher
		b.Run(fmt.Sprintf("XCipher_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := xcipher.Decrypt(xcipherEncrypted, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// Standard ChaCha20Poly1305
		b.Run(fmt.Sprintf("StdChaCha20Poly1305_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := decryptWithStdChaCha20Poly1305(stdChachaEncrypted, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// AES-GCM
		b.Run(fmt.Sprintf("AES_GCM_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				_, err := decryptWithAESGCM(aesGcmEncrypted, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 对比流式加密性能
func BenchmarkCompareStreamEncrypt(b *testing.B) {
	testCases := []struct {
		name string
		size int
		data []byte
	}{
		{"Medium_64KB", 64 * 1024, benchmarkMediumData},
		{"Large_1MB", 1 * 1024 * 1024, benchmarkLargeData},
		{"Huge_10MB", 10 * 1024 * 1024, benchmarkHugeData},
	}

	for _, tc := range testCases {
		// XCipher 顺序流式加密
		b.Run(fmt.Sprintf("XCipher_Sequential_%s", tc.name), func(b *testing.B) {
			xcipher := NewXCipher(benchmarkKey)
			options := DefaultStreamOptions()
			options.UseParallel = false

			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(tc.data)
				writer := ioutil.Discard
				b.StartTimer()

				_, err := xcipher.EncryptStreamWithOptions(reader, writer, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// XCipher 并行流式加密
		b.Run(fmt.Sprintf("XCipher_Parallel_%s", tc.name), func(b *testing.B) {
			xcipher := NewXCipher(benchmarkKey)
			options := DefaultStreamOptions()
			options.UseParallel = true
			options.MaxWorkers = runtime.NumCPU()

			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(tc.data)
				writer := ioutil.Discard
				b.StartTimer()

				_, err := xcipher.EncryptStreamWithOptions(reader, writer, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// 标准库模拟流式加密
		b.Run(fmt.Sprintf("StdChacha20Poly1305_Stream_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(tc.data)
				writer := ioutil.Discard
				b.StartTimer()

				err := streamEncryptWithStdChaCha20Poly1305(reader, writer, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 对比流式解密性能
func BenchmarkCompareStreamDecrypt(b *testing.B) {
	testCases := []struct {
		name string
		size int
		data []byte
	}{
		{"Medium_64KB", 64 * 1024, benchmarkMediumData},
		{"Large_1MB", 1 * 1024 * 1024, benchmarkLargeData},
		{"Huge_10MB", 10 * 1024 * 1024, benchmarkHugeData},
	}

	for _, tc := range testCases {
		// 准备XCipher加密数据
		xcipher := NewXCipher(benchmarkKey)
		var xCipherBuf bytes.Buffer
		options := DefaultStreamOptions()
		options.UseParallel = false
		_, _ = xcipher.EncryptStreamWithOptions(bytes.NewReader(tc.data), &xCipherBuf, options)
		xCipherEncData := xCipherBuf.Bytes()

		// 准备标准库加密数据
		var stdBuf bytes.Buffer
		_ = streamEncryptWithStdChaCha20Poly1305(bytes.NewReader(tc.data), &stdBuf, nil)
		stdEncData := stdBuf.Bytes()

		// XCipher 顺序流式解密
		b.Run(fmt.Sprintf("XCipher_Sequential_%s", tc.name), func(b *testing.B) {
			options := DefaultStreamOptions()
			options.UseParallel = false

			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(xCipherEncData)
				writer := ioutil.Discard
				b.StartTimer()

				_, err := xcipher.DecryptStreamWithOptions(reader, writer, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// XCipher 并行流式解密
		b.Run(fmt.Sprintf("XCipher_Parallel_%s", tc.name), func(b *testing.B) {
			options := DefaultStreamOptions()
			options.UseParallel = true
			options.MaxWorkers = runtime.NumCPU()

			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(xCipherEncData)
				writer := ioutil.Discard
				b.StartTimer()

				_, err := xcipher.DecryptStreamWithOptions(reader, writer, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// 标准库模拟流式解密
		b.Run(fmt.Sprintf("StdChacha20Poly1305_Stream_%s", tc.name), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(tc.size))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(stdEncData)
				writer := ioutil.Discard
				b.StartTimer()

				err := streamDecryptWithStdChaCha20Poly1305(reader, writer, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 多核心优化性能测试
func BenchmarkMultiCoreScaling(b *testing.B) {
	// 使用较大数据块展示并行处理优势
	dataSize := 32 * 1024 * 1024 // 32MB
	largeData := make([]byte, dataSize)
	rand.Read(largeData)

	// 测试在不同CPU核心数下的性能表现
	maxCores := runtime.NumCPU()
	for cores := 1; cores <= maxCores; cores *= 2 {
		// 如果cores超过最大核心数，使用最大核心数
		testCores := cores
		if testCores > maxCores {
			testCores = maxCores
		}

		coreName := fmt.Sprintf("%d_Cores", testCores)

		// 限制使用的CPU数量
		runtime.GOMAXPROCS(testCores)

		// XCipher并行加密
		b.Run(fmt.Sprintf("XCipher_Parallel_%s", coreName), func(b *testing.B) {
			xcipher := NewXCipher(benchmarkKey)
			options := DefaultStreamOptions()
			options.UseParallel = true
			options.MaxWorkers = testCores

			b.ResetTimer()
			b.SetBytes(int64(dataSize))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(largeData)
				writer := ioutil.Discard
				b.StartTimer()

				_, err := xcipher.EncryptStreamWithOptions(reader, writer, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// 标准库加密
		b.Run(fmt.Sprintf("StdChaCha20Poly1305_%s", coreName), func(b *testing.B) {
			b.ResetTimer()
			b.SetBytes(int64(dataSize))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				reader := bytes.NewReader(largeData)
				writer := ioutil.Discard
				b.StartTimer()

				err := streamEncryptWithStdChaCha20Poly1305(reader, writer, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	// 恢复默认的CPU核心数设置
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// HardwareAccelerationTest 测试硬件加速性能
func BenchmarkHardwareAcceleration(b *testing.B) {
	// 测试不同算法在硬件加速下的性能表现
	dataSize := 16 * 1024 * 1024 // 16MB
	data := make([]byte, dataSize)
	rand.Read(data)

	// 获取CPU架构信息
	info := GetSystemOptimizationInfo()

	// ChaCha20-Poly1305（XCipher）
	b.Run(fmt.Sprintf("XCipher_HW=%v_AVX2=%v", true, info.HasAVX2), func(b *testing.B) {
		cipher := NewXCipher(benchmarkKey)

		// 使用优化选项
		options := GetOptimizedStreamOptions()

		b.ResetTimer()
		b.SetBytes(int64(dataSize))
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			reader := bytes.NewReader(data)
			writer := ioutil.Discard
			b.StartTimer()

			_, err := cipher.EncryptStreamWithOptions(reader, writer, options)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// 标准库 ChaCha20-Poly1305
	b.Run(fmt.Sprintf("StdChaCha20Poly1305_HW=%v", true), func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(int64(dataSize))
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			reader := bytes.NewReader(data)
			writer := ioutil.Discard
			b.StartTimer()

			err := streamEncryptWithStdChaCha20Poly1305(reader, writer, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// AES-GCM (如果硬件支持AES-NI，可能会有很好的性能)
	b.Run(fmt.Sprintf("AES_GCM_HW=%v", true), func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(int64(dataSize))
		for i := 0; i < b.N; i++ {
			_, err := encryptWithAESGCM(data, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// 内存使用测试 - 检查不同大小数据时的内存分配情况
func BenchmarkMemoryUsage(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"4KB", 4 * 1024},
		{"1MB", 1 * 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, size := range sizes {
		data := make([]byte, size.size)
		rand.Read(data)

		// XCipher
		b.Run(fmt.Sprintf("XCipher_%s", size.name), func(b *testing.B) {
			cipher := NewXCipher(benchmarkKey)
			b.ResetTimer()
			b.ReportAllocs() // 报告内存分配情况

			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		// 标准库
		b.Run(fmt.Sprintf("StdChaCha20Poly1305_%s", size.name), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs() // 报告内存分配情况

			for i := 0; i < b.N; i++ {
				_, err := encryptWithStdChaCha20Poly1305(data, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// 综合性能矩阵测试，对比不同算法在各种场景下的性能
func BenchmarkPerformanceMatrix(b *testing.B) {
	// 测试参数矩阵
	sizes := []struct {
		name string
		size int
	}{
		{"4KB", 4 * 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1 * 1024 * 1024},
	}

	methods := []struct {
		name    string
		encrypt func([]byte, []byte) ([]byte, error)
		decrypt func([]byte, []byte) ([]byte, error)
	}{
		{
			name: "XCipher",
			encrypt: func(data, aad []byte) ([]byte, error) {
				cipher := NewXCipher(benchmarkKey)
				return cipher.Encrypt(data, aad)
			},
			decrypt: func(data, aad []byte) ([]byte, error) {
				cipher := NewXCipher(benchmarkKey)
				return cipher.Decrypt(data, aad)
			},
		},
		{
			name:    "StdChaCha20Poly1305",
			encrypt: encryptWithStdChaCha20Poly1305,
			decrypt: decryptWithStdChaCha20Poly1305,
		},
		{
			name:    "AES_GCM",
			encrypt: encryptWithAESGCM,
			decrypt: decryptWithAESGCM,
		},
	}

	// 针对每种数据大小
	for _, size := range sizes {
		data := make([]byte, size.size)
		rand.Read(data)

		// 针对每种加密方法
		for _, method := range methods {
			// 加密基准测试
			b.Run(fmt.Sprintf("Encrypt_%s_%s", method.name, size.name), func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size.size))
				for i := 0; i < b.N; i++ {
					_, err := method.encrypt(data, nil)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			// 解密基准测试
			encrypted, _ := method.encrypt(data, nil)
			b.Run(fmt.Sprintf("Decrypt_%s_%s", method.name, size.name), func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size.size))
				for i := 0; i < b.N; i++ {
					_, err := method.decrypt(encrypted, nil)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// 报告辅助函数 - 在测试运行期间收集相关信息
func TestPrintBenchmarkGuide(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过报告生成")
	}

	fmt.Println("======= XCipher 与标准库加密性能对比测试指南 =======")
	fmt.Println("运行以下命令以执行全面性能对比测试:")
	fmt.Println("go test -bench=Benchmark -benchmem -benchtime=1s")
	fmt.Println()
	fmt.Println("或运行特定测试:")
	fmt.Println("go test -bench=BenchmarkCompareEncrypt -benchmem")
	fmt.Println("go test -bench=BenchmarkCompareDecrypt -benchmem")
	fmt.Println("go test -bench=BenchmarkCompareStreamEncrypt -benchmem")
	fmt.Println("go test -bench=BenchmarkCompareStreamDecrypt -benchmem")
	fmt.Println("go test -bench=BenchmarkMultiCoreScaling -benchmem")
	fmt.Println("go test -bench=BenchmarkHardwareAcceleration -benchmem")
	fmt.Println("go test -bench=BenchmarkMemoryUsage -benchmem")
	fmt.Println("go test -bench=BenchmarkPerformanceMatrix -benchmem")
	fmt.Println()

	// 获取CPU和系统信息
	fmt.Println("系统信息:")
	fmt.Printf("CPU: %d 核心\n", runtime.NumCPU())
	fmt.Printf("GOMAXPROCS: %d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("架构: %s\n", runtime.GOARCH)

	// 获取优化相关信息
	info := GetSystemOptimizationInfo()
	fmt.Println("\n硬件加速支持:")
	fmt.Printf("AVX: %v\n", info.HasAVX)
	fmt.Printf("AVX2: %v\n", info.HasAVX2)
	fmt.Printf("SSE4.1: %v\n", info.HasSSE41)
	fmt.Printf("ARM NEON: %v\n", info.HasNEON)

	fmt.Println("\n推荐优化参数:")
	fmt.Printf("建议缓冲区大小: %d 字节\n", info.RecommendedBufferSize)
	fmt.Printf("建议工作线程数: %d\n", info.RecommendedWorkers)
	fmt.Printf("并行处理阈值: %d 字节\n", info.ParallelThreshold)
	fmt.Println("\n测试结果将显示各种加密算法和方法的性能差异。")
	fmt.Println("=================================================")
}

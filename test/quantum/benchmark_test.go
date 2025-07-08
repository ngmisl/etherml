package quantum_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"wallet/pkg/quantum"
)

// BenchmarkMLKEMKeyGeneration benchmarks ML-KEM-1024 key pair generation
func BenchmarkMLKEMKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := quantum.GenerateMLKEMKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

// BenchmarkHybridEncryption benchmarks the ML-KEM + AES hybrid encryption
func BenchmarkHybridEncryption(b *testing.B) {
	encapsKey, _, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test with different data sizes
	dataSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, ds := range dataSizes {
		data := make([]byte, ds.size)
		rand.Read(data)

		b.Run("encrypt_"+ds.name, func(b *testing.B) {
			b.SetBytes(int64(ds.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := quantum.EncryptDataPQC(data, encapsKey)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkHybridDecryption benchmarks the ML-KEM + AES hybrid decryption
func BenchmarkHybridDecryption(b *testing.B) {
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test with different data sizes
	dataSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, ds := range dataSizes {
		data := make([]byte, ds.size)
		rand.Read(data)

		encrypted, nonce, err := quantum.EncryptDataPQC(data, encapsKey)
		if err != nil {
			b.Fatalf("Failed to encrypt test data: %v", err)
		}

		b.Run("decrypt_"+ds.name, func(b *testing.B) {
			b.SetBytes(int64(ds.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
				if err != nil {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkHybridRoundTrip benchmarks complete encrypt/decrypt cycles
func BenchmarkHybridRoundTrip(b *testing.B) {
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate keypair: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, nonce, err := quantum.EncryptDataPQC(testData, encapsKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkSecureCompare benchmarks constant-time comparison
func BenchmarkSecureCompare(b *testing.B) {
	data1 := make([]byte, 1024)
	data2 := make([]byte, 1024)
	rand.Read(data1)
	copy(data2, data1) // Identical data for comparison

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		quantum.SecureCompare(data1, data2)
	}
}

// BenchmarkSecureZero benchmarks memory zeroing performance
func BenchmarkSecureZero(b *testing.B) {
	dataSizes := []int{32, 256, 1024, 4096, 16384}

	for _, size := range dataSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Restore data before each iteration
				rand.Read(data)
				b.StartTimer()
				
				quantum.SecureZero(data)
			}
		})
	}
}

// BenchmarkGenerateSecureRandom benchmarks random number generation
func BenchmarkGenerateSecureRandom(b *testing.B) {
	sizes := []int{16, 32, 64, 128, 256, 512, 1024}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := quantum.GenerateSecureRandom(size)
				if err != nil {
					b.Fatalf("Random generation failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkArgon2idKeyDerivation benchmarks password-based key derivation
func BenchmarkArgon2idKeyDerivation(b *testing.B) {
	password := []byte("benchmark_password_12345")
	salt := quantum.Salt{}
	rand.Read(salt[:])

	// Test different Argon2id parameter sets
	paramSets := []struct {
		name   string
		params quantum.KDFParams
	}{
		{
			"fast",
			quantum.KDFParams{
				Function:    "argon2id",
				Memory:      32768,  // 32MB
				Iterations:  1,
				Parallelism: 2,
				KeyLen:      32,
			},
		},
		{
			"standard",
			quantum.KDFParams{
				Function:    "argon2id",
				Memory:      65536,  // 64MB
				Iterations:  3,
				Parallelism: 4,
				KeyLen:      32,
			},
		},
		{
			"secure",
			quantum.KDFParams{
				Function:    "argon2id",
				Memory:      131072, // 128MB
				Iterations:  4,
				Parallelism: 8,
				KeyLen:      32,
			},
		},
	}

	for _, ps := range paramSets {
		b.Run("normal_"+ps.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				quantum.DeriveKey(password, salt, ps.params)
			}
		})

		b.Run("deniable_"+ps.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				quantum.DeriveKeyWithMode(password, salt, ps.params, true)
			}
		})
	}
}

// BenchmarkDeniableEncryption benchmarks the dual-mode key derivation
func BenchmarkDeniableEncryption(b *testing.B) {
	password := []byte("deniable_test_password")
	salt := quantum.Salt{}
	rand.Read(salt[:])

	params := quantum.KDFParams{
		Function:    "argon2id",
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32,
	}

	b.Run("normal_mode", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			quantum.DeriveKeyWithMode(password, salt, params, false)
		}
	})

	b.Run("decoy_mode", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			quantum.DeriveKeyWithMode(password, salt, params, true)
		}
	})
}

// BenchmarkMemoryUsage provides insights into memory allocation patterns
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("key_generation", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}
			// Prevent optimization
			_ = encapsKey
			_ = decapsKey
		}
	})

	b.Run("encryption", func(b *testing.B) {
		encapsKey, _, err := quantum.GenerateMLKEMKeyPair()
		if err != nil {
			b.Fatalf("Failed to generate keypair: %v", err)
		}

		data := make([]byte, 1024)
		rand.Read(data)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encrypted, nonce, err := quantum.EncryptDataPQC(data, encapsKey)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}
			// Prevent optimization
			_ = encrypted
			_ = nonce
		}
	})
}
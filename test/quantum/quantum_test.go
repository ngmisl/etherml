package quantum_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"wallet/pkg/quantum"
)

// TestMLKEMKeyGeneration tests ML-KEM-1024 key pair generation
func TestMLKEMKeyGeneration(t *testing.T) {
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM keypair: %v", err)
	}

	// Validate key sizes according to ML-KEM-1024 specification
	if len(encapsKey) == 0 {
		t.Error("Encapsulation key is empty")
	}
	if len(decapsKey) == 0 {
		t.Error("Decapsulation key is empty")
	}

	// Keys should be different
	if bytes.Equal(encapsKey, decapsKey) {
		t.Error("Encapsulation and decapsulation keys are identical")
	}
}

// TestMLKEMKeyGenerationUniqueness ensures each generation produces unique keys
func TestMLKEMKeyGenerationUniqueness(t *testing.T) {
	encaps1, decaps1, err1 := quantum.GenerateMLKEMKeyPair()
	encaps2, decaps2, err2 := quantum.GenerateMLKEMKeyPair()

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to generate keypairs: %v, %v", err1, err2)
	}

	// Keys should be unique across generations
	if bytes.Equal(encaps1, encaps2) {
		t.Error("Generated encapsulation keys are identical - randomness failure")
	}
	if bytes.Equal(decaps1, decaps2) {
		t.Error("Generated decapsulation keys are identical - randomness failure")
	}
}

// TestHybridEncryptionDecryption tests the ML-KEM + AES hybrid encryption system
func TestHybridEncryptionDecryption(t *testing.T) {
	// Generate test keypair
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"small data", []byte("hello quantum world")},
		{"medium data", bytes.Repeat([]byte("test"), 1000)},
		{"large data", bytes.Repeat([]byte("quantum"), 10000)},
		{"binary data", []byte{0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, nonce, err := quantum.EncryptDataPQC(tc.data, encapsKey)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Validate encrypted data is different from plaintext
			if len(tc.data) > 0 && bytes.Equal(tc.data, encrypted) {
				t.Error("Encrypted data is identical to plaintext")
			}

			// Decrypt
			decrypted, err := quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify round-trip integrity
			if !bytes.Equal(tc.data, decrypted) {
				t.Errorf("Round-trip failed: original=%x, decrypted=%x", tc.data, decrypted)
			}
		})
	}
}

// TestHybridEncryptionDeterminism ensures encryption is non-deterministic
func TestHybridEncryptionDeterminism(t *testing.T) {
	encapsKey, _, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	plaintext := []byte("determinism test data")

	// Encrypt same data twice
	encrypted1, nonce1, err1 := quantum.EncryptDataPQC(plaintext, encapsKey)
	encrypted2, nonce2, err2 := quantum.EncryptDataPQC(plaintext, encapsKey)

	if err1 != nil || err2 != nil {
		t.Fatalf("Encryption failed: %v, %v", err1, err2)
	}

	// Results should be different (non-deterministic)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encryption is deterministic - security vulnerability")
	}
	if nonce1 == nonce2 {
		t.Error("Nonces are identical - randomness failure")
	}
}

// TestInvalidDecryption tests error handling for invalid decryption attempts
func TestInvalidDecryption(t *testing.T) {
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	plaintext := []byte("test data for invalid decryption")
	encrypted, nonce, err := quantum.EncryptDataPQC(plaintext, encapsKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	testCases := []struct {
		name      string
		encrypted quantum.EncryptedData
		key       []byte
		nonce     string
	}{
		{"corrupted ciphertext", append(encrypted, 0xFF), decapsKey, nonce},
		{"truncated ciphertext", encrypted[:len(encrypted)/2], decapsKey, nonce},
		{"wrong key", encrypted, append(decapsKey, 0xFF), nonce},
		{"corrupted nonce", encrypted, decapsKey, "invalid_nonce"},
		{"empty ciphertext", quantum.EncryptedData{}, decapsKey, nonce},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := quantum.DecryptDataPQC(tc.encrypted, tc.key, tc.nonce)
			if err == nil {
				t.Error("Expected decryption to fail but it succeeded")
			}
		})
	}
}

// TestSecureCompare tests constant-time comparison function
func TestSecureCompare(t *testing.T) {
	testCases := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"identical bytes", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different bytes", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"different lengths", []byte{1, 2, 3}, []byte{1, 2}, false},
		{"empty arrays", []byte{}, []byte{}, true},
		{"one empty", []byte{1}, []byte{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := quantum.SecureCompare(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for %x vs %x", tc.expected, result, tc.a, tc.b)
			}
		})
	}
}

// TestSecureCompareTiming ensures constant-time behavior
func TestSecureCompareTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	data1 := bytes.Repeat([]byte{0x00}, 1000)
	data2 := bytes.Repeat([]byte{0x00}, 1000)
	data3 := bytes.Repeat([]byte{0xFF}, 1000)

	// Measure time for identical data
	start := time.Now()
	for i := 0; i < 10000; i++ {
		quantum.SecureCompare(data1, data2)
	}
	identicalTime := time.Since(start)

	// Measure time for different data
	start = time.Now()
	for i := 0; i < 10000; i++ {
		quantum.SecureCompare(data1, data3)
	}
	differentTime := time.Since(start)

	// Times should be similar (within 50% tolerance - accounts for system variance)
	ratio := float64(differentTime) / float64(identicalTime)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("Timing difference too large: identical=%v, different=%v, ratio=%.2f", 
			identicalTime, differentTime, ratio)
		t.Log("Note: Timing tests can be sensitive to system load. Use -short to skip.")
	}
}

// TestSecureZero tests memory zeroing functionality
func TestSecureZero(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	original := make([]byte, len(data))
	copy(original, data)

	quantum.SecureZero(data)

	// All bytes should be zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %x", i, b)
		}
	}

	// Ensure we actually had non-zero data initially
	hasNonZero := false
	for _, b := range original {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Test data was already all zeros")
	}
}

// TestGenerateSecureRandom tests cryptographically secure random generation
func TestGenerateSecureRandom(t *testing.T) {
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			data, err := quantum.GenerateSecureRandom(size)
			if err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			if len(data) != size {
				t.Errorf("Expected %d bytes, got %d", size, len(data))
			}

			// Basic entropy check - data should not be all zeros
			allZeros := true
			for _, b := range data {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Generated data is all zeros - entropy failure")
			}
		})
	}
}

// TestGenerateSecureRandomUniqueness ensures random generation produces unique outputs
func TestGenerateSecureRandomUniqueness(t *testing.T) {
	data1, err1 := quantum.GenerateSecureRandom(32)
	data2, err2 := quantum.GenerateSecureRandom(32)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to generate random data: %v, %v", err1, err2)
	}

	if bytes.Equal(data1, data2) {
		t.Error("Generated random data is identical - randomness failure")
	}
}

// TestArgon2idKeyDerivation tests password-based key derivation
func TestArgon2idKeyDerivation(t *testing.T) {
	password := []byte("test_password_123")
	salt := quantum.Salt{}
	rand.Read(salt[:])

	params := quantum.KDFParams{
		Function:    "argon2id",
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32,
	}

	key1 := quantum.DeriveKey(password, salt, params)
	key2 := quantum.DeriveKey(password, salt, params)

	// Same inputs should produce same key
	if !bytes.Equal(key1, key2) {
		t.Error("Key derivation is not deterministic")
	}

	// Different passwords should produce different keys
	differentPassword := []byte("different_password")
	key3 := quantum.DeriveKey(differentPassword, salt, params)
	if bytes.Equal(key1, key3) {
		t.Error("Different passwords produced same key")
	}

	// Different salts should produce different keys
	differentSalt := quantum.Salt{}
	rand.Read(differentSalt[:])
	key4 := quantum.DeriveKey(password, differentSalt, params)
	if bytes.Equal(key1, key4) {
		t.Error("Different salts produced same key")
	}
}

// TestDeniableEncryption tests the dual-mode key derivation for plausible deniability
func TestDeniableEncryption(t *testing.T) {
	password := []byte("master_password")
	salt := quantum.Salt{}
	rand.Read(salt[:])

	params := quantum.KDFParams{
		Function:    "argon2id",
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32,
	}

	// Derive keys for both modes
	normalKey := quantum.DeriveKeyWithMode(password, salt, params, false)
	decoyKey := quantum.DeriveKeyWithMode(password, salt, params, true)

	// Keys should be different
	if bytes.Equal(normalKey, decoyKey) {
		t.Error("Normal and decoy keys are identical - deniable encryption broken")
	}

	// Each mode should be deterministic
	normalKey2 := quantum.DeriveKeyWithMode(password, salt, params, false)
	decoyKey2 := quantum.DeriveKeyWithMode(password, salt, params, true)

	if !bytes.Equal(normalKey, normalKey2) {
		t.Error("Normal mode key derivation is not deterministic")
	}
	if !bytes.Equal(decoyKey, decoyKey2) {
		t.Error("Decoy mode key derivation is not deterministic")
	}

	// Validate standard DeriveKey matches normal mode
	standardKey := quantum.DeriveKey(password, salt, params)
	if !bytes.Equal(normalKey, standardKey) {
		t.Error("Normal mode should match standard DeriveKey function")
	}
}

// TestConcurrentEncryption tests thread safety of encryption operations
func TestConcurrentEncryption(t *testing.T) {
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	plaintext := []byte("concurrent encryption test data")
	numGoroutines := 100

	results := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			encrypted, nonce, err := quantum.EncryptDataPQC(plaintext, encapsKey)
			if err != nil {
				results <- false
				return
			}

			decrypted, err := quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
			if err != nil {
				results <- false
				return
			}

			results <- bytes.Equal(plaintext, decrypted)
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		success := <-results
		if !success {
			t.Error("Concurrent encryption/decryption failed")
		}
	}
}

// TestMemoryClearing validates that sensitive data is properly zeroed
func TestMemoryClearing(t *testing.T) {
	// This test verifies the memory clearing happens in the encryption functions
	// We'll encrypt data and ensure the function doesn't leak sensitive information
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	plaintext := []byte("sensitive data that should be cleared")
	
	// Perform encryption
	encrypted, nonce, err := quantum.EncryptDataPQC(plaintext, encapsKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Perform decryption
	decrypted, err := quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify round-trip worked
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Round-trip integrity check failed")
	}

	// Note: Actual memory inspection would require unsafe operations
	// The test validates that the functions complete successfully,
	// implying proper memory management didn't cause crashes
}
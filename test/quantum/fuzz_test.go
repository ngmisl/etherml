package quantum_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"wallet/pkg/quantum"
)

// FuzzHybridEncryption tests encryption with random inputs for robustness
func FuzzHybridEncryption(f *testing.F) {
	// Generate a valid keypair for fuzzing
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		f.Fatalf("Failed to generate keypair: %v", err)
	}

	// Add seed inputs for fuzzing
	seedInputs := [][]byte{
		{},                                           // empty data
		[]byte("hello"),                             // short data
		[]byte("The quick brown fox jumps over"),    // medium data
		bytes.Repeat([]byte("A"), 1000),             // repeated data
		{0x00, 0xFF, 0xAA, 0x55},                   // binary patterns
		bytes.Repeat([]byte{0x00}, 100),             // all zeros
		bytes.Repeat([]byte{0xFF}, 100),             // all ones
	}

	for _, seed := range seedInputs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Skip extremely large inputs to prevent resource exhaustion
		if len(data) > 10*1024*1024 { // 10MB limit
			t.Skip("Input too large")
		}

		// Attempt encryption
		encrypted, nonce, err := quantum.EncryptDataPQC(data, encapsKey)
		if err != nil {
			// Encryption should never fail with valid keys and any data
			t.Errorf("Encryption failed with valid inputs: %v", err)
			return
		}

		// Validate encryption produced different output (unless empty input)
		if len(data) > 0 && bytes.Equal(data, encrypted) {
			t.Error("Encrypted data is identical to plaintext")
		}

		// Attempt decryption
		decrypted, err := quantum.DecryptDataPQC(encrypted, decapsKey, nonce)
		if err != nil {
			t.Errorf("Decryption failed: %v", err)
			return
		}

		// Verify round-trip integrity
		if !bytes.Equal(data, decrypted) {
			t.Errorf("Round-trip integrity failed: len(original)=%d, len(decrypted)=%d", 
				len(data), len(decrypted))
		}
	})
}

// FuzzHybridDecryption tests decryption with corrupted ciphertext
func FuzzHybridDecryption(f *testing.F) {
	// Generate a valid keypair and some test data
	encapsKey, decapsKey, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		f.Fatalf("Failed to generate keypair: %v", err)
	}

	testData := []byte("test data for decryption fuzzing")
	validEncrypted, validNonce, err := quantum.EncryptDataPQC(testData, encapsKey)
	if err != nil {
		f.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Add seed inputs - variations of valid encrypted data
	f.Add([]byte(validEncrypted), validNonce)
	f.Add(append([]byte(validEncrypted), 0xFF), validNonce)        // append byte
	f.Add([]byte(validEncrypted)[:len(validEncrypted)/2], validNonce) // truncate
	f.Add([]byte{}, validNonce)                            // empty
	f.Add(bytes.Repeat([]byte{0x00}, len(validEncrypted)), validNonce) // all zeros

	f.Fuzz(func(t *testing.T, encryptedData []byte, nonce string) {
		// Attempt decryption - this should either succeed or fail gracefully
		_, err := quantum.DecryptDataPQC(quantum.EncryptedData(encryptedData), decapsKey, nonce)
		
		// We don't check for success/failure here - the important thing is that
		// the function doesn't panic or crash with invalid inputs
		_ = err // Explicitly ignore error for fuzzing
	})
}

// FuzzSecureCompare tests constant-time comparison with random inputs
func FuzzSecureCompare(f *testing.F) {
	// Seed with various comparison patterns
	seedPairs := []struct{ a, b []byte }{
		{[]byte{}, []byte{}},
		{[]byte{0x00}, []byte{0x00}},
		{[]byte{0x00}, []byte{0xFF}},
		{[]byte{0x00, 0x01}, []byte{0x00}},
		{[]byte("hello"), []byte("hello")},
		{[]byte("hello"), []byte("world")},
		{bytes.Repeat([]byte{0xAA}, 100), bytes.Repeat([]byte{0xAA}, 100)},
	}

	for _, pair := range seedPairs {
		f.Add(pair.a, pair.b)
	}

	f.Fuzz(func(t *testing.T, a, b []byte) {
		// Skip extremely large inputs
		if len(a) > 1024*1024 || len(b) > 1024*1024 {
			t.Skip("Input too large")
		}

		// SecureCompare should never panic
		result := quantum.SecureCompare(a, b)

		// Verify correctness against standard comparison
		expected := bytes.Equal(a, b)
		if result != expected {
			t.Errorf("SecureCompare result doesn't match bytes.Equal: got %v, expected %v", 
				result, expected)
		}
	})
}

// FuzzSecureZero tests memory zeroing with various input patterns
func FuzzSecureZero(f *testing.F) {
	// Seed with various data patterns
	seedInputs := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0xAA, 0x55},
		bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 25),
		make([]byte, 1000),
	}

	// Fill one seed with random data
	rand.Read(seedInputs[len(seedInputs)-1])

	for _, seed := range seedInputs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Skip extremely large inputs
		if len(data) > 1024*1024 {
			t.Skip("Input too large")
		}

		// Make a copy to verify the original data wasn't all zeros
		original := make([]byte, len(data))
		copy(original, data)

		// SecureZero should never panic
		quantum.SecureZero(data)

		// Verify all bytes are zero
		for i, b := range data {
			if b != 0 {
				t.Errorf("Byte at index %d is not zero after SecureZero: %x", i, b)
			}
		}
	})
}

// FuzzArgon2idKeyDerivation tests key derivation with random passwords and salts
func FuzzArgon2idKeyDerivation(f *testing.F) {
	// Seed with various password/salt combinations
	seedPasswords := [][]byte{
		{},
		[]byte("password"),
		[]byte("very_long_password_with_special_chars_!@#$%^&*()"),
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0xFF}, 32),
	}

	var seedSalt quantum.Salt
	rand.Read(seedSalt[:])

	for _, password := range seedPasswords {
		f.Add(password, seedSalt[:])
	}

	f.Fuzz(func(t *testing.T, password []byte, saltBytes []byte) {
		// Skip extremely large passwords
		if len(password) > 1024 {
			t.Skip("Password too large")
		}

		// Ensure salt is correct size
		var salt quantum.Salt
		if len(saltBytes) >= len(salt) {
			copy(salt[:], saltBytes[:len(salt)])
		} else {
			copy(salt[:len(saltBytes)], saltBytes)
		}

		params := quantum.KDFParams{
			Function:    "argon2id",
			Memory:      32768, // Use smaller memory for fuzzing performance
			Iterations:  1,     // Use fewer iterations for fuzzing performance
			Parallelism: 2,
			KeyLen:      32,
		}

		// Key derivation should never panic
		key1 := quantum.DeriveKey(password, salt, params)
		key2 := quantum.DeriveKey(password, salt, params)

		// Should be deterministic
		if !bytes.Equal(key1, key2) {
			t.Error("Key derivation is not deterministic")
		}

		// Should produce correct key length
		if len(key1) != int(params.KeyLen) {
			t.Errorf("Key length mismatch: got %d, expected %d", len(key1), params.KeyLen)
		}

		// Test deniable encryption modes
		normalKey := quantum.DeriveKeyWithMode(password, salt, params, false)
		decoyKey := quantum.DeriveKeyWithMode(password, salt, params, true)

		// Normal mode should match standard derivation
		if !bytes.Equal(key1, normalKey) {
			t.Error("Normal mode key doesn't match standard derivation")
		}

		// Decoy and normal modes should be different (unless zero-length password)
		if len(password) > 0 && bytes.Equal(normalKey, decoyKey) {
			t.Error("Normal and decoy keys are identical")
		}
	})
}

// FuzzMLKEMKeyValidation tests key validation with random key data
func FuzzMLKEMKeyValidation(f *testing.F) {
	// Generate a valid keypair for seeding
	validEncaps, validDecaps, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		f.Fatalf("Failed to generate valid keypair: %v", err)
	}

	// Seed with valid keys and variations
	f.Add(validEncaps)
	f.Add(validDecaps)
	f.Add(append(validEncaps, 0xFF))
	f.Add(validEncaps[:len(validEncaps)/2])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, len(validEncaps)))

	f.Fuzz(func(t *testing.T, keyData []byte) {
		// Skip extremely large inputs
		if len(keyData) > 10*1024 {
			t.Skip("Key data too large")
		}

		// Test if the fuzzing input can be used as an encapsulation key
		testData := []byte("test data for key validation")
		
		// This should either work with valid keys or fail gracefully with invalid ones
		_, _, err := quantum.EncryptDataPQC(testData, keyData)
		
		// We don't check for success/failure - just that it doesn't panic
		_ = err
	})
}
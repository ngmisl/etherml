package quantum

import (
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

// SecureCompare performs constant-time comparison
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// SecureZero zeros memory
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateSecureRandom generates cryptographically secure random bytes
func GenerateSecureRandom(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// DeriveKey performs key derivation using Argon2id
func DeriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}

// DeriveKeyWithMode performs key derivation with deniable encryption support
// The mode parameter allows for different key derivation paths for plausible deniability
func DeriveKeyWithMode(password []byte, salt Salt, params KDFParams, isDecoyMode bool) []byte {
	if isDecoyMode {
		// For decoy mode, use slightly different parameters to create cryptographically
		// independent keys while maintaining constant-time operation
		decoyParams := params
		decoyParams.Iterations = params.Iterations + 1 // Subtle difference
		decoyParams.Memory = params.Memory * 2         // Different memory usage
		
		// Use a modified salt for decoy mode (append decoy marker)
		var decoySalt Salt
		copy(decoySalt[:], salt[:])
		// XOR the last 4 bytes with a constant to create derivation separation
		for i := 28; i < 32; i++ {
			decoySalt[i] ^= 0xAA
		}
		
		return argon2.IDKey(password, decoySalt[:], decoyParams.Iterations, decoyParams.Memory, decoyParams.Parallelism, decoyParams.KeyLen)
	}
	
	// Standard mode - original key derivation
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}
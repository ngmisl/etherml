package quantum

import (
	"crypto/rand"
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
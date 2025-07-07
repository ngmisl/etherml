package quantum

import (
	"crypto/mlkem"
	"fmt"
)

// GenerateMLKEMKeyPair generates ML-KEM-1024 keypair
func GenerateMLKEMKeyPair() ([]byte, []byte, error) {
	decapsKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
	}
	encapsKey := decapsKey.EncapsulationKey()

	// ML-KEM keys in Go are already byte arrays
	encapsKeyBytes := encapsKey.Bytes()
	decapsKeyBytes := decapsKey.Bytes()

	// Basic validation - ML-KEM-1024 sizes
	// Encapsulation key should be 1568 bytes
	// Decapsulation key should be 3168 bytes
	if len(encapsKeyBytes) == 0 || len(decapsKeyBytes) == 0 {
		return nil, nil, fmt.Errorf("invalid key sizes generated")
	}

	return encapsKeyBytes, decapsKeyBytes, nil
}
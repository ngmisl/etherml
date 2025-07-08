package quantum

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptDataPQC encrypts data using ML-KEM-1024 + AES-256-GCM hybrid approach
func EncryptDataPQC(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, error) {
	// Create the encapsulation key
	encapsKey, err := mlkem.NewEncapsulationKey1024(encapsKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create encapsulation key: %w", err)
	}

	// Generate shared secret using ML-KEM-1024
	sharedSecret, ciphertext := encapsKey.Encapsulate()

	// Use shared secret as AES key (first 32 bytes for AES-256)
	aesKey := make([]byte, AESKeySize)
	copy(aesKey, sharedSecret[:AESKeySize])

	// Zero the shared secret immediately after copying
	SecureZero(sharedSecret[:])

	encrypted, nonce, err := encryptData(plaintext, aesKey)
	if err != nil {
		SecureZero(aesKey) // Zero AES key on error
		return nil, "", err
	}

	// Combine ML-KEM ciphertext with AES ciphertext
	combined := append(ciphertext, encrypted...)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])

	// Zero the AES key
	SecureZero(aesKey)

	return EncryptedData(combined), nonceB64, nil
}

// DecryptDataPQC decrypts data using ML-KEM-1024 + AES-256-GCM hybrid approach
func DecryptDataPQC(combined EncryptedData, decapsKeyBytes []byte, nonceB64 string) ([]byte, error) {
	// Create the decapsulation key
	decapsKey, err := mlkem.NewDecapsulationKey1024(decapsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create decapsulation key: %w", err)
	}

	// ML-KEM-1024 ciphertext is 1568 bytes
	if len(combined) < MLKEMCiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext: too short (got %d bytes, need at least %d)",
			len(combined), MLKEMCiphertextSize)
	}

	mlkemCiphertext := combined[:MLKEMCiphertextSize]
	aesCiphertext := combined[MLKEMCiphertextSize:]

	// Decapsulate to get shared secret
	sharedSecret, err := decapsKey.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	// Copy AES key to ensure we can zero both independently
	aesKey := make([]byte, AESKeySize)
	copy(aesKey, sharedSecret[:AESKeySize])

	// Zero shared secret immediately
	SecureZero(sharedSecret[:])

	// Decrypt with AES
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		SecureZero(aesKey)
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	var nonce Nonce
	copy(nonce[:], nonceBytes)

	plaintext, err := decryptData(EncryptedData(aesCiphertext), aesKey, nonce)

	// Always zero the AES key
	SecureZero(aesKey)

	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptData encrypts data using AES-256-GCM
func encryptData(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
	if len(key) != AESKeySize {
		return nil, Nonce{}, fmt.Errorf("invalid key length: got %d, expected %d", len(key), AESKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, Nonce{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Nonce{}, err
	}

	var nonce Nonce
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, Nonce{}, err
	}

	ciphertext := gcm.Seal(nil, nonce[:], plaintext, nil)
	return EncryptedData(ciphertext), nonce, nil
}

// decryptData decrypts data using AES-256-GCM
func decryptData(ciphertext EncryptedData, key []byte, nonce Nonce) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("invalid key length: got %d, expected %d", len(key), AESKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
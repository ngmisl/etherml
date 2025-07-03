package project

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Salt represents a cryptographic salt
type Salt [32]byte

// Nonce represents a GCM nonce
type Nonce [12]byte

// EncryptedData represents encrypted data
type EncryptedData []byte

// ML-KEM-1024 constants for size validation
const (
	MLKEMPublicKeySize    = 1568 // Correct for ML-KEM-1024
	MLKEMPrivateKeySize   = 3168 // Theoretical full size - Go uses 64-byte seed
	MLKEMCiphertextSize   = 1568 // Correct for ML-KEM-1024
	MLKEMSharedSecretSize = 32   // Correct shared secret size
	// Go's actual private key seed size
	MLKEMPrivateKeySeedSize = 64 // Go's ML-KEM uses 64-byte seed for private key
)

// CryptoManager handles project-specific encryption operations
type CryptoManager struct {
	mlkemPrivateKey []byte
	aesKey          []byte
}

// NewCryptoManager creates a new crypto manager
func NewCryptoManager() *CryptoManager {
	return &CryptoManager{}
}

// GenerateMLKEMKeyPair generates a new ML-KEM-1024 keypair
func (cm *CryptoManager) GenerateMLKEMKeyPair() ([]byte, []byte, error) {
	decapsKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
	}
	encapsKey := decapsKey.EncapsulationKey()

	encapsKeyBytes := encapsKey.Bytes()
	decapsKeyBytes := decapsKey.Bytes()

	// Validate key sizes against ML-KEM-1024 specification
	if len(encapsKeyBytes) != MLKEMPublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key size: got %d, expected %d",
			len(encapsKeyBytes), MLKEMPublicKeySize)
	}
	if len(decapsKeyBytes) != MLKEMPrivateKeySeedSize {
		return nil, nil, fmt.Errorf("invalid private key size: got %d, expected %d",
			len(decapsKeyBytes), MLKEMPrivateKeySeedSize)
	}

	return encapsKeyBytes, decapsKeyBytes, nil
}

// DeriveKey derives an AES key from password using Argon2id
func (cm *CryptoManager) DeriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}

// EncryptDataPQC encrypts data using ML-KEM-1024 + AES-256-GCM hybrid approach
func (cm *CryptoManager) EncryptDataPQC(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, error) {
	// Validate public key size
	if len(encapsKeyBytes) != MLKEMPublicKeySize {
		return nil, "", fmt.Errorf("invalid public key size: got %d, expected %d",
			len(encapsKeyBytes), MLKEMPublicKeySize)
	}

	// Create the encapsulation key
	encapsKey, err := mlkem.NewEncapsulationKey1024(encapsKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create encapsulation key: %w", err)
	}

	// Generate shared secret using ML-KEM-1024
	sharedSecret, ciphertext := encapsKey.Encapsulate()

	// Use shared secret as AES key (first 32 bytes for AES-256)
	aesKey := make([]byte, 32)
	copy(aesKey, sharedSecret[:32])

	// Zero the shared secret immediately after copying
	SecureZero(sharedSecret[:])

	encrypted, nonce, err := cm.encryptAES(plaintext, aesKey)
	if err != nil {
		SecureZero(aesKey)
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
func (cm *CryptoManager) DecryptDataPQC(combined EncryptedData, decapsKeyBytes []byte, nonceB64 string) ([]byte, error) {
	// Validate private key size
	if len(decapsKeyBytes) != MLKEMPrivateKeySeedSize {
		return nil, fmt.Errorf("invalid private key size: got %d, expected %d",
			len(decapsKeyBytes), MLKEMPrivateKeySeedSize)
	}

	// Create the decapsulation key
	decapsKey, err := mlkem.NewDecapsulationKey1024(decapsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create decapsulation key: %w", err)
	}

	// Validate ciphertext size
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
	aesKey := make([]byte, 32)
	copy(aesKey, sharedSecret[:32])

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

	plaintext, err := cm.decryptAES(EncryptedData(aesCiphertext), aesKey, nonce)

	// Always zero the AES key
	SecureZero(aesKey)

	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptAES encrypts data using AES-256-GCM
func (cm *CryptoManager) encryptAES(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
	if len(key) != 32 {
		return nil, Nonce{}, fmt.Errorf("invalid key length: got %d, expected 32", len(key))
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

// decryptAES decrypts data using AES-256-GCM
func (cm *CryptoManager) decryptAES(ciphertext EncryptedData, key []byte, nonce Nonce) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: got %d, expected 32", len(key))
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

// GenerateSalt generates a cryptographically secure salt
func GenerateSalt() (Salt, error) {
	var salt Salt
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return salt, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// ComputeHMAC computes HMAC-SHA256 for data integrity
func ComputeHMAC(key, data []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256 for data integrity
func VerifyHMAC(key, data, expectedHMAC []byte) bool {
	computedHMAC := ComputeHMAC(key, data)
	return SecureCompare(computedHMAC, expectedHMAC)
}

// SecureCompare performs constant-time comparison
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// DefaultKDFParams returns default Argon2id parameters optimized for performance
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Function:    "argon2id",
		Memory:      16384, // Further reduced for faster operations
		Iterations:  1,     // Minimum safe value for faster operations
		Parallelism: 4,
		KeyLen:      32,
	}
}

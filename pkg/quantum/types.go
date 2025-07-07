package quantum

// Type definitions for quantum-resistant cryptography
type (
	PrivateKey    [32]byte
	PublicKey     []byte
	Address       [20]byte
	Salt          [32]byte
	Nonce         [12]byte
	EncryptedData []byte
)

// ML-KEM-1024 Constants
const (
	// ML-KEM-1024 ciphertext is 1568 bytes
	MLKEMCiphertextSize = 1568
	
	// AES-256 key size
	AESKeySize = 32
	
	// Shared secret size from ML-KEM
	SharedSecretSize = 32
)
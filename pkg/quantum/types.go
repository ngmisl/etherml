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

// KDFParams for Argon2id configuration
type KDFParams struct {
	Function    string `json:"function"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"`
	KeyLen      uint32 `json:"key_len"`
}

// ML-KEM-1024 Constants
const (
	// ML-KEM-1024 ciphertext is 1568 bytes
	MLKEMCiphertextSize = 1568
	
	// AES-256 key size
	AESKeySize = 32
	
	// Shared secret size from ML-KEM
	SharedSecretSize = 32
)
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.design/x/clipboard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"wallet/pkg/project"
)

// Type definitions for type safety
type (
	PrivateKey    [32]byte
	PublicKey     []byte
	Address       [20]byte
	Salt          [32]byte
	Nonce         [12]byte
	EncryptedData []byte
)

// Wallet represents an Ethereum wallet
type Wallet struct {
	PrivateKey PrivateKey `json:"-"`
	Address    Address    `json:"address"`
	CreatedAt  time.Time  `json:"created_at"`
	Label      string     `json:"label,omitempty"`
}

// EncryptedWallet for storage
type EncryptedWallet struct {
	Address      string    `json:"address"`
	EncryptedKey string    `json:"encrypted_key"`
	Nonce        string    `json:"nonce"`
	CreatedAt    time.Time `json:"created_at"`
	Label        string    `json:"label,omitempty"`
}

// StorageFile represents the encrypted storage format with deniable encryption
type StorageFile struct {
	Version              string            `json:"version"`
	Algorithm            string            `json:"algorithm"`
	KDF                  KDFParams         `json:"kdf"`
	
	// Real wallet storage (opened with real password)
	MLKEMPublicKey       string            `json:"mlkem_public_key,omitempty"`
	MLKEMPrivateKeyEnc   string            `json:"mlkem_private_key_enc,omitempty"`
	MLKEMPrivateKeyNonce string            `json:"mlkem_private_key_nonce,omitempty"`
	EncryptedWallets     string            `json:"encrypted_wallets,omitempty"`
	HMAC                 string            `json:"hmac,omitempty"`
	
	// Decoy wallet storage (opened with decoy password)
	DecoyKDF             KDFParams         `json:"decoy_kdf"`
	DecoyMLKEMPublicKey  string            `json:"decoy_mlkem_public_key,omitempty"`
	DecoyMLKEMPrivateKeyEnc string         `json:"decoy_mlkem_private_key_enc,omitempty"`
	DecoyMLKEMPrivateKeyNonce string       `json:"decoy_mlkem_private_key_nonce,omitempty"`
	DecoyEncryptedWallets string           `json:"decoy_encrypted_wallets,omitempty"`
	DecoyHMAC            string            `json:"decoy_hmac,omitempty"`
	
	Wallets              []EncryptedWallet `json:"wallets"` // Legacy support
	UpdatedAt            time.Time         `json:"updated_at"`
}

// KDFParams for Argon2id
type KDFParams struct {
	Function    string `json:"function"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"`
	KeyLen      uint32 `json:"key_len"`
}

// WalletMode represents which wallet set is active
type WalletMode int

const (
	RealMode  WalletMode = iota // Real wallets (actual password)
	DecoyMode                   // Decoy wallets ("$5 wrench" password)
)

// WalletManager handles wallet operations with deniable encryption
type WalletManager struct {
	filePath        string
	storage         *StorageFile
	key             []byte
	mlkemPrivateKey []byte
	masterPassword  []byte
	mode            WalletMode // Current operating mode
	isDecoySetup    bool       // Whether decoy wallets have been initialized
}

// Result type for error handling
type Result[T any] struct {
	value T
	err   error
}

func Ok[T any](value T) Result[T] {
	return Result[T]{value: value}
}

func Err[T any](err error) Result[T] {
	return Result[T]{err: err}
}

func (r Result[T]) Unwrap() (T, error) {
	return r.value, r.err
}

// Option type for nullable values
type Option[T any] struct {
	value *T
}

func Some[T any](value T) Option[T] {
	return Option[T]{value: &value}
}

func None[T any]() Option[T] {
	return Option[T]{value: nil}
}

func (o Option[T]) IsSome() bool {
	return o.value != nil
}

func (o Option[T]) Unwrap() T {
	if o.value == nil {
		panic("unwrap on None")
	}
	return *o.value
}

// Secure string that zeros memory
type SecureString struct {
	data []byte
}

func NewSecureString(s string) *SecureString {
	return &SecureString{data: []byte(s)}
}

func (s *SecureString) String() string {
	return string(s.data)
}

func (s *SecureString) Bytes() []byte {
	return s.data
}

func (s *SecureString) Zero() {
	for i := range s.data {
		s.data[i] = 0
	}
}

// Generate new Ethereum wallet
func GenerateWallet() Result[*Wallet] {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return Err[*Wallet](fmt.Errorf("failed to generate key: %w", err))
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return Err[*Wallet](errors.New("failed to cast public key"))
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	wallet := &Wallet{
		CreatedAt: time.Now(),
	}

	// Copy private key bytes
	copy(wallet.PrivateKey[:], crypto.FromECDSA(privateKey))
	copy(wallet.Address[:], address.Bytes())

	// Zero the original key
	b := crypto.FromECDSA(privateKey)
	SecureZero(b)

	return Ok(wallet)
}

// Derive key using Argon2id
func deriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}

// Generate ML-KEM-1024 keypair
func generateMLKEMKeyPair() ([]byte, []byte, error) {
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

// Encrypt data using ML-KEM-1024 + AES-256-GCM hybrid approach
func encryptDataPQC(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, error) {
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

// Decrypt data using ML-KEM-1024 + AES-256-GCM hybrid approach
func decryptDataPQC(combined EncryptedData, decapsKeyBytes []byte, nonceB64 string) ([]byte, error) {
	// Create the decapsulation key
	decapsKey, err := mlkem.NewDecapsulationKey1024(decapsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create decapsulation key: %w", err)
	}

	// ML-KEM-1024 ciphertext is 1568 bytes
	const mlkemCiphertextSize = 1568
	if len(combined) < mlkemCiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext: too short (got %d bytes, need at least %d)",
			len(combined), mlkemCiphertextSize)
	}

	mlkemCiphertext := combined[:mlkemCiphertextSize]
	aesCiphertext := combined[mlkemCiphertextSize:]

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

	plaintext, err := decryptData(EncryptedData(aesCiphertext), aesKey, nonce)

	// Always zero the AES key
	SecureZero(aesKey)

	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

// Encrypt data using AES-256-GCM
func encryptData(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
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

// Decrypt data using AES-256-GCM
func decryptData(ciphertext EncryptedData, key []byte, nonce Nonce) ([]byte, error) {
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

// GenerateDummyWallets creates realistic-looking dummy wallets for decoy mode
func GenerateDummyWallets(count int) []Wallet {
	dummy := make([]Wallet, count)
	baseTime := time.Now().Add(-30 * 24 * time.Hour) // 30 days ago
	
	labels := []string{
		"Personal Wallet", "Trading Account", "DeFi Holdings", 
		"NFT Collection", "Emergency Fund", "Investment Portfolio",
		"Savings Account", "Gaming Wallet", "Test Wallet",
	}
	
	for i := 0; i < count; i++ {
		// Generate a realistic looking wallet
		result := GenerateWallet()
		if wallet, err := result.Unwrap(); err == nil {
			// Add realistic creation times spread over the past month
			wallet.CreatedAt = baseTime.Add(time.Duration(i*3) * 24 * time.Hour)
			
			// Add realistic labels
			if i < len(labels) {
				wallet.Label = labels[i]
			} else {
				wallet.Label = fmt.Sprintf("Wallet %d", i+1)
			}
			
			dummy[i] = *wallet
			
			// Zero the original wallet memory for security
			SecureZero(wallet.PrivateKey[:])
		}
	}
	
	return dummy
}

// initializeDecoyWallets sets up the decoy wallet system with dummy wallets
func (wm *WalletManager) initializeDecoyWallets(decoyPassword []byte) error {
	// Generate separate decoy KDF parameters with different salt
	var decoySalt Salt
	if _, err := io.ReadFull(rand.Reader, decoySalt[:]); err != nil {
		return fmt.Errorf("failed to generate decoy salt: %w", err)
	}
	
	wm.storage.DecoyKDF = KDFParams{
		Function:    "argon2id",
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		Salt:        base64.StdEncoding.EncodeToString(decoySalt[:]),
		KeyLen:      32,
	}
	
	// Derive decoy key
	decoyKey := deriveKey(decoyPassword, decoySalt, wm.storage.DecoyKDF)
	defer SecureZero(decoyKey)
	
	// Generate separate ML-KEM keypair for decoy wallets
	decoyEncapsKeyBytes, decoyDecapsKeyBytes, err := generateMLKEMKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate decoy ML-KEM keypair: %w", err)
	}
	defer SecureZero(decoyDecapsKeyBytes)
	
	// Encrypt the decoy ML-KEM private key
	encryptedDecoyPrivKey, decoyPrivKeyNonce, err := encryptData(decoyDecapsKeyBytes, decoyKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt decoy ML-KEM private key: %w", err)
	}
	
	// Store decoy ML-KEM keys
	wm.storage.DecoyMLKEMPublicKey = base64.StdEncoding.EncodeToString(decoyEncapsKeyBytes)
	wm.storage.DecoyMLKEMPrivateKeyEnc = base64.StdEncoding.EncodeToString(encryptedDecoyPrivKey)
	wm.storage.DecoyMLKEMPrivateKeyNonce = base64.StdEncoding.EncodeToString(decoyPrivKeyNonce[:])
	
	// Generate dummy wallets
	dummyWallets := GenerateDummyWallets(7) // Generate 7 dummy wallets
	
	// Encrypt dummy wallets using the decoy ML-KEM system
	var encryptedDummyWallets []EncryptedWallet
	for _, wallet := range dummyWallets {
		encrypted, nonce, err := encryptDataPQC(wallet.PrivateKey[:], decoyEncapsKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt dummy wallet: %w", err)
		}
		
		ew := EncryptedWallet{
			Address:      hex.EncodeToString(wallet.Address[:]),
			EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
			Nonce:        nonce,
			CreatedAt:    wallet.CreatedAt,
			Label:        wallet.Label,
		}
		encryptedDummyWallets = append(encryptedDummyWallets, ew)
		
		// Zero the dummy wallet's private key
		SecureZero(wallet.PrivateKey[:])
	}
	
	// Serialize and encrypt the decoy wallet collection
	decoyWalletData, err := json.Marshal(encryptedDummyWallets)
	if err != nil {
		return fmt.Errorf("failed to marshal decoy wallets: %w", err)
	}
	
	encryptedDecoyData, decoyDataNonce, err := encryptDataPQC(decoyWalletData, decoyEncapsKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt decoy wallet data: %w", err)
	}
	
	wm.storage.DecoyEncryptedWallets = base64.StdEncoding.EncodeToString(encryptedDecoyData)
	wm.storage.DecoyHMAC = decoyDataNonce
	
	wm.isDecoySetup = true
	return nil
}

// switchToDecoyMode switches the wallet manager to operate in decoy mode
func (wm *WalletManager) switchToDecoyMode(decoyPassword []byte) error {
	// Derive decoy key
	decoySalt, err := base64.StdEncoding.DecodeString(wm.storage.DecoyKDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode decoy salt: %w", err)
	}
	
	var s Salt
	copy(s[:], decoySalt)
	decoyKey := deriveKey(decoyPassword, s, wm.storage.DecoyKDF)
	
	// Decrypt decoy ML-KEM private key
	encryptedDecoyPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyEnc)
	if err != nil {
		SecureZero(decoyKey)
		return fmt.Errorf("failed to decode decoy ML-KEM private key: %w", err)
	}
	
	decoyPrivKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyNonce)
	if err != nil {
		SecureZero(decoyKey)
		return fmt.Errorf("failed to decode decoy ML-KEM private key nonce: %w", err)
	}
	
	var decoyPrivKeyNonce Nonce
	copy(decoyPrivKeyNonce[:], decoyPrivKeyNonceBytes)
	
	decoyMLKEMPrivateKey, err := decryptData(EncryptedData(encryptedDecoyPrivKey), decoyKey, decoyPrivKeyNonce)
	if err != nil {
		SecureZero(decoyKey)
		return fmt.Errorf("invalid decoy password: %w", err)
	}
	
	// Clear any existing real mode data and switch to decoy mode
	SecureZero(wm.key)
	if wm.mlkemPrivateKey != nil {
		SecureZero(wm.mlkemPrivateKey)
	}
	
	wm.key = decoyKey
	wm.mlkemPrivateKey = decoyMLKEMPrivateKey
	wm.mode = DecoyMode
	
	// Store decoy password for re-authentication
	if wm.masterPassword != nil {
		SecureZero(wm.masterPassword)
	}
	wm.masterPassword = make([]byte, len(decoyPassword))
	copy(wm.masterPassword, decoyPassword)
	
	return nil
}

// tryDecoyPassword attempts to authenticate with the provided password as a decoy password
func (wm *WalletManager) tryDecoyPassword(password []byte) bool {
	if wm.storage.DecoyKDF.Salt == "" {
		return false // No decoy system setup
	}
	
	// Try to derive decoy key and decrypt decoy ML-KEM private key
	decoySalt, err := base64.StdEncoding.DecodeString(wm.storage.DecoyKDF.Salt)
	if err != nil {
		return false
	}
	
	var s Salt
	copy(s[:], decoySalt)
	decoyKey := deriveKey(password, s, wm.storage.DecoyKDF)
	defer SecureZero(decoyKey)
	
	// Try to decrypt decoy ML-KEM private key
	encryptedDecoyPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyEnc)
	if err != nil {
		return false
	}
	
	decoyPrivKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyNonce)
	if err != nil {
		return false
	}
	
	var decoyPrivKeyNonce Nonce
	copy(decoyPrivKeyNonce[:], decoyPrivKeyNonceBytes)
	
	_, err = decryptData(EncryptedData(encryptedDecoyPrivKey), decoyKey, decoyPrivKeyNonce)
	return err == nil
}

// tryRealPassword attempts to authenticate with the provided password as the real password
func (wm *WalletManager) tryRealPassword(password []byte) bool {
	if wm.storage.KDF.Salt == "" {
		return false // No real system setup
	}
	
	// Try to derive real key and decrypt real ML-KEM private key
	salt, err := base64.StdEncoding.DecodeString(wm.storage.KDF.Salt)
	if err != nil {
		return false
	}
	
	var s Salt
	copy(s[:], salt)
	realKey := deriveKey(password, s, wm.storage.KDF)
	defer SecureZero(realKey)
	
	// Try to decrypt real ML-KEM private key
	encryptedPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyEnc)
	if err != nil {
		return false
	}
	
	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyNonce)
	if err != nil {
		return false
	}
	
	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)
	
	_, err = decryptData(EncryptedData(encryptedPrivKey), realKey, privKeyNonce)
	return err == nil
}

// detectPasswordType determines whether the provided password is real or decoy
func (wm *WalletManager) detectPasswordType(password []byte) WalletMode {
	// First check if it's a real password
	if wm.tryRealPassword(password) {
		return RealMode
	}
	
	// Then check if it's a decoy password
	if wm.tryDecoyPassword(password) {
		return DecoyMode
	}
	
	// If neither works, default to real mode (this will cause an error later)
	return RealMode
}

// switchToRealMode switches the wallet manager to operate in real mode
func (wm *WalletManager) switchToRealMode(realPassword []byte) error {
	// Derive real key
	salt, err := base64.StdEncoding.DecodeString(wm.storage.KDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}
	
	var s Salt
	copy(s[:], salt)
	realKey := deriveKey(realPassword, s, wm.storage.KDF)
	
	// Decrypt real ML-KEM private key
	encryptedPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyEnc)
	if err != nil {
		SecureZero(realKey)
		return fmt.Errorf("failed to decode ML-KEM private key: %w", err)
	}
	
	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyNonce)
	if err != nil {
		SecureZero(realKey)
		return fmt.Errorf("failed to decode ML-KEM private key nonce: %w", err)
	}
	
	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)
	
	realMLKEMPrivateKey, err := decryptData(EncryptedData(encryptedPrivKey), realKey, privKeyNonce)
	if err != nil {
		SecureZero(realKey)
		return fmt.Errorf("invalid real password: %w", err)
	}
	
	// Clear any existing decoy mode data and switch to real mode
	SecureZero(wm.key)
	if wm.mlkemPrivateKey != nil {
		SecureZero(wm.mlkemPrivateKey)
	}
	
	wm.key = realKey
	wm.mlkemPrivateKey = realMLKEMPrivateKey
	wm.mode = RealMode
	
	// Store real password for re-authentication
	if wm.masterPassword != nil {
		SecureZero(wm.masterPassword)
	}
	wm.masterPassword = make([]byte, len(realPassword))
	copy(wm.masterPassword, realPassword)
	
	return nil
}

// NewWalletManager creates a new wallet manager
func NewWalletManager(filePath string) *WalletManager {
	return &WalletManager{
		filePath: filePath,
		storage: &StorageFile{
			Version:   "1.0",
			Algorithm: "mlkem1024-aes256gcm",
			Wallets:   []EncryptedWallet{},
		},
		mode:         RealMode, // Default to real mode
		isDecoySetup: false,
	}
}

// Initialize or load storage with dual-password support
func (wm *WalletManager) Initialize(password []byte) error {
	// Check if file exists
	if _, err := os.Stat(wm.filePath); os.IsNotExist(err) {
		// NEW FILE: Set up both real and decoy encryption systems
		
		// Set up real wallet system (actual password)
		var salt Salt
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}

		wm.storage.KDF = KDFParams{
			Function:    "argon2id",
			Memory:      65536,
			Iterations:  3,
			Parallelism: 4,
			Salt:        base64.StdEncoding.EncodeToString(salt[:]),
			KeyLen:      32,
		}

		// Derive the real key
		wm.key = deriveKey(password, salt, wm.storage.KDF)

		// Generate real ML-KEM keypair
		encapsKeyBytes, decapsKeyBytes, err := generateMLKEMKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate real ML-KEM keypair: %w", err)
		}

		// Encrypt the real ML-KEM private key
		encryptedPrivKey, privKeyNonce, err := encryptData(decapsKeyBytes, wm.key)
		if err != nil {
			return fmt.Errorf("failed to encrypt real ML-KEM private key: %w", err)
		}

		// Store real ML-KEM keys
		wm.storage.MLKEMPublicKey = base64.StdEncoding.EncodeToString(encapsKeyBytes)
		wm.storage.MLKEMPrivateKeyEnc = base64.StdEncoding.EncodeToString(encryptedPrivKey)
		wm.storage.MLKEMPrivateKeyNonce = base64.StdEncoding.EncodeToString(privKeyNonce[:])

		// Store the real private key in memory
		wm.mlkemPrivateKey = decapsKeyBytes

		// Prompt for decoy password and set up decoy system
		fmt.Print(infoStyle.Render("🔐 For deniable encryption, enter a different decoy password: "))
		decoyPassword, err := readPassword("")
		if err != nil {
			return fmt.Errorf("failed to read decoy password: %w", err)
		}
		defer SecureZero(decoyPassword)

		// Initialize decoy wallet system
		if err := wm.initializeDecoyWallets(decoyPassword); err != nil {
			return fmt.Errorf("failed to initialize decoy wallets: %w", err)
		}

		// Store real password for re-authentication and set mode
		wm.masterPassword = make([]byte, len(password))
		copy(wm.masterPassword, password)
		wm.mode = RealMode

		return wm.Save()
	}

	// EXISTING FILE: Load and detect which password type is being used
	return wm.Load(password)
}

// Load storage file with dual-password detection
func (wm *WalletManager) Load(password []byte) error {
	data, err := os.ReadFile(wm.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(data, &wm.storage); err != nil {
		return fmt.Errorf("failed to unmarshal storage: %w", err)
	}

	// Ensure this is a post-quantum format
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return fmt.Errorf("unsupported storage format: %s. This wallet only supports ML-KEM post-quantum encryption", wm.storage.Algorithm)
	}

	// CRITICAL: Detect which password type is being used
	passwordType := wm.detectPasswordType(password)

	switch passwordType {
	case RealMode:
		// User entered the real password - load real wallets
		if err := wm.switchToRealMode(password); err != nil {
			return fmt.Errorf("failed to load real wallets: %w", err)
		}
		
		// Verify real password by trying to decrypt first real wallet (if any exist)
		if len(wm.storage.Wallets) > 0 {
			_, err := wm.decryptWallet(&wm.storage.Wallets[0])
			if err != nil {
				return fmt.Errorf("real password verification failed: %w", err)
			}
		}

	case DecoyMode:
		// User entered the decoy password - load decoy wallets
		if err := wm.switchToDecoyMode(password); err != nil {
			return fmt.Errorf("failed to load decoy wallets: %w", err)
		}
		
		// Clear real wallets from memory to maintain deniability
		wm.storage.Wallets = []EncryptedWallet{}

	default:
		return fmt.Errorf("invalid password - authentication failed")
	}

	return nil
}

// Save storage file
func (wm *WalletManager) Save() error {
	wm.storage.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(wm.storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal storage: %w", err)
	}

	// Write atomically
	tmpFile := wm.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := os.Rename(tmpFile, wm.filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// Add wallet to storage using ML-KEM post-quantum encryption
func (wm *WalletManager) AddWallet(wallet *Wallet) error {
	// Ensure we have ML-KEM setup
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" || wm.storage.MLKEMPublicKey == "" {
		return fmt.Errorf("ML-KEM encryption not initialized")
	}

	// Decode the ML-KEM public key
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM public key: %w", err)
	}

	// Use post-quantum encryption
	encrypted, nonce, err := encryptDataPQC(wallet.PrivateKey[:], encapsKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt key with ML-KEM: %w", err)
	}

	ew := EncryptedWallet{
		Address:      hex.EncodeToString(wallet.Address[:]),
		EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
		Nonce:        nonce,
		CreatedAt:    wallet.CreatedAt,
		Label:        wallet.Label,
	}

	wm.storage.Wallets = append(wm.storage.Wallets, ew)
	return wm.Save()
}

// List all wallets (real or decoy depending on current mode)
func (wm *WalletManager) ListWallets() ([]Wallet, error) {
	if wm.mode == DecoyMode {
		// Return decoy wallets when in decoy mode
		return wm.listDecoyWallets()
	}

	// Return real wallets when in real mode
	wallets := make([]Wallet, 0, len(wm.storage.Wallets))

	for _, ew := range wm.storage.Wallets {
		wallet, err := wm.decryptWallet(&ew)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt wallet %s: %w", ew.Address, err)
		}
		wallets = append(wallets, *wallet)
	}

	return wallets, nil
}

// listDecoyWallets returns the dummy wallets for decoy mode
func (wm *WalletManager) listDecoyWallets() ([]Wallet, error) {
	if wm.storage.DecoyEncryptedWallets == "" {
		return []Wallet{}, nil // No decoy wallets setup
	}

	// Decrypt the decoy wallet collection
	encryptedDecoyData, err := base64.StdEncoding.DecodeString(wm.storage.DecoyEncryptedWallets)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decoy wallet data: %w", err)
	}

	decoyWalletData, err := decryptDataPQC(EncryptedData(encryptedDecoyData), wm.mlkemPrivateKey, wm.storage.DecoyHMAC)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt decoy wallet collection: %w", err)
	}

	// Unmarshal the encrypted wallet list
	var encryptedDecoyWallets []EncryptedWallet
	if err := json.Unmarshal(decoyWalletData, &encryptedDecoyWallets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decoy wallets: %w", err)
	}

	// Decrypt each decoy wallet
	var wallets []Wallet
	for _, ew := range encryptedDecoyWallets {
		wallet, err := wm.decryptDecoyWallet(&ew)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt decoy wallet %s: %w", ew.Address, err)
		}
		wallets = append(wallets, *wallet)
	}

	return wallets, nil
}

// decryptDecoyWallet decrypts a single decoy wallet
func (wm *WalletManager) decryptDecoyWallet(ew *EncryptedWallet) (*Wallet, error) {
	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Use decoy ML-KEM decryption
	decrypted, err := decryptDataPQC(EncryptedData(encrypted), wm.mlkemPrivateKey, ew.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoy ML-KEM decryption failed: %w", err)
	}

	addressBytes, err := hex.DecodeString(ew.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	wallet := &Wallet{
		CreatedAt: ew.CreatedAt,
		Label:     ew.Label,
	}
	copy(wallet.PrivateKey[:], decrypted)
	copy(wallet.Address[:], addressBytes)

	// Zero the decrypted key data
	SecureZero(decrypted)

	return wallet, nil
}

// Delete wallet from storage
func (wm *WalletManager) DeleteWallet(address string) error {
	// Find and remove the wallet with matching address
	for i, ew := range wm.storage.Wallets {
		if strings.EqualFold(ew.Address, address) {
			// Remove wallet from slice
			wm.storage.Wallets = append(wm.storage.Wallets[:i], wm.storage.Wallets[i+1:]...)
			return wm.Save()
		}
	}
	return fmt.Errorf("wallet with address %s not found", address)
}

// Decrypt wallet using ML-KEM post-quantum decryption
func (wm *WalletManager) decryptWallet(ew *EncryptedWallet) (*Wallet, error) {
	// Ensure we have ML-KEM setup
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", wm.storage.Algorithm)
	}

	if wm.mlkemPrivateKey == nil {
		return nil, fmt.Errorf("ML-KEM private key not available")
	}

	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Use post-quantum decryption
	decrypted, err := decryptDataPQC(EncryptedData(encrypted), wm.mlkemPrivateKey, ew.Nonce)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decryption failed: %w", err)
	}

	addressBytes, err := hex.DecodeString(ew.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	wallet := &Wallet{
		CreatedAt: ew.CreatedAt,
		Label:     ew.Label,
	}
	copy(wallet.PrivateKey[:], decrypted)
	copy(wallet.Address[:], addressBytes)

	// Zero the decrypted key data
	SecureZero(decrypted)

	return wallet, nil
}

// Enhanced TUI Components

type model struct {
	list              list.Model
	walletMgr         *WalletManager
	wallets           []Wallet
	filteredWallets   []Wallet
	err               error
	quitting          bool
	input             textinput.Model
	passwordInput     textinput.Model
	inputMode         string
	searchQuery       string
	help              help.Model
	keys              keyMap
	status            string
	statusColor       lipgloss.Color
	showingPrivateKey bool
	selectedWallet    *Wallet
	confirmingDelete  bool
	walletToDelete    *Wallet
	width             int
	height            int
	spinner           spinner.Model
	loading           bool
	loadingMsg        string
	selectedIndex     int     // Track selection for grid layout
	editingWallet     *Wallet // Wallet currently being edited
	
	// Project management
	projectMgr     project.ProjectManager
	projectMode    bool
	projectModel   tea.Model
}

type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	New      key.Binding
	Delete   key.Binding
	Export   key.Binding
	Copy     key.Binding
	Search   key.Binding
	Projects key.Binding
	Quit     key.Binding
	Help     key.Binding
	Enter    key.Binding
	Escape   key.Binding
	Tab      key.Binding
	ShiftTab key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	New: key.NewBinding(
		key.WithKeys("n"),
		key.WithHelp("n", "new wallet"),
	),
	Delete: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "delete"),
	),
	Export: key.NewBinding(
		key.WithKeys("e"),
		key.WithHelp("e", "export key"),
	),
	Copy: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "copy address"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search"),
	),
	Projects: key.NewBinding(
		key.WithKeys("p"),
		key.WithHelp("p", "projects"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("⏎", "confirm"),
	),
	Escape: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "cancel"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next"),
	),
	ShiftTab: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("⇧tab", "prev"),
	),
}

type item struct {
	wallet Wallet
}

// Catppuccin Mocha Color Palette
const (
	// Primary colors
	primaryColor   = "#89b4fa" // Blue
	secondaryColor = "#a6e3a1" // Green
	accentColor    = "#fab387" // Peach
	mauveColor     = "#cba6f7" // Mauve

	// Semantic colors
	successColor = "#a6e3a1" // Green
	warningColor = "#f9e2af" // Yellow
	errorColor   = "#f38ba8" // Red
	infoColor    = "#94e2d5" // Teal

	// Text colors
	textColor     = "#cdd6f4" // Text
	subtext1Color = "#bac2de" // Subtext1
	subtext0Color = "#a6adc8" // Subtext0

	// Surface colors
	bgColor       = "#1e1e2e" // Base
	mantleColor   = "#181825" // Mantle
	crustColor    = "#11111b" // Crust
	cardBgColor   = "#313244" // Surface0
	surface1Color = "#45475a" // Surface1
	surface2Color = "#585b70" // Surface2

	// Overlay colors
	mutedColor    = "#6c7086" // Overlay0
	overlay1Color = "#7f849c" // Overlay1
	overlay2Color = "#9399b2" // Overlay2
	borderColor   = "#45475a" // Surface1

	// Special colors
	highlightColor = "#b4befe" // Lavender
	rosewaterColor = "#f5e0dc" // Rosewater
	pinkColor      = "#f5c2e7" // Pink
)

// Enhanced Styles
var (
	// Base styles
	baseStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor))

	// Message styles
	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(successColor)).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(errorColor)).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(warningColor)).
			Bold(true)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(infoColor)).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext0Color))

	// Enhanced layout styles
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor)).
			Background(lipgloss.Color(mantleColor)).
			Bold(true).
			Padding(1, 2).
			MarginBottom(1).
			Align(lipgloss.Center)

	cardStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(textColor)).
			Background(lipgloss.Color(cardBgColor)).
			Padding(0, 1).
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color(borderColor))

	selectedCardStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(crustColor)).
				Background(lipgloss.Color(primaryColor)).
				Bold(true).
				Padding(0, 1).
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color(primaryColor))

	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(mauveColor)).
			Background(lipgloss.Color(surface2Color)).
			Padding(2, 4).
			AlignHorizontal(lipgloss.Center).
			AlignVertical(lipgloss.Center)

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color(cardBgColor)).
			Foreground(lipgloss.Color(textColor)).
			Padding(0, 1).
			MarginTop(1)

	helpBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext1Color)).
			Background(lipgloss.Color(mantleColor)).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(primaryColor)).
			Bold(true).
			MarginBottom(1).
			Align(lipgloss.Center)

	addressStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(accentColor)).
			Bold(true)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(secondaryColor)).
			Italic(true)

	iconStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(primaryColor))

	quantumBadgeStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(crustColor)).
				Background(lipgloss.Color(mauveColor)).
				Padding(0, 1).
				Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(borderColor)).
			Padding(1, 2)
)

func (i item) FilterValue() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	return i.wallet.Label + " 0x" + addr
}

func (i item) Title() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	addressStr := formatAddress(addr)

	if i.wallet.Label != "" {
		// Don't apply inline styling - let the delegate handle selection styling
		return fmt.Sprintf("🔐 %s (%s)", i.wallet.Label, addressStr)
	}
	return fmt.Sprintf("🔐 %s", addressStr)
}

func (i item) Description() string {
	timeAgo := humanizeTime(i.wallet.CreatedAt)
	return fmt.Sprintf("📅 Created %s", timeAgo)
}

// Format address for display
func formatAddress(addr string) string {
	if len(addr) >= 16 {
		return "0x" + addr[:6] + "..." + addr[len(addr)-4:]
	}
	return "0x" + addr
}

// Humanize time display
func humanizeTime(t time.Time) string {
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		return fmt.Sprintf("%d min ago", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	case diff < 7*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	default:
		return t.Format("Jan 2, 2006")
	}
}

// Initialize clipboard
func initClipboard() error {
	err := clipboard.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize clipboard: %w", err)
	}
	return nil
}

// Copy to clipboard with timeout
func copyToClipboard(text string, timeout time.Duration) error {
	clipboard.Write(clipboard.FmtText, []byte(text))

	// Clear clipboard after timeout for sensitive data
	if timeout > 0 {
		go func() {
			time.Sleep(timeout)
			clipboard.Write(clipboard.FmtText, []byte(""))
		}()
	}

	return nil
}

// Filter wallets based on search query
func filterWallets(wallets []Wallet, query string) []Wallet {
	if query == "" {
		return wallets
	}

	query = strings.ToLower(query)
	var filtered []Wallet

	for _, wallet := range wallets {
		addr := strings.ToLower(hex.EncodeToString(wallet.Address[:]))
		label := strings.ToLower(wallet.Label)

		if strings.Contains(addr, query) || strings.Contains(label, query) {
			filtered = append(filtered, wallet)
		}
	}

	return filtered
}

// Loading complete message
type loadingCompleteMsg struct{}

func initialModel(walletMgr *WalletManager) model {
	wallets, err := walletMgr.ListWallets()
	if err != nil {
		wallets = []Wallet{} // Empty list on error
	}

	items := make([]list.Item, len(wallets))
	for i, w := range wallets {
		items[i] = item{wallet: w}
	}

	const defaultWidth = 100
	const listHeight = 25 // Sheet-style with more visible wallets

	// Create enhanced delegate
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = selectedCardStyle
	delegate.Styles.SelectedDesc = selectedCardStyle.Copy().Foreground(lipgloss.Color(crustColor))
	delegate.Styles.NormalTitle = cardStyle
	delegate.Styles.NormalDesc = mutedStyle
	delegate.SetHeight(3)  // Restore stable height for proper list calculations
	delegate.SetSpacing(1) // Add spacing back for list component stability

	l := list.New(items, delegate, defaultWidth, listHeight)
	l.Title = ""
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowPagination(true)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(overlay2Color)).
		Align(lipgloss.Right)

	// Input for wallet labels
	ti := textinput.New()
	ti.Placeholder = "Enter wallet label..."
	ti.CharLimit = 50
	ti.Width = 50
	ti.PromptStyle = labelStyle
	ti.TextStyle = baseStyle

	// Password input for sensitive operations
	pi := textinput.New()
	pi.Placeholder = "Enter master password..."
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.CharLimit = 100
	pi.Width = 50
	pi.PromptStyle = warningStyle
	pi.TextStyle = baseStyle

	// Spinner for loading states
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(primaryColor))

	// Initialize project manager
	homeDir, _ := os.UserHomeDir()
	projectsDir := filepath.Join(homeDir, ".qwallet", "projects")
	projectMgr := project.NewManager(projectsDir)

	return model{
		list:            l,
		walletMgr:       walletMgr,
		wallets:         wallets,
		filteredWallets: wallets,
		input:           ti,
		passwordInput:   pi,
		help:            help.New(),
		keys:            keys,
		status:          infoStyle.Render(fmt.Sprintf("✨ Ready - %d wallet(s) loaded", len(wallets))),
		statusColor:     lipgloss.Color(primaryColor),
		spinner:         s,
		selectedIndex:   0, // Initialize grid selection
		projectMgr:      projectMgr,
		projectMode:     false,
		projectModel:    nil,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		textinput.Blink,
	)
}

// Helper function to refresh wallet list
func (m *model) refreshWalletList() {
	wallets, err := m.walletMgr.ListWallets()
	if err != nil {
		m.status = errorStyle.Render("❌ Failed to load wallets: " + err.Error())
		return
	}

	m.wallets = wallets
	m.filteredWallets = filterWallets(wallets, m.searchQuery)

	// Create new items and completely reset the list
	items := make([]list.Item, len(m.filteredWallets))
	for i, w := range m.filteredWallets {
		items[i] = item{wallet: w}
	}

	// Set items and reset selection to top
	m.list.SetItems(items)
	m.selectedIndex = 0 // Reset to top for grid layout
	if len(items) > 0 && m.selectedIndex >= len(items) {
		m.selectedIndex = len(items) - 1
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// With compact header, almost entire screen available for wallets
		availableHeight := msg.Height - 2 // Only subtract header space
		if availableHeight < 10 {
			availableHeight = 10
		}
		m.list.SetSize(msg.Width, availableHeight) // Full width for sheet appearance

		// Update project model size if in project mode
		if m.projectMode && m.projectModel != nil {
			var cmd tea.Cmd
			m.projectModel, cmd = m.projectModel.Update(msg)
			cmds = append(cmds, cmd)
		}

		return m, tea.Batch(cmds...)

	case loadingCompleteMsg:
		m.loading = false
		m.refreshWalletList()
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			m.spinner, _ = m.spinner.Update(msg)
			cmds = append(cmds, m.spinner.Tick)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		// Handle project mode first
		if m.projectMode && m.projectModel != nil {
			var cmd tea.Cmd
			m.projectModel, cmd = m.projectModel.Update(msg)
			
			// Check if project model wants to quit back to main
			if cmd != nil {
				if _, ok := cmd().(tea.QuitMsg); ok {
					m.projectMode = false
					m.projectModel = nil
					m.status = infoStyle.Render("🔙 Back to wallet view")
					return m, nil
				}
			}
			
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		// Handle private key display interactions
		if m.showingPrivateKey {
			switch msg.String() {
			case "c", "C":
				// Copy private key again
				if m.selectedWallet != nil {
					privateKeyHex := "0x" + hex.EncodeToString(m.selectedWallet.PrivateKey[:])
					copyToClipboard(privateKeyHex, 30*time.Second)
					m.status = successStyle.Render("📋 Private key copied again (auto-clears in 30s)")
				}
				return m, nil
			default:
				// Clear private key display on any other key
				m.showingPrivateKey = false
				if m.selectedWallet != nil {
					SecureZero(m.selectedWallet.PrivateKey[:])
					m.selectedWallet = nil
				}
				m.status = infoStyle.Render("🔒 Private key cleared from memory")
				return m, nil
			}
		}

		// Handle delete confirmation
		if m.confirmingDelete {
			switch msg.String() {
			case "y", "Y":
				if m.walletToDelete != nil {
					addr := hex.EncodeToString(m.walletToDelete.Address[:])
					if err := m.walletMgr.DeleteWallet(addr); err == nil {
						m.refreshWalletList()
						m.status = successStyle.Render(fmt.Sprintf("✅ Wallet deleted: %s", formatAddress(addr)))
					} else {
						m.status = errorStyle.Render("❌ Failed to delete wallet: " + err.Error())
					}
				}
				m.confirmingDelete = false
				m.walletToDelete = nil
				return m, nil
			case "n", "N", "esc":
				m.confirmingDelete = false
				m.walletToDelete = nil
				m.status = infoStyle.Render("❌ Delete cancelled")
				return m, nil
			}
			return m, nil
		}

		// Handle input modes
		if m.inputMode != "" {
			switch msg.String() {
			case "enter":
				switch m.inputMode {
				case "new":
					// Capture the label value before clearing input
					walletLabel := m.input.Value()
					m.loading = true
					m.loadingMsg = "Creating quantum-resistant wallet..."

					// Create wallet in background
					go func() {
						// Simulate some work for better UX
						time.Sleep(500 * time.Millisecond)

						// Create new wallet with label
						result := GenerateWallet()
						if wallet, err := result.Unwrap(); err == nil {
							wallet.Label = walletLabel

							if err := m.walletMgr.AddWallet(wallet); err == nil {
								addr := hex.EncodeToString(wallet.Address[:])
								m.status = successStyle.Render(fmt.Sprintf("✅ Wallet created! %s", formatAddress(addr)))
								// Zero the private key in memory
								SecureZero(wallet.PrivateKey[:])
							} else {
								m.status = errorStyle.Render("❌ Failed to save wallet: " + err.Error())
							}
						} else {
							m.status = errorStyle.Render("❌ Failed to generate wallet: " + err.Error())
						}
					}()

					// Set a timer to complete loading
					cmds = append(cmds, tea.Tick(time.Second, func(t time.Time) tea.Msg {
						return loadingCompleteMsg{}
					}))

				case "search":
					m.searchQuery = m.input.Value()
					m.refreshWalletList()
					if m.searchQuery == "" {
						m.status = infoStyle.Render("🔍 Search cleared - showing all wallets")
					} else {
						m.status = infoStyle.Render(fmt.Sprintf("🔍 Found %d wallet(s) matching '%s'", len(m.filteredWallets), m.searchQuery))
					}
				case "password":
					// Verify password and show private key
					if m.selectedWallet != nil {
						password := m.passwordInput.Value()
						if SecureCompare([]byte(password), m.walletMgr.masterPassword) {
							m.showingPrivateKey = true
							m.status = warningStyle.Render("🔓 Private key displayed - Press any key to clear")
						} else {
							m.status = errorStyle.Render("❌ Invalid password")
						}
					}
				case "edit":
					// Update wallet label
					if m.editingWallet != nil {
						newLabel := m.input.Value()
						// Find the wallet in storage and update it
						for i, ew := range m.walletMgr.storage.Wallets {
							if strings.EqualFold(ew.Address, hex.EncodeToString(m.editingWallet.Address[:])) {
								m.walletMgr.storage.Wallets[i].Label = newLabel
								if err := m.walletMgr.Save(); err != nil {
									m.status = errorStyle.Render("❌ Failed to save label: " + err.Error())
								} else {
									m.status = successStyle.Render(fmt.Sprintf("✅ Label updated: %s", newLabel))
									m.refreshWalletList()
								}
								break
							}
						}
						m.editingWallet = nil
					}
				}
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				return m, tea.Batch(cmds...)
			case "esc":
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				m.showingPrivateKey = false
				m.selectedWallet = nil
				m.editingWallet = nil
				m.status = infoStyle.Render("❌ Cancelled")
				return m, nil
			}

			// Update the appropriate input
			var cmd tea.Cmd
			if m.inputMode == "password" {
				m.passwordInput, cmd = m.passwordInput.Update(msg)
			} else {
				m.input, cmd = m.input.Update(msg)
			}
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		// Handle grid navigation
		switch {
		case key.Matches(msg, m.keys.Up):
			if len(m.filteredWallets) > 0 {
				// Calculate grid dimensions for navigation
				walletWidth := 45
				maxCols := m.width / walletWidth
				if maxCols < 1 {
					maxCols = 1
				}
				if maxCols > 4 {
					maxCols = 4
				}

				newIndex := m.selectedIndex - maxCols
				if newIndex < 0 {
					newIndex = 0
				}
				m.selectedIndex = newIndex
			}
			return m, nil

		case key.Matches(msg, m.keys.Down):
			if len(m.filteredWallets) > 0 {
				// Calculate grid dimensions for navigation
				walletWidth := 45
				maxCols := m.width / walletWidth
				if maxCols < 1 {
					maxCols = 1
				}
				if maxCols > 4 {
					maxCols = 4
				}

				newIndex := m.selectedIndex + maxCols
				if newIndex >= len(m.filteredWallets) {
					newIndex = len(m.filteredWallets) - 1
				}
				m.selectedIndex = newIndex
			}
			return m, nil

		case msg.String() == "left", msg.String() == "h":
			if len(m.filteredWallets) > 0 && m.selectedIndex > 0 {
				m.selectedIndex--
			}
			return m, nil

		case msg.String() == "right", msg.String() == "l":
			if len(m.filteredWallets) > 0 && m.selectedIndex < len(m.filteredWallets)-1 {
				m.selectedIndex++
			}
			return m, nil
		}

		// Handle main key bindings
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit

		case key.Matches(msg, m.keys.New):
			m.inputMode = "new"
			m.input.Placeholder = "Enter wallet label (optional)..."
			m.input.Focus()
			m.status = infoStyle.Render("✨ Creating new quantum-resistant wallet...")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Search):
			m.inputMode = "search"
			m.input.Placeholder = "Search by label or address..."
			m.input.SetValue(m.searchQuery)
			m.input.Focus()
			m.status = infoStyle.Render("🔍 Search mode - type to filter wallets")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Copy):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				addr := "0x" + hex.EncodeToString(wallet.Address[:])
				if err := copyToClipboard(addr, 0); err == nil {
					m.status = successStyle.Render(fmt.Sprintf("📋 Address copied: %s", formatAddress(hex.EncodeToString(wallet.Address[:]))))
				} else {
					m.status = errorStyle.Render("❌ Failed to copy address")
				}
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to copy")
			}
			return m, nil

		case key.Matches(msg, m.keys.Export):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.selectedWallet = &wallet
				m.inputMode = "password"
				m.passwordInput.Focus()
				m.status = warningStyle.Render("🔐 Enter master password to view private key")
				return m, textinput.Blink
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to export")
			}
			return m, nil

		case key.Matches(msg, m.keys.Delete):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.walletToDelete = &wallet
				m.confirmingDelete = true
				addr := hex.EncodeToString(wallet.Address[:])
				m.status = warningStyle.Render(fmt.Sprintf("⚠️ Delete wallet %s? (y/N)", formatAddress(addr)))
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to delete")
			}
			return m, nil

		case key.Matches(msg, m.keys.Enter):
			if len(m.filteredWallets) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filteredWallets) {
				wallet := m.filteredWallets[m.selectedIndex]
				m.editingWallet = &wallet
				m.inputMode = "edit"
				m.input.Placeholder = "Enter new label..."
				m.input.SetValue(wallet.Label)
				m.input.Focus()
				m.status = infoStyle.Render("✏️ Editing wallet label - Enter to save, Esc to cancel")
				return m, textinput.Blink
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to edit")
			}
			return m, nil

		case key.Matches(msg, m.keys.Projects):
			// Switch to project mode
			m.projectMode = true
			if m.projectModel == nil {
				m.projectModel = project.NewProjectTUIModel(m.projectMgr)
				// Initialize with current window size
				if m.width > 0 && m.height > 0 {
					m.projectModel, _ = m.projectModel.Update(tea.WindowSizeMsg{
						Width:  m.width,
						Height: m.height,
					})
				}
			}
			m.status = infoStyle.Render("📁 Entering project mode...")
			return m, nil

		// Add a refresh key binding to reset list state if it gets stuck
		case key.Matches(msg, key.NewBinding(key.WithKeys("r"))):
			if m.inputMode == "" {
				m.refreshWalletList()
				m.status = infoStyle.Render("🔄 List refreshed")
				return m, nil
			}
		}
	}

	// Update list if not in input mode
	if m.inputMode == "" && !m.loading {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// Render wallets in a multi-column grid layout
func (m model) renderWalletGrid() string {
	if len(m.filteredWallets) == 0 {
		emptyMessage := lipgloss.NewStyle().
			Foreground(lipgloss.Color(subtext1Color)).
			Italic(true).
			Padding(2, 0).
			Render("No wallets found. Press 'n' to create your first wallet.")
		return lipgloss.Place(m.width, m.height-2, lipgloss.Center, lipgloss.Center, emptyMessage)
	}

	// Calculate optimal column layout based on terminal width
	walletWidth := 45 // Minimum width per wallet entry
	maxCols := m.width / walletWidth
	if maxCols < 1 {
		maxCols = 1
	}
	if maxCols > 4 { // Cap at 4 columns for readability
		maxCols = 4
	}

	actualWalletWidth := m.width / maxCols
	selectedIndex := m.selectedIndex

	var rows []string

	for i := 0; i < len(m.filteredWallets); i += maxCols {
		var columns []string

		for col := 0; col < maxCols && i+col < len(m.filteredWallets); col++ {
			walletIndex := i + col
			wallet := m.filteredWallets[walletIndex]
			isSelected := walletIndex == selectedIndex

			// Format wallet entry
			addr := hex.EncodeToString(wallet.Address[:])
			addressStr := formatAddress(addr)
			timeAgo := humanizeTime(wallet.CreatedAt)

			label := wallet.Label
			if label == "" {
				label = "Unlabeled Wallet"
			}

			var walletContent string
			if isSelected {
				walletContent = selectedCardStyle.Copy().
					Width(actualWalletWidth - 2).
					Render(fmt.Sprintf("🔐 %s\n📍 %s\n📅 %s", label, addressStr, timeAgo))
			} else {
				walletContent = cardStyle.Copy().
					Width(actualWalletWidth - 2).
					Render(fmt.Sprintf("🔐 %s\n📍 %s\n📅 %s", label, addressStr, timeAgo))
			}

			columns = append(columns, walletContent)
		}

		// Pad remaining columns if needed
		for len(columns) < maxCols {
			columns = append(columns, lipgloss.NewStyle().Width(actualWalletWidth-2).Render(""))
		}

		row := lipgloss.JoinHorizontal(lipgloss.Top, columns...)
		rows = append(rows, row)
	}

	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (m model) View() string {
	if m.quitting {
		farewell := lipgloss.NewStyle().
			Foreground(lipgloss.Color(successColor)).
			Bold(true).
			Padding(1, 2).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color(primaryColor)).
			Render("👋 Stay secure with quantum-resistant encryption!")

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, farewell)
	}

	// Handle project mode
	if m.projectMode {
		if m.projectModel != nil {
			return m.projectModel.View()
		} else {
			return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().
					Foreground(lipgloss.Color(primaryColor)).
					Bold(true).
					Render("📁 Loading Projects..."))
		}
	}

	// Handle loading state
	if m.loading {
		loadingView := lipgloss.JoinVertical(
			lipgloss.Center,
			titleStyle.Render("🔐 Quantum Wallet Manager"),
			"",
			m.spinner.View()+" "+m.loadingMsg,
		)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			modalStyle.Render(loadingView))
	}

	// Handle input modes with enhanced overlay
	if m.inputMode != "" {
		var title, inputView, helpText string
		var icon string

		switch m.inputMode {
		case "new":
			icon = "✨"
			title = "Create New Quantum-Resistant Wallet"
			inputView = m.input.View()
			helpText = "Enter • Create | Esc • Cancel"
		case "search":
			icon = "🔍"
			title = "Search Wallets"
			inputView = m.input.View()
			helpText = "Enter • Search | Esc • Cancel"
		case "password":
			icon = "🔐"
			title = "Authentication Required"
			inputView = m.passwordInput.View()
			helpText = "Enter • Authenticate | Esc • Cancel"
		case "edit":
			icon = "✏️"
			title = "Edit Wallet Label"
			inputView = m.input.View()
			helpText = "Enter • Save | Esc • Cancel"
		}

		content := lipgloss.JoinVertical(
			lipgloss.Center,
			iconStyle.Render(icon),
			titleStyle.Render(title),
			"",
			inputView,
			"",
			mutedStyle.Render(helpText),
		)

		modal := modalStyle.Width(60).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show private key if authenticated
	if m.showingPrivateKey && m.selectedWallet != nil {
		privateKeyHex := "0x" + hex.EncodeToString(m.selectedWallet.PrivateKey[:])
		addressHex := "0x" + hex.EncodeToString(m.selectedWallet.Address[:])

		labelText := "Unlabeled Wallet"
		if m.selectedWallet.Label != "" {
			labelText = m.selectedWallet.Label
		}

		// Auto-copy private key to clipboard with 30-second timeout
		copyToClipboard(privateKeyHex, 30*time.Second)

		content := lipgloss.JoinVertical(
			lipgloss.Left,
			titleStyle.Render("🔓 Private Key Export"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color(textColor)).
				Background(lipgloss.Color(errorColor)).
				Bold(true).
				Padding(0, 1).
				Render("⚠️  EXTREMELY SENSITIVE DATA"),
			"",
			boxStyle.Render(lipgloss.JoinVertical(
				lipgloss.Left,
				labelStyle.Render("Label: ")+baseStyle.Render(labelText),
				addressStyle.Render("Address: ")+baseStyle.Render(addressHex),
				"",
				warningStyle.Render("Private Key:"),
				errorStyle.Copy().Underline(true).Render(privateKeyHex),
			)),
			"",
			successStyle.Render("✅ Copied to clipboard (auto-clears in 30s)"),
			"",
			mutedStyle.Copy().Italic(true).Render("Press 'c' to copy again • Any other key to clear from memory"),
		)

		modal := modalStyle.Width(80).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show delete confirmation if active
	if m.confirmingDelete && m.walletToDelete != nil {
		addressHex := hex.EncodeToString(m.walletToDelete.Address[:])
		label := m.walletToDelete.Label
		if label == "" {
			label = "Unlabeled Wallet"
		}

		content := lipgloss.JoinVertical(
			lipgloss.Center,
			titleStyle.Render("🗑️ Confirm Deletion"),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color(textColor)).
				Background(lipgloss.Color(errorColor)).
				Bold(true).
				Padding(0, 1).
				Render("⚠️  THIS ACTION CANNOT BE UNDONE"),
			"",
			boxStyle.Render(lipgloss.JoinVertical(
				lipgloss.Left,
				labelStyle.Render("Wallet: ")+baseStyle.Render(label),
				addressStyle.Render("Address: ")+baseStyle.Render(formatAddress(addressHex)),
			)),
			"",
			mutedStyle.Render("Press 'y' to confirm • 'n' or Esc to cancel"),
		)

		modal := modalStyle.Width(60).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
	}

	// Compact sheet-style layout focused on wallets
	var sections []string

	// Compact single-line header with status and essential info
	walletCount := fmt.Sprintf("%d", len(m.wallets))
	if m.searchQuery != "" {
		walletCount = fmt.Sprintf("🔍 %d/%d", len(m.filteredWallets), len(m.wallets))
	}

	headerContent := lipgloss.JoinHorizontal(
		lipgloss.Left,
		lipgloss.NewStyle().Foreground(lipgloss.Color(primaryColor)).Bold(true).Render("🔐 Quantum Wallets"),
		lipgloss.NewStyle().Foreground(lipgloss.Color(subtext1Color)).Render(" • "),
		lipgloss.NewStyle().Foreground(lipgloss.Color(textColor)).Render(walletCount),
		lipgloss.NewStyle().Foreground(lipgloss.Color(subtext1Color)).Render(" • "),
		lipgloss.NewStyle().Foreground(lipgloss.Color(mutedColor)).Render("n•new ⏎•edit c•copy e•export d•delete /•search p•projects q•quit"),
	)

	// Add status message to header if present and not just ready message
	if m.status != "" && !strings.Contains(m.status, "Ready") {
		headerContent = lipgloss.JoinHorizontal(
			lipgloss.Left,
			headerContent,
			lipgloss.NewStyle().Render(" • "),
			m.status,
		)
	}

	compactHeader := lipgloss.NewStyle().
		Background(lipgloss.Color(mantleColor)).
		Foreground(lipgloss.Color(textColor)).
		Padding(0, 1).
		Width(m.width).
		Render(headerContent)
	sections = append(sections, compactHeader)

	// Multi-column wallet grid using full terminal width
	listView := m.renderWalletGrid()
	sections = append(sections, listView)

	// Join sections without extra spacing
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// Read password securely
func readPassword(prompt string) ([]byte, error) {
	// Enhanced prompt with color
	fmt.Print(infoStyle.Render(prompt))

	// Check if we're in a proper terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Fallback for non-interactive environments
		var password string
		_, err := fmt.Scanln(&password)
		fmt.Println()
		return []byte(password), err
	}

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password, err
}

func main() {
	// Initialize clipboard
	if err := initClipboard(); err != nil {
		log.Printf("Warning: Clipboard not available: %v", err)
	}

	// Welcome message
	fmt.Println(headerStyle.Render("🔐 Quantum-Resistant Ethereum Wallet Manager"))
	fmt.Println(quantumBadgeStyle.Render("Secured with ML-KEM-1024 (Kyber)"))
	fmt.Println()

	walletFile := "wallets.enc"
	walletMgr := NewWalletManager(walletFile)

	// Get master password
	password, err := readPassword("Enter master password: ")
	if err != nil {
		log.Fatal(errorStyle.Render("Failed to read password: " + err.Error()))
	}
	defer func() {
		// Zero password
		SecureZero(password)
	}()

	// Initialize wallet manager
	fmt.Println(infoStyle.Render("🔄 Initializing quantum-resistant encryption..."))
	if err := walletMgr.Initialize(password); err != nil {
		log.Fatal(errorStyle.Render("Failed to initialize: " + err.Error()))
	}

	// Launch enhanced TUI
	p := tea.NewProgram(
		initialModel(walletMgr),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		log.Fatal(errorStyle.Render("Failed to run: " + err.Error()))
	}
}

// Additional security functions that would be in separate files in production

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

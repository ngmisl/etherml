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
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/term"

	"wallet/pkg/quantum"
	"wallet/pkg/tui"
)

// Type definitions for type safety
type (
	PrivateKey    = quantum.PrivateKey
	PublicKey     = quantum.PublicKey
	Address       = quantum.Address
	Salt          = quantum.Salt
	Nonce         = quantum.Nonce
	EncryptedData = quantum.EncryptedData
	KDFParams     = quantum.KDFParams
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

// StorageFile represents the encrypted storage format with deniable encryption support
type StorageFile struct {
	Version              string            `json:"version"`
	Algorithm            string            `json:"algorithm"`
	KDF                  KDFParams         `json:"kdf"`
	MLKEMPublicKey       string            `json:"mlkem_public_key,omitempty"`
	MLKEMPrivateKeyEnc   string            `json:"mlkem_private_key_enc,omitempty"`
	MLKEMPrivateKeyNonce string            `json:"mlkem_private_key_nonce,omitempty"`
	EncryptedWallets     string            `json:"encrypted_wallets,omitempty"`
	HMAC                 string            `json:"hmac,omitempty"`
	Wallets              []EncryptedWallet `json:"wallets"` // Legacy support
	UpdatedAt            time.Time         `json:"updated_at"`
	
	// Deniable encryption fields
	DeniableMode         bool              `json:"deniable_mode,omitempty"`
	DecoyKDF             KDFParams         `json:"decoy_kdf,omitempty"`
	DecoyMLKEMPublicKey  string            `json:"decoy_mlkem_public_key,omitempty"`
	DecoyMLKEMPrivateKeyEnc string         `json:"decoy_mlkem_private_key_enc,omitempty"`
	DecoyMLKEMPrivateKeyNonce string       `json:"decoy_mlkem_private_key_nonce,omitempty"`
	DecoyWallets         []EncryptedWallet `json:"decoy_wallets,omitempty"`
}

// WalletManager handles wallet operations with deniable encryption support
type WalletManager struct {
	filePath        string
	storage         *StorageFile
	key             []byte
	mlkemPrivateKey []byte
	masterPassword  []byte
	
	// Deniable encryption state
	isDecoyMode     bool
	decoyKey        []byte
	decoyMLKEMPrivateKey []byte
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
	quantum.SecureZero(b)

	return Ok(wallet)
}

// Derive key using Argon2id
func deriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return quantum.DeriveKey(password, salt, params)
}

// Helper functions for ML-KEM private key storage encryption (not the hybrid quantum encryption)
func encryptDataForMLKEMKey(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
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

func decryptDataForMLKEMKey(ciphertext EncryptedData, key []byte, nonce Nonce) ([]byte, error) {
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

// generateDecoyWallets creates realistic fake wallets for plausible deniability
func generateDecoyWallets(decoyPassword []byte, count int) ([]Wallet, error) {
	if count < 2 || count > 8 {
		count = 5 // Default to 5 decoy wallets
	}

	// Use decoy password as seed for deterministic generation
	// This ensures the same decoy wallets are generated each time
	seed := make([]byte, 32)
	copy(seed, decoyPassword)
	if len(decoyPassword) < 32 {
		// Pad with deterministic data if password is short
		for i := len(decoyPassword); i < 32; i++ {
			seed[i] = byte(i ^ 0x5A)
		}
	}

	wallets := make([]Wallet, count)
	
	for i := 0; i < count; i++ {
		// Create deterministic but realistic wallet data
		walletSeed := make([]byte, 32)
		copy(walletSeed, seed)
		walletSeed[31] = byte(i) // Unique per wallet
		
		// Generate deterministic private key
		var privateKey PrivateKey
		copy(privateKey[:], walletSeed)
		
		// Derive realistic public key and address from private key
		// (This creates a valid Ethereum address that looks real)
		ecdsaKey, err := crypto.ToECDSA(privateKey[:])
		if err != nil {
			return nil, fmt.Errorf("failed to create decoy ECDSA key: %w", err)
		}
		
		publicKey := &ecdsaKey.PublicKey
		address := crypto.PubkeyToAddress(*publicKey)
		
		// Generate realistic creation timestamps (spread over past months)
		baseTime := time.Now().AddDate(0, -6, 0) // 6 months ago
		dayOffset := time.Duration(i*30+7) * 24 * time.Hour // Spread wallets
		createdAt := baseTime.Add(dayOffset)
		
		// Generate realistic labels
		labels := []string{
			"Main Wallet",
			"Savings",
			"Trading Account",
			"DeFi Wallet",
			"Cold Storage",
			"Work Wallet",
			"Personal",
			"Backup Wallet",
		}
		
		wallet := Wallet{
			PrivateKey: privateKey,
			CreatedAt:  createdAt,
			Label:      labels[i%len(labels)],
		}
		copy(wallet.Address[:], address.Bytes())
		
		wallets[i] = wallet
	}

	return wallets, nil
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
	}
}

// InitializeWithDeniable supports deniable encryption initialization
func (wm *WalletManager) InitializeWithDeniable(realPassword []byte, decoyPassword []byte, enableDeniable bool) error {
	// Check if file exists to determine if this is new wallet creation or loading
	if _, err := os.Stat(wm.filePath); os.IsNotExist(err) {
		// New wallet creation
		return wm.initializeNewWallet(realPassword, decoyPassword, enableDeniable)
	}
	
	// Existing wallet - attempt to load with either password
	return wm.loadExistingWallet(realPassword)
}

// Initialize or load storage (legacy method for backwards compatibility)
func (wm *WalletManager) Initialize(password []byte) error {
	return wm.InitializeWithDeniable(password, nil, false)
}

// initializeNewWallet creates a new wallet with optional deniable encryption
func (wm *WalletManager) initializeNewWallet(realPassword []byte, decoyPassword []byte, enableDeniable bool) error {
	// Store master password for re-authentication
	wm.masterPassword = make([]byte, len(realPassword))
	copy(wm.masterPassword, realPassword)
	
	// Set up deniable encryption mode if requested
	wm.storage.DeniableMode = enableDeniable

	// Generate salt for real encryption
	var salt Salt
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Set up KDF parameters for real encryption
	wm.storage.KDF = KDFParams{
		Function:    "argon2id",
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		Salt:        base64.StdEncoding.EncodeToString(salt[:]),
		KeyLen:      32,
	}

	// Derive the key using the KDF parameters
	wm.key = deriveKey(realPassword, salt, wm.storage.KDF)

	// Generate ML-KEM-1024 keypair for real encryption
	encapsKeyBytes, decapsKeyBytes, err := quantum.GenerateMLKEMKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ML-KEM keypair: %w", err)
	}

	// Encrypt the ML-KEM private key with AES using derived key
	encryptedPrivKey, privKeyNonce, err := encryptDataForMLKEMKey(decapsKeyBytes, wm.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt ML-KEM private key: %w", err)
	}

	// Store the encapsulation key (public key) and encrypted private key in the file
	wm.storage.MLKEMPublicKey = base64.StdEncoding.EncodeToString(encapsKeyBytes)
	wm.storage.MLKEMPrivateKeyEnc = base64.StdEncoding.EncodeToString(encryptedPrivKey)
	wm.storage.MLKEMPrivateKeyNonce = base64.StdEncoding.EncodeToString(privKeyNonce[:])

	// Store the decrypted private key in memory
	wm.mlkemPrivateKey = decapsKeyBytes

	// Set up deniable encryption if requested
	if enableDeniable && decoyPassword != nil {
		// Generate separate salt for decoy encryption
		var decoySalt Salt
		if _, err := io.ReadFull(rand.Reader, decoySalt[:]); err != nil {
			return fmt.Errorf("failed to generate decoy salt: %w", err)
		}

		// Set up decoy KDF parameters (slightly different for separation)
		wm.storage.DecoyKDF = KDFParams{
			Function:    "argon2id",
			Memory:      131072, // Different memory usage
			Iterations:  4,      // Different iterations
			Parallelism: 4,
			Salt:        base64.StdEncoding.EncodeToString(decoySalt[:]),
			KeyLen:      32,
		}

		// Derive decoy key using different parameters
		wm.decoyKey = quantum.DeriveKeyWithMode(decoyPassword, decoySalt, wm.storage.DecoyKDF, true)

		// Generate ML-KEM-1024 keypair for decoy encryption
		decoyEncapsKeyBytes, decoyDecapsKeyBytes, err := quantum.GenerateMLKEMKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate decoy ML-KEM keypair: %w", err)
		}

		// Encrypt the decoy ML-KEM private key
		decoyEncryptedPrivKey, decoyPrivKeyNonce, err := encryptDataForMLKEMKey(decoyDecapsKeyBytes, wm.decoyKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt decoy ML-KEM private key: %w", err)
		}

		// Store decoy encryption data
		wm.storage.DecoyMLKEMPublicKey = base64.StdEncoding.EncodeToString(decoyEncapsKeyBytes)
		wm.storage.DecoyMLKEMPrivateKeyEnc = base64.StdEncoding.EncodeToString(decoyEncryptedPrivKey)
		wm.storage.DecoyMLKEMPrivateKeyNonce = base64.StdEncoding.EncodeToString(decoyPrivKeyNonce[:])

		// Store decoy private key in memory
		wm.decoyMLKEMPrivateKey = decoyDecapsKeyBytes

		// Generate decoy wallets
		decoyWallets, err := generateDecoyWallets(decoyPassword, 5)
		if err != nil {
			return fmt.Errorf("failed to generate decoy wallets: %w", err)
		}

		// Encrypt decoy wallets using decoy encryption
		wm.storage.DecoyWallets = make([]EncryptedWallet, len(decoyWallets))
		for i, wallet := range decoyWallets {
			encrypted, nonce, err := quantum.EncryptDataPQC(wallet.PrivateKey[:], decoyEncapsKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to encrypt decoy wallet %d: %w", i, err)
			}

			wm.storage.DecoyWallets[i] = EncryptedWallet{
				Address:      hex.EncodeToString(wallet.Address[:]),
				EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
				Nonce:        nonce,
				CreatedAt:    wallet.CreatedAt,
				Label:        wallet.Label,
			}

			// Zero the decoy wallet private key
			quantum.SecureZero(wallet.PrivateKey[:])
		}
	}

	return wm.Save()
}

// loadExistingWallet attempts to load wallet with potential deniable encryption
func (wm *WalletManager) loadExistingWallet(password []byte) error {
	data, err := os.ReadFile(wm.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(data, &wm.storage); err != nil {
		return fmt.Errorf("failed to unmarshal storage: %w", err)
	}

	// Store password for re-authentication
	wm.masterPassword = make([]byte, len(password))
	copy(wm.masterPassword, password)

	// Ensure this is a post-quantum format
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return fmt.Errorf("unsupported storage format: %s. This wallet only supports ML-KEM post-quantum encryption", wm.storage.Algorithm)
	}

	// Try to load as real wallet first
	if err := wm.tryLoadAsReal(password); err == nil {
		wm.isDecoyMode = false
		return nil
	}

	// If deniable mode is enabled, try to load as decoy wallet
	if wm.storage.DeniableMode {
		if err := wm.tryLoadAsDecoy(password); err == nil {
			wm.isDecoyMode = true
			return nil
		}
	}

	return fmt.Errorf("invalid password - unable to decrypt wallet")
}

// tryLoadAsReal attempts to load wallet using real encryption
func (wm *WalletManager) tryLoadAsReal(password []byte) error {
	// Derive key for real encryption
	salt, err := base64.StdEncoding.DecodeString(wm.storage.KDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	var s Salt
	copy(s[:], salt)
	wm.key = deriveKey(password, s, wm.storage.KDF)

	if wm.storage.MLKEMPublicKey == "" {
		return fmt.Errorf("ML-KEM public key missing from storage file")
	}

	// Decrypt the stored ML-KEM private key
	if wm.storage.MLKEMPrivateKeyEnc == "" || wm.storage.MLKEMPrivateKeyNonce == "" {
		return fmt.Errorf("ML-KEM private key not found in storage")
	}

	encryptedPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyEnc)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted ML-KEM private key: %w", err)
	}

	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyNonce)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM private key nonce: %w", err)
	}

	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)

	// Decrypt the ML-KEM private key using regular AES decryption (not hybrid ML-KEM)
	decryptedPrivKey, err := decryptDataForMLKEMKey(EncryptedData(encryptedPrivKey), wm.key, privKeyNonce)
	if err != nil {
		return fmt.Errorf("invalid password - failed to decrypt ML-KEM private key: %w", err)
	}

	wm.mlkemPrivateKey = decryptedPrivKey

	// Verify the decrypted private key by checking public key match
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode stored ML-KEM public key: %w", err)
	}

	// Derive the public key from our private key to verify correctness
	decapsKey, err := mlkem.NewDecapsulationKey1024(wm.mlkemPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create decapsulation key: %w", err)
	}
	derivedEncapsKey := decapsKey.EncapsulationKey()
	derivedEncapsKeyBytes := derivedEncapsKey.Bytes()

	// Verify the derived public key matches the stored one
	if !quantum.SecureCompare(encapsKeyBytes, derivedEncapsKeyBytes) {
		return errors.New("invalid password - ML-KEM key mismatch")
	}

	// Verify password by trying to decrypt first wallet (if any exist)
	if len(wm.storage.Wallets) > 0 {
		_, err := wm.decryptWallet(&wm.storage.Wallets[0])
		if err != nil {
			return fmt.Errorf("password verification failed: %w", err)
		}
	}

	return nil
}

// tryLoadAsDecoy attempts to load wallet using decoy encryption
func (wm *WalletManager) tryLoadAsDecoy(password []byte) error {
	// Derive key for decoy encryption
	salt, err := base64.StdEncoding.DecodeString(wm.storage.DecoyKDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode decoy salt: %w", err)
	}

	var s Salt
	copy(s[:], salt)
	wm.decoyKey = quantum.DeriveKeyWithMode(password, s, wm.storage.DecoyKDF, true)

	if wm.storage.DecoyMLKEMPublicKey == "" {
		return fmt.Errorf("decoy ML-KEM public key missing from storage file")
	}

	// Decrypt the stored decoy ML-KEM private key
	if wm.storage.DecoyMLKEMPrivateKeyEnc == "" || wm.storage.DecoyMLKEMPrivateKeyNonce == "" {
		return fmt.Errorf("decoy ML-KEM private key not found in storage")
	}

	encryptedPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyEnc)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted decoy ML-KEM private key: %w", err)
	}

	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPrivateKeyNonce)
	if err != nil {
		return fmt.Errorf("failed to decode decoy ML-KEM private key nonce: %w", err)
	}

	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)

	// Decrypt the decoy ML-KEM private key
	decryptedPrivKey, err := decryptDataForMLKEMKey(EncryptedData(encryptedPrivKey), wm.decoyKey, privKeyNonce)
	if err != nil {
		return fmt.Errorf("invalid password - failed to decrypt decoy ML-KEM private key: %w", err)
	}

	wm.decoyMLKEMPrivateKey = decryptedPrivKey

	// Verify the decrypted private key by checking public key match
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode stored decoy ML-KEM public key: %w", err)
	}

	// Derive the public key from our private key to verify correctness
	decapsKey, err := mlkem.NewDecapsulationKey1024(wm.decoyMLKEMPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create decoy decapsulation key: %w", err)
	}
	derivedEncapsKey := decapsKey.EncapsulationKey()
	derivedEncapsKeyBytes := derivedEncapsKey.Bytes()

	// Verify the derived public key matches the stored one
	if !quantum.SecureCompare(encapsKeyBytes, derivedEncapsKeyBytes) {
		return errors.New("invalid password - decoy ML-KEM key mismatch")
	}

	// Verify password by trying to decrypt first decoy wallet (if any exist)
	if len(wm.storage.DecoyWallets) > 0 {
		_, err := wm.decryptDecoyWallet(&wm.storage.DecoyWallets[0])
		if err != nil {
			return fmt.Errorf("decoy password verification failed: %w", err)
		}
	}

	return nil
}

// Load storage file (legacy method)
func (wm *WalletManager) Load(password []byte) error {
	data, err := os.ReadFile(wm.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(data, &wm.storage); err != nil {
		return fmt.Errorf("failed to unmarshal storage: %w", err)
	}

	// Derive key
	salt, err := base64.StdEncoding.DecodeString(wm.storage.KDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	var s Salt
	copy(s[:], salt)
	wm.key = deriveKey(password, s, wm.storage.KDF)

	// Ensure this is a post-quantum format
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return fmt.Errorf("unsupported storage format: %s. This wallet only supports ML-KEM post-quantum encryption", wm.storage.Algorithm)
	}

	if wm.storage.MLKEMPublicKey == "" {
		return fmt.Errorf("ML-KEM public key missing from storage file")
	}

	// Decrypt the stored ML-KEM private key
	if wm.storage.MLKEMPrivateKeyEnc == "" || wm.storage.MLKEMPrivateKeyNonce == "" {
		return fmt.Errorf("ML-KEM private key not found in storage")
	}

	encryptedPrivKey, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyEnc)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted ML-KEM private key: %w", err)
	}

	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPrivateKeyNonce)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM private key nonce: %w", err)
	}

	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)

	// Decrypt the ML-KEM private key using regular AES decryption (not hybrid ML-KEM)
	decryptedPrivKey, err := decryptDataForMLKEMKey(EncryptedData(encryptedPrivKey), wm.key, privKeyNonce)
	if err != nil {
		return fmt.Errorf("invalid password - failed to decrypt ML-KEM private key: %w", err)
	}

	wm.mlkemPrivateKey = decryptedPrivKey

	// Verify the decrypted private key by checking public key match
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode stored ML-KEM public key: %w", err)
	}

	// Derive the public key from our private key to verify correctness
	decapsKey, err := mlkem.NewDecapsulationKey1024(wm.mlkemPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create decapsulation key: %w", err)
	}
	derivedEncapsKey := decapsKey.EncapsulationKey()
	derivedEncapsKeyBytes := derivedEncapsKey.Bytes()

	// Verify the derived public key matches the stored one
	if !quantum.SecureCompare(encapsKeyBytes, derivedEncapsKeyBytes) {
		return errors.New("invalid password - ML-KEM key mismatch")
	}

	// Successfully decrypted and verified ML-KEM private key

	// Verify password by trying to decrypt first wallet (if any exist)
	if len(wm.storage.Wallets) > 0 {
		_, err := wm.decryptWallet(&wm.storage.Wallets[0])
		if err != nil {
			return fmt.Errorf("password verification failed: %w", err)
		}
	}

	// If no wallets exist yet, the password is considered valid
	// (we already verified ML-KEM key decryption above)

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

// Add wallet to storage using ML-KEM post-quantum encryption (supports both real and decoy modes)
func (wm *WalletManager) AddWallet(wallet *Wallet) error {
	// Ensure we have ML-KEM setup
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return fmt.Errorf("ML-KEM encryption not initialized")
	}

	if wm.isDecoyMode {
		// Add to decoy storage
		if wm.storage.DecoyMLKEMPublicKey == "" {
			return fmt.Errorf("decoy ML-KEM encryption not initialized")
		}

		// Decode the decoy ML-KEM public key
		encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.DecoyMLKEMPublicKey)
		if err != nil {
			return fmt.Errorf("failed to decode decoy ML-KEM public key: %w", err)
		}

		// Use post-quantum encryption with decoy key
		encrypted, nonce, err := quantum.EncryptDataPQC(wallet.PrivateKey[:], encapsKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt key with decoy ML-KEM: %w", err)
		}

		ew := EncryptedWallet{
			Address:      hex.EncodeToString(wallet.Address[:]),
			EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
			Nonce:        nonce,
			CreatedAt:    wallet.CreatedAt,
			Label:        wallet.Label,
		}

		wm.storage.DecoyWallets = append(wm.storage.DecoyWallets, ew)
		return wm.Save()
	}

	// Add to real storage
	if wm.storage.MLKEMPublicKey == "" {
		return fmt.Errorf("ML-KEM encryption not initialized")
	}

	// Decode the ML-KEM public key
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(wm.storage.MLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM public key: %w", err)
	}

	// Use post-quantum encryption
	encrypted, nonce, err := quantum.EncryptDataPQC(wallet.PrivateKey[:], encapsKeyBytes)
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

// List all wallets (supports both real and decoy modes)
func (wm *WalletManager) ListWallets() ([]Wallet, error) {
	if wm.isDecoyMode {
		// Return decoy wallets
		wallets := make([]Wallet, 0, len(wm.storage.DecoyWallets))
		for _, ew := range wm.storage.DecoyWallets {
			wallet, err := wm.decryptDecoyWallet(&ew)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt decoy wallet %s: %w", ew.Address, err)
			}
			wallets = append(wallets, *wallet)
		}
		return wallets, nil
	}

	// Return real wallets
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

// UpdateWalletLabel updates the label of a wallet by address (supports both real and decoy modes)
func (wm *WalletManager) UpdateWalletLabel(address string, newLabel string) error {
	// Remove 0x prefix if present
	address = strings.TrimPrefix(address, "0x")
	
	if wm.isDecoyMode {
		// Update decoy wallet label
		for i, ew := range wm.storage.DecoyWallets {
			if strings.EqualFold(ew.Address, address) {
				wm.storage.DecoyWallets[i].Label = newLabel
				return wm.Save()
			}
		}
		return fmt.Errorf("decoy wallet with address %s not found", address)
	}

	// Update real wallet label
	for i, ew := range wm.storage.Wallets {
		if strings.EqualFold(ew.Address, address) {
			wm.storage.Wallets[i].Label = newLabel
			return wm.Save()
		}
	}
	return fmt.Errorf("wallet with address %s not found", address)
}

// Delete wallet from storage (supports both real and decoy modes)
func (wm *WalletManager) DeleteWallet(address string) error {
	if wm.isDecoyMode {
		// Find and remove from decoy wallets
		for i, ew := range wm.storage.DecoyWallets {
			if strings.EqualFold(ew.Address, address) {
				// Remove wallet from slice
				wm.storage.DecoyWallets = append(wm.storage.DecoyWallets[:i], wm.storage.DecoyWallets[i+1:]...)
				return wm.Save()
			}
		}
		return fmt.Errorf("decoy wallet with address %s not found", address)
	}

	// Find and remove from real wallets
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
	decrypted, err := quantum.DecryptDataPQC(EncryptedData(encrypted), wm.mlkemPrivateKey, ew.Nonce)
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
	quantum.SecureZero(decrypted)

	return wallet, nil
}

// decryptDecoyWallet decrypts a wallet from decoy storage
func (wm *WalletManager) decryptDecoyWallet(ew *EncryptedWallet) (*Wallet, error) {
	// Ensure we have decoy ML-KEM setup
	if wm.storage.Algorithm != "mlkem1024-aes256gcm" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", wm.storage.Algorithm)
	}

	if wm.decoyMLKEMPrivateKey == nil {
		return nil, fmt.Errorf("decoy ML-KEM private key not available")
	}

	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Use post-quantum decryption with decoy key
	decrypted, err := quantum.DecryptDataPQC(EncryptedData(encrypted), wm.decoyMLKEMPrivateKey, ew.Nonce)
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
	quantum.SecureZero(decrypted)

	return wallet, nil
}

// TUI Wallet interface implementation
func (wm *WalletManager) ListTUIWallets() ([]tui.Wallet, error) {
	mainWallets, err := wm.ListWallets()
	if err != nil {
		return nil, err
	}

	tuiWallets := make([]tui.Wallet, len(mainWallets))
	for i, mw := range mainWallets {
		tuiWallets[i] = tui.Wallet{
			PrivateKey: mw.PrivateKey,
			Address:    mw.Address,
			CreatedAt:  mw.CreatedAt,
			Label:      mw.Label,
		}
	}

	return tuiWallets, nil
}

func (wm *WalletManager) AddTUIWallet(wallet *tui.Wallet) error {
	mainWallet := &Wallet{
		PrivateKey: wallet.PrivateKey,
		Address:    wallet.Address,
		CreatedAt:  wallet.CreatedAt,
		Label:      wallet.Label,
	}

	return wm.AddWallet(mainWallet)
}

// TUIWalletManager adapter implements the TUI interface
type TUIWalletManager struct {
	manager *WalletManager
}

func (t *TUIWalletManager) ListWallets() ([]tui.Wallet, error) {
	return t.manager.ListTUIWallets()
}

func (t *TUIWalletManager) AddWallet(wallet *tui.Wallet) error {
	return t.manager.AddTUIWallet(wallet)
}

func (t *TUIWalletManager) DeleteWallet(address string) error {
	return t.manager.DeleteWallet(address)
}

func (t *TUIWalletManager) UpdateWalletLabel(address string, newLabel string) error {
	return t.manager.UpdateWalletLabel(address, newLabel)
}

func (t *TUIWalletManager) Save() error {
	return t.manager.Save()
}

// Read password securely
func readPassword(prompt string) ([]byte, error) {
	// Enhanced prompt with color
	fmt.Print(prompt)

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

// Validate password strength
func validatePassword(password []byte) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be less than 128 characters")
	}
	
	// Check for at least one number or special character for basic strength
	hasComplexity := false
	for _, b := range password {
		if (b >= '0' && b <= '9') || (b >= '!' && b <= '/') || (b >= ':' && b <= '@') || (b >= '[' && b <= '`') || (b >= '{' && b <= '~') {
			hasComplexity = true
			break
		}
	}
	
	if !hasComplexity {
		return fmt.Errorf("password should include at least one number or special character")
	}
	
	return nil
}

// Read password with confirmation for new wallets, and handle deniable encryption setup
func readPasswordWithConfirmation(filePath string) (realPassword []byte, decoyPassword []byte, enableDeniable bool, err error) {
	// Check if wallet file exists
	isNewWallet := true
	if _, err := os.Stat(filePath); err == nil {
		isNewWallet = false
	}

	if !isNewWallet {
		// Existing wallet - single password prompt
		password, err := readPassword("Enter master password: ")
		return password, nil, false, err
	}

	// New wallet - password confirmation and deniable encryption setup
	fmt.Println("🔐 Creating New Quantum-Resistant Wallet")
	fmt.Println()

	var realPass []byte
	for {
		realPass, err = readPassword("Enter master password: ")
		if err != nil {
			return nil, nil, false, err
		}

		if err := validatePassword(realPass); err != nil {
			fmt.Println("❌ " + err.Error())
			quantum.SecureZero(realPass)
			continue
		}

		confirmPass, err := readPassword("Confirm master password: ")
		if err != nil {
			quantum.SecureZero(realPass)
			return nil, nil, false, err
		}

		if !quantum.SecureCompare(realPass, confirmPass) {
			fmt.Println("❌ Passwords do not match")
			quantum.SecureZero(realPass)
			quantum.SecureZero(confirmPass)
			continue
		}

		quantum.SecureZero(confirmPass)
		break
	}

	// Ask about deniable encryption
	fmt.Println()
	fmt.Println("🛡️  Deniable Encryption ($5 Wrench Protection)")
	fmt.Println("This creates a decoy wallet that opens with a different password,")
	fmt.Println("providing plausible deniability if forced to unlock your wallet.")
	fmt.Print("Enable deniable encryption? (y/N): ")

	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response == "y" || response == "yes" {
		fmt.Println()
		fmt.Println("🔑 Decoy Password Setup")
		fmt.Println("This password will open fake wallets for plausible deniability.")
		fmt.Println("Choose a password you would believably give under duress.")

		var decoyPass []byte
		for {
			decoyPass, err = readPassword("Enter decoy password: ")
			if err != nil {
				quantum.SecureZero(realPass)
				return nil, nil, false, err
			}

			if err := validatePassword(decoyPass); err != nil {
				fmt.Println("❌ " + err.Error())
				quantum.SecureZero(decoyPass)
				continue
			}

			if quantum.SecureCompare(realPass, decoyPass) {
				fmt.Println("❌ Decoy password cannot be the same as master password")
				quantum.SecureZero(decoyPass)
				continue
			}

			confirmDecoy, err := readPassword("Confirm decoy password: ")
			if err != nil {
				quantum.SecureZero(realPass)
				quantum.SecureZero(decoyPass)
				return nil, nil, false, err
			}

			if !quantum.SecureCompare(decoyPass, confirmDecoy) {
				fmt.Println("❌ Decoy passwords do not match")
				quantum.SecureZero(decoyPass)
				quantum.SecureZero(confirmDecoy)
				continue
			}

			quantum.SecureZero(confirmDecoy)
			break
		}

		return realPass, decoyPass, true, nil
	}

	return realPass, nil, false, nil
}

func main() {
	// Welcome message
	fmt.Println("🔐 Quantum-Resistant Ethereum Wallet Manager")
	fmt.Println("Secured with ML-KEM-1024 (Kyber)")
	fmt.Println()

	walletFile := "wallets.enc"
	walletMgr := NewWalletManager(walletFile)

	// Get master password with confirmation and deniable encryption setup
	realPassword, decoyPassword, enableDeniable, err := readPasswordWithConfirmation(walletFile)
	if err != nil {
		log.Fatal("Failed to read password: " + err.Error())
	}
	defer func() {
		// Zero passwords
		quantum.SecureZero(realPassword)
		if decoyPassword != nil {
			quantum.SecureZero(decoyPassword)
		}
	}()

	// Initialize wallet manager with deniable encryption support
	fmt.Println("🔄 Initializing quantum-resistant encryption...")
	if err := walletMgr.InitializeWithDeniable(realPassword, decoyPassword, enableDeniable); err != nil {
		log.Fatal("Failed to initialize: " + err.Error())
	}

	// Set up GenerateWallet function for TUI
	tui.SetGenerateWalletFunc(func() tui.Result[*tui.Wallet] {
		result := GenerateWallet()
		if wallet, err := result.Unwrap(); err != nil {
			return tui.Err[*tui.Wallet](err)
		} else {
			tuiWallet := &tui.Wallet{
				PrivateKey: wallet.PrivateKey,
				Address:    wallet.Address,
				CreatedAt:  wallet.CreatedAt,
				Label:      wallet.Label,
			}
			return tui.Ok(tuiWallet)
		}
	})

	// Create TUI adapter
	tuiManager := &TUIWalletManager{manager: walletMgr}

	// Launch TUI
	if err := tui.Run(tuiManager, realPassword); err != nil {
		log.Fatal("Failed to run TUI: " + err.Error())
	}
}
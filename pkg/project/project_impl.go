package project

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// Type definitions reused from main
type (
	PrivateKey    [32]byte
	PublicKey     []byte
	Address       [20]byte
	Salt          [32]byte
	Nonce         [12]byte
	EncryptedData []byte
)

// EncryptedNonce combines encrypted data and a nonce
type EncryptedNonce struct {
	EncryptedData EncryptedData
	Nonce         Nonce
}

// ProjectImpl implements the Project interface
type ProjectImpl struct {
	info        ProjectInfo
	wallets     []ProjectWallet
	projectPath string
	storage     *ProjectStorage

	// Encryption keys
	key             []byte
	mlkemPrivateKey []byte
	password        []byte
	isLocked        bool
}

// GetInfo returns project information
func (p *ProjectImpl) GetInfo() ProjectInfo {
	return p.info
}

// GetWallets returns all wallets in the project
func (p *ProjectImpl) GetWallets() ([]ProjectWallet, error) {
	if p.isLocked {
		return nil, fmt.Errorf("project is locked")
	}
	return p.wallets, nil
}

// DefaultKDFParams returns recommended Argon2id parameters
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Function:    "argon2id",
		Memory:      64 * 1024, // 64 MB
		Iterations:  1,
		Parallelism: 4,
		KeyLen:      32, // For AES-256
	}
}

// CreateEncrypted initializes and encrypts a new project
func (p *ProjectImpl) CreateEncrypted() error {
	// Generate new ML-KEM keys
	decapsKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return fmt.Errorf("failed to generate ML-KEM key: %w", err)
	}

	p.mlkemPrivateKey = decapsKey.Bytes()
	encapsKey := decapsKey.EncapsulationKey()

	// Derive key from password
	var salt Salt
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	kdfParams := DefaultKDFParams()
	p.key = p.deriveKey(p.password, salt, kdfParams)

	// Encrypt ML-KEM private key
	encryptedData, nonce, err := p.encryptData(p.mlkemPrivateKey, p.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt ML-KEM key: %w", err)
	}

	// Create storage structure
	p.storage = &ProjectStorage{
		Version:            "1.0",
		Algorithm:          "pqc-aes-gcm",
		ProjectInfo:        p.info,
		KDF:                kdfParams,
		MLKEMPublicKey:     base64.StdEncoding.EncodeToString(encapsKey.Bytes()),
		MLKEMPrivateKeyEnc: base64.StdEncoding.EncodeToString(encryptedData),
		MLKEMPrivateKeyNonce: base64.StdEncoding.EncodeToString(nonce[:]),
		UpdatedAt:          time.Now(),
	}

	// Store password and unlock
	p.isLocked = false

	return p.Save()
}

// Initialize sets up a new project
func (p *ProjectImpl) Initialize() error {
	p.isLocked = false

	// Create storage with a lightweight setup
	p.storage = &ProjectStorage{
		Version:     "1.0",
		Algorithm:   "per-wallet-encryption",
		ProjectInfo: p.info,
		UpdatedAt:   time.Now(),
	}

	return p.Save()
}

// Load opens an existing project
func (p *ProjectImpl) Load() error {
	projectFile := filepath.Join(p.projectPath, "project.enc")

	data, err := os.ReadFile(projectFile)
	if err != nil {
		return fmt.Errorf("failed to read project file: %w", err)
	}

	var storage ProjectStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return fmt.Errorf("failed to unmarshal project: %w", err)
	}

	p.storage = &storage
	p.info = storage.ProjectInfo

	// Check if this is a new lightweight project (no crypto during project creation)
	if storage.Algorithm == "per-wallet-encryption" {
		// New format: just store password, no project-level crypto
		p.isLocked = false
		return p.loadWallets()
	}

	// Legacy format: handle old projects with project-level encryption
	if storage.KDF.Salt == "" {
		return fmt.Errorf("invalid project format")
	}

	// Derive key from password
	salt, err := base64.StdEncoding.DecodeString(storage.KDF.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	var s Salt
	copy(s[:], salt)
	p.key = p.deriveKey(p.password, s, storage.KDF)

	// Decrypt ML-KEM private key
	encryptedPrivKey, err := base64.StdEncoding.DecodeString(storage.MLKEMPrivateKeyEnc)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM private key: %w", err)
	}

	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(storage.MLKEMPrivateKeyNonce)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM nonce: %w", err)
	}

	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)

	mlkemPrivKey, err := p.decryptData(EncryptedData(encryptedPrivKey), p.key, privKeyNonce)
	if err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	p.mlkemPrivateKey = mlkemPrivKey

	// Store password and unlock
	p.isLocked = false

	// Load wallets
	return p.loadWallets()
}

// loadWallets loads all wallets from storage
func (p *ProjectImpl) loadWallets() error {
	// Check if this is new format (per-wallet encryption)
	if p.storage.Algorithm == "per-wallet-encryption" {
		// New format: wallets are stored as simple JSON (each wallet encrypts its own private key)
		if p.storage.WalletsJSON == "" {
			p.wallets = []ProjectWallet{}
			return nil
		}

		// Directly unmarshal wallets (no project-level decryption needed)
		if err := json.Unmarshal([]byte(p.storage.WalletsJSON), &p.wallets); err != nil {
			return fmt.Errorf("failed to unmarshal wallets: %w", err)
		}
		return nil
	}

	// Legacy format: handle old encrypted wallet storage
	if p.storage.EncryptedWallets == "" {
		p.wallets = []ProjectWallet{}
		return nil
	}

	// Decrypt wallet data using project-level encryption
	encryptedData, err := base64.StdEncoding.DecodeString(p.storage.EncryptedWallets)
	if err != nil {
		return fmt.Errorf("failed to decode wallet data: %w", err)
	}

	walletData, err := p.decryptDataPQC(EncryptedData(encryptedData), p.mlkemPrivateKey, p.storage.HMAC)
	if err != nil {
		return fmt.Errorf("failed to decrypt wallet data: %w", err)
	}

	// Unmarshal encrypted wallets
	var encryptedWallets []EncryptedProjectWallet
	if err := json.Unmarshal(walletData, &encryptedWallets); err != nil {
		return fmt.Errorf("failed to unmarshal wallets: %w", err)
	}

	// Decrypt each wallet
	p.wallets = make([]ProjectWallet, 0, len(encryptedWallets))
	for _, ew := range encryptedWallets {
		wallet, err := p.decryptWallet(&ew)
		if err != nil {
			return fmt.Errorf("failed to decrypt wallet %s: %w", ew.Address, err)
		}
		p.wallets = append(p.wallets, *wallet)
	}

	return nil
}

// Save persists the project to disk
func (p *ProjectImpl) Save() error {
	if p.isLocked {
		return fmt.Errorf("project is locked")
	}

	// Update project info
	p.info.UpdatedAt = time.Now()
	p.info.WalletCount = len(p.wallets)

	// Count mainnet/testnet wallets
	mainnetCount := 0
	testnetCount := 0
	for _, wallet := range p.wallets {
		if wallet.Network == Mainnet {
			mainnetCount++
		} else {
			testnetCount++
		}
	}
	p.info.MainnetCount = mainnetCount
	p.info.TestnetCount = testnetCount

	p.storage.ProjectInfo = p.info
	p.storage.UpdatedAt = time.Now()

	// Store wallets if any exist
	if len(p.wallets) > 0 {
		if err := p.saveWallets(); err != nil {
			return fmt.Errorf("failed to save wallets: %w", err)
		}
	} else {
		// Clear wallet storage when no wallets exist
		p.storage.WalletsJSON = ""
		p.storage.EncryptedWallets = ""
		p.storage.HMAC = ""
	}

	// Write to file
	projectFile := filepath.Join(p.projectPath, "project.enc")
	data, err := json.MarshalIndent(p.storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal project: %w", err)
	}

	// Write atomically
	tmpFile := projectFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write project file: %w", err)
	}

	if err := os.Rename(tmpFile, projectFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to rename project file: %w", err)
	}

	return nil
}

// saveWallets stores all wallets using the appropriate format
func (p *ProjectImpl) saveWallets() error {
	// Check if this is new format (per-wallet encryption)
	if p.storage.Algorithm == "per-wallet-encryption" {
		// New format: store wallets as simple JSON (private keys handled individually)
		walletData, err := json.Marshal(p.wallets)
		if err != nil {
			return fmt.Errorf("failed to marshal wallets: %w", err)
		}
		p.storage.WalletsJSON = string(walletData)
		return nil
	}

	// Legacy format: use project-level encryption
	// Create encrypted wallet list
	var encryptedWallets []EncryptedProjectWallet

	for _, wallet := range p.wallets {
		ew, err := p.encryptWallet(&wallet)
		if err != nil {
			return fmt.Errorf("failed to encrypt wallet %s: %w", hex.EncodeToString(wallet.Address[:]), err)
		}
		encryptedWallets = append(encryptedWallets, *ew)
	}

	// Marshal wallet data
	walletData, err := json.Marshal(encryptedWallets)
	if err != nil {
		return fmt.Errorf("failed to marshal wallets: %w", err)
	}

	// Encrypt wallet data
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(p.storage.MLKEMPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode ML-KEM public key: %w", err)
	}

	encryptedData, nonce, err := p.encryptDataPQC(walletData, encapsKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt wallet data: %w", err)
	}

	p.storage.EncryptedWallets = base64.StdEncoding.EncodeToString(encryptedData)
	p.storage.HMAC = nonce

	return nil
}

// Lock secures the project and clears sensitive data from memory
func (p *ProjectImpl) Lock() {
	p.isLocked = true

	// Clear sensitive data
	if p.key != nil {
		p.secureZero(p.key)
		p.key = nil
	}
	if p.mlkemPrivateKey != nil {
		p.secureZero(p.mlkemPrivateKey)
		p.mlkemPrivateKey = nil
	}
	if p.password != nil {
		p.secureZero(p.password)
		p.password = nil
	}

	// Clear wallet private keys
	for i := range p.wallets {
		p.secureZero(p.wallets[i].PrivateKey[:])
	}
	p.wallets = nil
}

// IsLocked returns whether the project is locked
func (p *ProjectImpl) IsLocked() bool {
	return p.isLocked
}

// Cryptographic helper functions (reused from main.go)

func (p *ProjectImpl) deriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}

func (p *ProjectImpl) encryptData(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
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

func (p *ProjectImpl) decryptData(ciphertext EncryptedData, key []byte, nonce Nonce) ([]byte, error) {
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

func (p *ProjectImpl) encryptDataPQC(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, error) {
	encapsKey, err := mlkem.NewEncapsulationKey1024(encapsKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create encapsulation key: %w", err)
	}

	sharedSecret, ciphertext := encapsKey.Encapsulate()

	aesKey := make([]byte, 32)
	copy(aesKey, sharedSecret[:32])
	p.secureZero(sharedSecret[:])

	encrypted, nonce, err := p.encryptData(plaintext, aesKey)
	if err != nil {
		p.secureZero(aesKey)
		return nil, "", err
	}

	combined := append(ciphertext, encrypted...)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])

	p.secureZero(aesKey)

	return EncryptedData(combined), nonceB64, nil
}

func (p *ProjectImpl) decryptDataPQC(combined EncryptedData, decapsKeyBytes []byte, nonceB64 string) ([]byte, error) {
	decapsKey, err := mlkem.NewDecapsulationKey1024(decapsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create decapsulation key: %w", err)
	}

	const mlkemCiphertextSize = 1568
	if len(combined) < mlkemCiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	mlkemCiphertext := combined[:mlkemCiphertextSize]
	aesCiphertext := combined[mlkemCiphertextSize:]

	sharedSecret, err := decapsKey.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	aesKey := make([]byte, 32)
	copy(aesKey, sharedSecret[:32])
	p.secureZero(sharedSecret[:])

	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		p.secureZero(aesKey)
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	var nonce Nonce
	copy(nonce[:], nonceBytes)

	plaintext, err := p.decryptData(EncryptedData(aesCiphertext), aesKey, nonce)
	p.secureZero(aesKey)

	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

func (p *ProjectImpl) secureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CreateWallet generates a new wallet in the project
func (p *ProjectImpl) CreateWallet(label string, network NetworkType) (*ProjectWallet, error) {
	if p.isLocked {
		return nil, fmt.Errorf("project is locked")
	}

	// If the project is not yet encrypted, do it now
	if p.storage.Algorithm != "pqc-aes-gcm" {
		if err := p.CreateEncrypted(); err != nil {
			return nil, fmt.Errorf("failed to encrypt project: %w", err)
		}
	}

	// Generate new Ethereum wallet
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast public key")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Create project wallet
	wallet := &ProjectWallet{
		Label:     label,
		Network:   network,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Copy keys
	copy(wallet.PrivateKey[:], crypto.FromECDSA(privateKey))
	copy(wallet.Address[:], address.Bytes())

	// Zero the original key
	keyBytes := crypto.FromECDSA(privateKey)
	p.secureZero(keyBytes)

	// Add to project
	p.wallets = append(p.wallets, *wallet)

	return wallet, nil
}

// BulkCreateWallets creates multiple wallets according to the configuration
func (p *ProjectImpl) BulkCreateWallets(config BulkConfig) ([]*ProjectWallet, error) {
	if p.isLocked {
		return nil, fmt.Errorf("project is locked")
	}

	if config.Count <= 0 || config.Count > 100 {
		return nil, fmt.Errorf("invalid wallet count: must be between 1 and 100")
	}

	var createdWallets []*ProjectWallet

	for i := 0; i < config.Count; i++ {
		// Determine label
		var label string
		if config.AutoLabel {
			label = p.generateAutoLabel(config.LabelTemplate, i+1)
		} else {
			label = fmt.Sprintf("Wallet %d", i+1)
		}

		// Determine network
		network := Testnet // Default
		if networkType, exists := config.NetworkConfig[i]; exists {
			network = networkType
		}

		// Create wallet
		wallet, err := p.CreateWallet(label, network)
		if err != nil {
			return nil, fmt.Errorf("failed to create wallet %d: %w", i+1, err)
		}

		createdWallets = append(createdWallets, wallet)
	}

	return createdWallets, nil
}

// generateAutoLabel creates labels based on template
func (p *ProjectImpl) generateAutoLabel(template string, index int) string {
	label := template
	if label == "" {
		label = "{project}-wallet-{index}"
	}

	// Replace placeholders
	label = strings.ReplaceAll(label, "{project}", p.info.Name)
	label = strings.ReplaceAll(label, "{index}", fmt.Sprintf("%d", index))

	return label
}

// EditWallet modifies an existing wallet's properties
func (p *ProjectImpl) EditWallet(address string, newLabel string, newNetwork NetworkType) error {
	if p.isLocked {
		return fmt.Errorf("project is locked")
	}

	// Find wallet
	for i, wallet := range p.wallets {
		walletAddr := hex.EncodeToString(wallet.Address[:])
		if strings.EqualFold(walletAddr, strings.TrimPrefix(address, "0x")) {
			// Update wallet
			p.wallets[i].Label = newLabel
			p.wallets[i].Network = newNetwork
			p.wallets[i].UpdatedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("wallet with address %s not found", address)
}

// DeleteWallet removes a wallet from the project
func (p *ProjectImpl) DeleteWallet(address string) error {
	if p.isLocked {
		return fmt.Errorf("project is locked")
	}

	// Find and remove wallet
	for i, wallet := range p.wallets {
		walletAddr := hex.EncodeToString(wallet.Address[:])
		if strings.EqualFold(walletAddr, strings.TrimPrefix(address, "0x")) {
			// Zero the private key before removal
			p.secureZero(p.wallets[i].PrivateKey[:])

			// Remove from slice
			p.wallets = append(p.wallets[:i], p.wallets[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("wallet with address %s not found", address)
}

// ExportWallet returns the private key for a wallet
func (p *ProjectImpl) ExportWallet(address string) (string, error) {
	if p.isLocked {
		return "", fmt.Errorf("project is locked")
	}

	// Find wallet
	for _, wallet := range p.wallets {
		walletAddr := hex.EncodeToString(wallet.Address[:])
		if strings.EqualFold(walletAddr, strings.TrimPrefix(address, "0x")) {
			return "0x" + hex.EncodeToString(wallet.PrivateKey[:]), nil
		}
	}

	return "", fmt.Errorf("wallet with address %s not found", address)
}

// encryptWallet encrypts a project wallet for storage
func (p *ProjectImpl) encryptWallet(wallet *ProjectWallet) (*EncryptedProjectWallet, error) {
	// Get ML-KEM public key
	encapsKeyBytes, err := base64.StdEncoding.DecodeString(p.storage.MLKEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ML-KEM public key: %w", err)
	}

	// Encrypt private key
	encrypted, nonce, err := p.encryptDataPQC(wallet.PrivateKey[:], encapsKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return &EncryptedProjectWallet{
		Address:      hex.EncodeToString(wallet.Address[:]),
		EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
		Nonce:        nonce,
		Label:        wallet.Label,
		Network:      wallet.Network,
		CreatedAt:    wallet.CreatedAt,
		UpdatedAt:    wallet.UpdatedAt,
	}, nil
}

// decryptWallet decrypts a stored wallet
func (p *ProjectImpl) decryptWallet(ew *EncryptedProjectWallet) (*ProjectWallet, error) {
	// Decrypt private key
	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	decrypted, err := p.decryptDataPQC(EncryptedData(encrypted), p.mlkemPrivateKey, ew.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Decode address
	addressBytes, err := hex.DecodeString(ew.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	wallet := &ProjectWallet{
		Label:     ew.Label,
		Network:   ew.Network,
		CreatedAt: ew.CreatedAt,
		UpdatedAt: ew.UpdatedAt,
	}

	copy(wallet.PrivateKey[:], decrypted)
	copy(wallet.Address[:], addressBytes)

	// Zero decrypted data
	p.secureZero(decrypted)

	return wallet, nil
}

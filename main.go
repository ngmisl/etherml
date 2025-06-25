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

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.design/x/clipboard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
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

// StorageFile represents the encrypted storage format
type StorageFile struct {
	Version             string            `json:"version"`
	Algorithm           string            `json:"algorithm"`
	KDF                 KDFParams         `json:"kdf"`
	MLKEMPublicKey      string            `json:"mlkem_public_key,omitempty"`
	MLKEMPrivateKeyEnc  string            `json:"mlkem_private_key_enc,omitempty"`
	MLKEMPrivateKeyNonce string           `json:"mlkem_private_key_nonce,omitempty"`
	EncryptedWallets    string            `json:"encrypted_wallets,omitempty"`
	HMAC                string            `json:"hmac,omitempty"`
	Wallets             []EncryptedWallet `json:"wallets"` // Legacy support
	UpdatedAt           time.Time         `json:"updated_at"`
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

// WalletManager handles wallet operations
type WalletManager struct {
	filePath       string
	storage        *StorageFile
	key            []byte
	mlkemPrivateKey []byte
	masterPassword []byte
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
	for i := range b {
		b[i] = 0
	}

	return Ok(wallet)
}

// Derive key using Argon2id
func deriveKey(password []byte, salt Salt, params KDFParams) []byte {
	return argon2.IDKey(password, salt[:], params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
}

// Generate ML-KEM-1024 keypair (non-deterministic for now, will improve later)
func generateMLKEMKeyPair() ([]byte, []byte, error) {
	decapsKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
	}
	encapsKey := decapsKey.EncapsulationKey()
	
	// ML-KEM keys in Go are already byte arrays
	encapsKeyBytes := encapsKey.Bytes()
	decapsKeyBytes := decapsKey.Bytes()
	
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
	aesKey := sharedSecret[:32]
	encrypted, nonce, err := encryptData(plaintext, aesKey)
	if err != nil {
		return nil, "", err
	}

	// Combine ML-KEM ciphertext with AES ciphertext
	combined := append(ciphertext, encrypted...)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])

	// Zero the shared secret
	SecureZero(sharedSecret[:])

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
		return nil, fmt.Errorf("invalid ciphertext: too short (got %d bytes, need %d)", len(combined), mlkemCiphertextSize)
	}

	mlkemCiphertext := combined[:mlkemCiphertextSize]
	aesCiphertext := combined[mlkemCiphertextSize:]

	// Decapsulate to get shared secret
	sharedSecret, err := decapsKey.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}
	defer SecureZero(sharedSecret[:])

	// Decrypt with AES using first 32 bytes as key
	aesKey := sharedSecret[:32]
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}

	var nonce Nonce
	copy(nonce[:], nonceBytes)

	plaintext, err := decryptData(EncryptedData(aesCiphertext), aesKey, nonce)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Encrypt data using AES-256-GCM
func encryptData(plaintext []byte, key []byte) (EncryptedData, Nonce, error) {
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

// Initialize or load storage
func (wm *WalletManager) Initialize(password []byte) error {
	// Store master password for re-authentication
	wm.masterPassword = make([]byte, len(password))
	copy(wm.masterPassword, password)

	// Check if file exists
	if _, err := os.Stat(wm.filePath); os.IsNotExist(err) {
		// Create new storage with post-quantum encryption
		var salt Salt
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}

		// Set up KDF parameters first
		wm.storage.KDF = KDFParams{
			Function:    "argon2id",
			Memory:      65536,
			Iterations:  3,
			Parallelism: 4,
			Salt:        base64.StdEncoding.EncodeToString(salt[:]),
			KeyLen:      32,
		}

		// Derive the key using the KDF parameters
		wm.key = deriveKey(password, salt, wm.storage.KDF)
		
		// Generate ML-KEM-1024 keypair
		encapsKeyBytes, decapsKeyBytes, err := generateMLKEMKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate ML-KEM keypair: %w", err)
		}
		
		// Encrypt the ML-KEM private key with AES using derived key
		encryptedPrivKey, privKeyNonce, err := encryptData(decapsKeyBytes, wm.key)
		if err != nil {
			return fmt.Errorf("failed to encrypt ML-KEM private key: %w", err)
		}

		// Store the encapsulation key (public key) and encrypted private key in the file
		wm.storage.MLKEMPublicKey = base64.StdEncoding.EncodeToString(encapsKeyBytes)
		wm.storage.MLKEMPrivateKeyEnc = base64.StdEncoding.EncodeToString(encryptedPrivKey)
		wm.storage.MLKEMPrivateKeyNonce = base64.StdEncoding.EncodeToString(privKeyNonce[:])
		
		// Store the decrypted private key in memory
		wm.mlkemPrivateKey = decapsKeyBytes
		return wm.Save()
	}

	// Load existing storage
	return wm.Load(password)
}

// Load storage file
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
	decryptedPrivKey, err := decryptData(EncryptedData(encryptedPrivKey), wm.key, privKeyNonce)
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
	if !SecureCompare(encapsKeyBytes, derivedEncapsKeyBytes) {
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

// List all wallets
func (wm *WalletManager) ListWallets() ([]Wallet, error) {
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

// Delete wallet from storage
func (wm *WalletManager) DeleteWallet(address string) error {
	// Find and remove the wallet with matching address
	for i, ew := range wm.storage.Wallets {
		if ew.Address == address {
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

	return wallet, nil
}

// TUI Components

type model struct {
	list           list.Model
	walletMgr      *WalletManager
	wallets        []Wallet
	filteredWallets []Wallet
	err            error
	quitting       bool
	input          textinput.Model
	passwordInput  textinput.Model
	inputMode      string
	searchQuery    string
	help           help.Model
	keys           keyMap
	status         string
	statusColor    lipgloss.Color
	showingPrivateKey bool
	selectedWallet *Wallet
	confirmingDelete bool
	walletToDelete *Wallet
}

type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	New      key.Binding
	Delete   key.Binding
	Export   key.Binding
	Copy     key.Binding
	Search   key.Binding
	Quit     key.Binding
	Help     key.Binding
	Enter    key.Binding
	Escape   key.Binding
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
		key.WithHelp("e", "export private key"),
	),
	Copy: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "copy address"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search"),
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
		key.WithHelp("enter", "confirm"),
	),
	Escape: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "cancel"),
	),
}

type item struct {
	wallet Wallet
}

// TUI Color Palette
const (
	primaryColor   = "#00D4FF"
	secondaryColor = "#FF6B6B"
	accentColor    = "#4ECDC4"
	successColor   = "#45B7D1"
	warningColor   = "#FFA07A"
	errorColor     = "#FF6B6B"
	textColor      = "#E1E1E6"
	mutedColor     = "#8892B0"
	bgColor        = "#0D1117"
	cardBgColor    = "#161B22"
	borderColor    = "#21262D"
)

// TUI Styles
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
		Foreground(lipgloss.Color(primaryColor)).
		Bold(true)

	mutedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(mutedColor))

	// Layout styles
	headerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color(primaryColor)).
		Bold(true).
		Padding(0, 1)

	cardStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(textColor))

	selectedCardStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(primaryColor)).
		Background(lipgloss.Color(cardBgColor)).
		Bold(true)

	modalStyle = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color(primaryColor)).
		Background(lipgloss.Color(bgColor)).
		Padding(2, 4).
		AlignHorizontal(lipgloss.Center).
		AlignVertical(lipgloss.Center)

	statusBarStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(textColor)).
		Italic(true)

	helpBarStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(mutedColor))

	titleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(primaryColor)).
		Bold(true).
		MarginBottom(1)

	addressStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(accentColor)).
		Bold(true)

	labelStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(textColor)).
		Italic(true)

	iconStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color(primaryColor))
)

func (i item) FilterValue() string { 
	addr := hex.EncodeToString(i.wallet.Address[:])
	return i.wallet.Label + " 0x" + addr
}

func (i item) Title() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	addressStr := "0x" + addr[:8] + "..." + addr[len(addr)-6:]
	
	if i.wallet.Label != "" {
		return fmt.Sprintf("💳 %s", i.wallet.Label)
	}
	return fmt.Sprintf("💳 %s", addressStr)
}

func (i item) Description() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	addressStr := "0x" + addr[:8] + "..." + addr[len(addr)-6:]
	
	if i.wallet.Label != "" {
		return fmt.Sprintf("%s • %s", addressStr, i.wallet.CreatedAt.Format("Jan 2, 2006"))
	}
	return i.wallet.CreatedAt.Format("Jan 2, 2006 15:04")
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

func initialModel(walletMgr *WalletManager) model {
	wallets, err := walletMgr.ListWallets()
	if err != nil {
		wallets = []Wallet{} // Empty list on error
	}
	
	items := make([]list.Item, len(wallets))
	for i, w := range wallets {
		items[i] = item{wallet: w}
	}

	const defaultWidth = 80
	const listHeight = 15

	// Create simple delegate for compact list
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = selectedCardStyle
	delegate.Styles.SelectedDesc = mutedStyle
	delegate.Styles.NormalTitle = cardStyle
	delegate.Styles.NormalDesc = mutedStyle
	delegate.SetHeight(2) // Compact item height
	
	l := list.New(items, delegate, defaultWidth, listHeight)
	l.Title = "" // Remove duplicate title - we use custom header
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowPagination(true)
	l.SetShowHelp(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = mutedStyle

	// Input for wallet labels
	ti := textinput.New()
	ti.Placeholder = "Enter wallet label..."
	ti.CharLimit = 50
	ti.Width = 50

	// Password input for sensitive operations
	pi := textinput.New()
	pi.Placeholder = "Enter master password..."
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '*'
	pi.CharLimit = 100
	pi.Width = 50

	return model{
		list:            l,
		walletMgr:       walletMgr,
		wallets:         wallets,
		filteredWallets: wallets,
		input:           ti,
		passwordInput:   pi,
		help:            help.New(),
		keys:            keys,
		status:          infoStyle.Render(fmt.Sprintf("Ready - %d wallet(s) loaded", len(wallets))),
		statusColor:     "#00AAFF",
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

// Helper function to refresh wallet list
func (m model) refreshWalletList() model {
	wallets, err := m.walletMgr.ListWallets()
	if err != nil {
		m.status = errorStyle.Render("❌ Failed to load wallets: " + err.Error())
		return m
	}
	
	m.wallets = wallets
	m.filteredWallets = filterWallets(wallets, m.searchQuery)
	
	// Create new items and force list refresh
	items := make([]list.Item, len(m.filteredWallets))
	for i, w := range m.filteredWallets {
		items[i] = item{wallet: w}
	}
	m.list.SetItems(items)
	
	// Also update the list title to show count
	m.list.Title = headerStyle.Render(fmt.Sprintf("🔒 Ethereum Quantum-Resistant Wallet Manager (%d wallets)", len(wallets)))
	
	return m
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil

	case tea.KeyMsg:
		// Clear private key display on any key press
		if m.showingPrivateKey {
			m.showingPrivateKey = false
			if m.selectedWallet != nil {
				SecureZero(m.selectedWallet.PrivateKey[:])
				m.selectedWallet = nil
			}
			m.status = infoStyle.Render("Private key cleared from memory")
			return m, nil
		}
		
		// Handle delete confirmation
		if m.confirmingDelete {
			switch msg.String() {
			case "y", "Y":
				if m.walletToDelete != nil {
					addr := hex.EncodeToString(m.walletToDelete.Address[:])
					if err := m.walletMgr.DeleteWallet(addr); err == nil {
						m = m.refreshWalletList()
						m.status = successStyle.Render(fmt.Sprintf("✅ Wallet deleted: 0x%s...", addr[:10]))
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
				m.status = infoStyle.Render("Delete cancelled")
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
					// Create new wallet with label
					result := GenerateWallet()
					if wallet, err := result.Unwrap(); err == nil {
						wallet.Label = m.input.Value()
						if err := m.walletMgr.AddWallet(wallet); err == nil {
							// Reload wallets and refresh list
							m = m.refreshWalletList()
							addr := "0x" + hex.EncodeToString(wallet.Address[:])
							m.status = successStyle.Render(fmt.Sprintf("✅ Wallet created! %s (%d total)", addr[:12]+"...", len(m.wallets)))
							// Zero the private key in memory
							SecureZero(wallet.PrivateKey[:])
						} else {
							m.status = errorStyle.Render("❌ Failed to save wallet: " + err.Error())
						}
					} else {
						m.status = errorStyle.Render("❌ Failed to generate wallet: " + err.Error())
					}
				case "search":
					m.searchQuery = m.input.Value()
					m = m.refreshWalletList()
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
							m.status = warningStyle.Render("Private key displayed - handle with care!")
						} else {
							m.status = errorStyle.Render("Invalid password")
						}
					}
				}
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				return m, nil
			case "esc":
				m.inputMode = ""
				m.input.SetValue("")
				m.passwordInput.SetValue("")
				m.showingPrivateKey = false
				m.selectedWallet = nil
				m.status = infoStyle.Render("Cancelled")
				return m, nil
			}
			
			// Update the appropriate input
			var cmd tea.Cmd
			if m.inputMode == "password" {
				m.passwordInput, cmd = m.passwordInput.Update(msg)
			} else {
				m.input, cmd = m.input.Update(msg)
			}
			return m, cmd
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
			m.status = infoStyle.Render("Creating new wallet...")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Search):
			m.inputMode = "search"
			m.input.Placeholder = "Search by label or address..."
			m.input.Focus()
			m.status = infoStyle.Render("Search mode - type to filter wallets")
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Copy):
			if len(m.filteredWallets) > 0 {
				selectedIndex := m.list.Index()
				if selectedIndex >= 0 && selectedIndex < len(m.filteredWallets) {
					wallet := m.filteredWallets[selectedIndex]
					addr := "0x" + hex.EncodeToString(wallet.Address[:])
					if err := copyToClipboard(addr, 0); err == nil {
						m.status = successStyle.Render("📋 Address copied: " + addr[:10] + "...")
					} else {
						m.status = errorStyle.Render("❌ Failed to copy address")
					}
				}
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to copy")
			}
			return m, nil

		case key.Matches(msg, m.keys.Export):
			if len(m.filteredWallets) > 0 {
				selectedIndex := m.list.Index()
				if selectedIndex >= 0 && selectedIndex < len(m.filteredWallets) {
					wallet := m.filteredWallets[selectedIndex]
					m.selectedWallet = &wallet
					m.inputMode = "password"
					m.passwordInput.Focus()
					m.status = warningStyle.Render("🔐 Enter master password to view private key")
					return m, textinput.Blink
				}
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to export")
			}
			return m, nil

		case key.Matches(msg, m.keys.Delete):
			if len(m.filteredWallets) > 0 {
				selectedIndex := m.list.Index()
				if selectedIndex >= 0 && selectedIndex < len(m.filteredWallets) {
					wallet := m.filteredWallets[selectedIndex]
					m.walletToDelete = &wallet
					m.confirmingDelete = true
					addr := "0x" + hex.EncodeToString(wallet.Address[:])
					m.status = warningStyle.Render(fmt.Sprintf("❌ Delete wallet %s? (y/N)", addr[:10]+"..."))
				}
			} else {
				m.status = warningStyle.Render("⚠️ No wallets to delete")
			}
			return m, nil
		}
	}

	// Update list if not in input mode
	if m.inputMode == "" {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return successStyle.Render("👋 Goodbye! Stay secure!") + "\n"
	}

	// Handle input modes with simple overlay
	if m.inputMode != "" {
		var title, inputView, helpText string
		
		switch m.inputMode {
		case "new":
			title = "✨ Create New Wallet"
			inputView = m.input.View()
			helpText = "Enter to create • Esc to cancel"
		case "search":
			title = "🔍 Search Wallets"
			inputView = m.input.View()
			helpText = "Enter to search • Esc to cancel"
		case "password":
			title = "🔐 Authentication Required"
			inputView = m.passwordInput.View()
			helpText = "Enter master password • Esc to cancel"
		}
		
		content := fmt.Sprintf(
			"%s\n%s\n%s",
			titleStyle.Render(title),
			inputView,
			mutedStyle.Render(helpText),
		)
		
		modal := modalStyle.Copy().Padding(1, 2).Render(content)
		return lipgloss.Place(80, 24, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show private key if authenticated
	if m.showingPrivateKey && m.selectedWallet != nil {
		privateKeyHex := "0x" + hex.EncodeToString(m.selectedWallet.PrivateKey[:])
		addressHex := "0x" + hex.EncodeToString(m.selectedWallet.Address[:])
		
		content := fmt.Sprintf(
			"%s\n%s\n%s\n%s\n%s",
			titleStyle.Render("🔐 Private Key Export"),
			errorStyle.Render("⚠️  KEEP SECURE!"),
			fmt.Sprintf("Address: %s", addressStyle.Render(addressHex)),
			fmt.Sprintf("Private Key: %s", errorStyle.Render(privateKeyHex)),
			mutedStyle.Render("Press any key to clear..."),
		)
		
		modal := modalStyle.Copy().Padding(1, 2).Render(content)
		return lipgloss.Place(80, 24, lipgloss.Center, lipgloss.Center, modal)
	}

	// Show delete confirmation if active
	if m.confirmingDelete && m.walletToDelete != nil {
		addressHex := "0x" + hex.EncodeToString(m.walletToDelete.Address[:])
		label := m.walletToDelete.Label
		if label == "" {
			label = "Unlabeled Wallet"
		}
		
		content := fmt.Sprintf(
			"%s\n%s\n%s\n%s\n%s",
			titleStyle.Render("🗑️ Confirm Deletion"),
			errorStyle.Render("⚠️  PERMANENT ACTION!"),
			fmt.Sprintf("Wallet: %s", label),
			fmt.Sprintf("Address: %s", addressStyle.Render(addressHex[:16]+"...")),
			mutedStyle.Render("Press 'y' to confirm • 'n' or Esc to cancel"),
		)
		
		modal := modalStyle.Copy().Padding(1, 2).Render(content)
		return lipgloss.Place(80, 24, lipgloss.Center, lipgloss.Center, modal)
	}

	// Compact main layout
	var output strings.Builder
	
	// Header
	output.WriteString(headerStyle.Render("🔒 Quantum-Resistant Ethereum Wallet"))
	output.WriteString("\n")
	
	// Search info (if active)
	if m.searchQuery != "" {
		output.WriteString(mutedStyle.Render(fmt.Sprintf("🔍 '%s' (%d results)", m.searchQuery, len(m.filteredWallets))))
		output.WriteString("\n")
	}
	
	// Main wallet list
	output.WriteString(m.list.View())
	
	// Status line
	output.WriteString("\n")
	output.WriteString(statusBarStyle.Render(m.status))
	
	// Help line
	output.WriteString("\n")
	helpText := "n:new • c:copy • e:export • d:delete • /:search • q:quit"
	output.WriteString(helpBarStyle.Render(helpText))
	
	return output.String()
}

// Read password securely
func readPassword(prompt string) ([]byte, error) {
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

func main() {
	// Initialize clipboard
	if err := initClipboard(); err != nil {
		log.Printf("Warning: Clipboard not available: %v", err)
	}

	walletFile := "wallets.enc"
	walletMgr := NewWalletManager(walletFile)

	// Get master password
	password, err := readPassword("🔐 Enter master password: ")
	if err != nil {
		log.Fatal("Failed to read password:", err)
	}
	defer func() {
		// Zero password
		for i := range password {
			password[i] = 0
		}
	}()

	// Initialize wallet manager
	if err := walletMgr.Initialize(password); err != nil {
		log.Fatal("Failed to initialize wallet manager:", err)
	}

	// Always launch TUI - all commands available within the interface
	p := tea.NewProgram(initialModel(walletMgr), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal("Failed to run TUI:", err)
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

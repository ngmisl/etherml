package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
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
	Version   string            `json:"version"`
	Algorithm string            `json:"algorithm"`
	KDF       KDFParams         `json:"kdf"`
	Wallets   []EncryptedWallet `json:"wallets"`
	UpdatedAt time.Time         `json:"updated_at"`
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
	filePath string
	storage  *StorageFile
	key      []byte
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
			Algorithm: "aes256gcm-argon2id",
			Wallets:   []EncryptedWallet{},
		},
	}
}

// Initialize or load storage
func (wm *WalletManager) Initialize(password []byte) error {
	// Check if file exists
	if _, err := os.Stat(wm.filePath); os.IsNotExist(err) {
		// Create new storage
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

		wm.key = deriveKey(password, salt, wm.storage.KDF)
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

	// Verify by trying to decrypt first wallet
	if len(wm.storage.Wallets) > 0 {
		_, err := wm.decryptWallet(&wm.storage.Wallets[0])
		if err != nil {
			return errors.New("invalid password")
		}
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

// Add wallet to storage
func (wm *WalletManager) AddWallet(wallet *Wallet) error {
	// Encrypt private key
	encrypted, nonce, err := encryptData(wallet.PrivateKey[:], wm.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	ew := EncryptedWallet{
		Address:      hex.EncodeToString(wallet.Address[:]),
		EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
		Nonce:        base64.StdEncoding.EncodeToString(nonce[:]),
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

// Decrypt wallet
func (wm *WalletManager) decryptWallet(ew *EncryptedWallet) (*Wallet, error) {
	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(ew.Nonce)
	if err != nil {
		return nil, err
	}

	var nonce Nonce
	copy(nonce[:], nonceBytes)

	decrypted, err := decryptData(EncryptedData(encrypted), wm.key, nonce)
	if err != nil {
		return nil, err
	}

	addressBytes, err := hex.DecodeString(ew.Address)
	if err != nil {
		return nil, err
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
	list      list.Model
	walletMgr *WalletManager
	wallets   []Wallet
	err       error
	quitting  bool
	input     textinput.Model
	inputMode string
	help      help.Model
	keys      keyMap
}

type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	New    key.Binding
	Delete key.Binding
	Export key.Binding
	Quit   key.Binding
	Help   key.Binding
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
		key.WithHelp("e", "export"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
}

type item struct {
	wallet Wallet
}

func (i item) FilterValue() string { return hex.EncodeToString(i.wallet.Address[:]) }
func (i item) Title() string {
	addr := hex.EncodeToString(i.wallet.Address[:])
	return "0x" + addr
}
func (i item) Description() string {
	label := i.wallet.Label
	if label == "" {
		label = "No label"
	}
	return fmt.Sprintf("%s | Created: %s", label, i.wallet.CreatedAt.Format("2006-01-02"))
}

func initialModel(walletMgr *WalletManager) model {
	wallets, _ := walletMgr.ListWallets()
	items := make([]list.Item, len(wallets))
	for i, w := range wallets {
		items[i] = item{wallet: w}
	}

	const defaultWidth = 20
	const listHeight = 14

	l := list.New(items, list.NewDefaultDelegate(), defaultWidth, listHeight)
	l.Title = "Ethereum Wallets"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = lipgloss.NewStyle().MarginLeft(2)
	l.Styles.PaginationStyle = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	l.Styles.HelpStyle = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)

	ti := textinput.New()
	ti.Placeholder = "Enter wallet label"
	ti.CharLimit = 50
	ti.Width = 50

	return model{
		list:      l,
		walletMgr: walletMgr,
		wallets:   wallets,
		input:     ti,
		help:      help.New(),
		keys:      keys,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil

	case tea.KeyMsg:
		if m.inputMode != "" {
			switch msg.String() {
			case "enter":
				if m.inputMode == "new" {
					// Create new wallet with label
					result := GenerateWallet()
					if wallet, err := result.Unwrap(); err == nil {
						wallet.Label = m.input.Value()
						if err := m.walletMgr.AddWallet(wallet); err == nil {
							// Reload wallets
							m.wallets, _ = m.walletMgr.ListWallets()
							items := make([]list.Item, len(m.wallets))
							for i, w := range m.wallets {
								items[i] = item{wallet: w}
							}
							m.list.SetItems(items)
						}
					}
				}
				m.inputMode = ""
				m.input.SetValue("")
				return m, nil
			case "esc":
				m.inputMode = ""
				m.input.SetValue("")
				return m, nil
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}

		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit

		case key.Matches(msg, m.keys.New):
			m.inputMode = "new"
			m.input.Focus()
			return m, textinput.Blink

		case key.Matches(msg, m.keys.Export):
			if i, ok := m.list.SelectedItem().(item); ok {
				// In real implementation, show private key securely
				fmt.Printf("\nAddress: 0x%s\n", hex.EncodeToString(i.wallet.Address[:]))
				fmt.Printf("Private Key: 0x%s\n", hex.EncodeToString(i.wallet.PrivateKey[:]))
			}
			return m, nil
		}
	}

	if m.inputMode == "" {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	if m.inputMode != "" {
		return fmt.Sprintf(
			"Creating new wallet...\n\n%s\n\n%s",
			m.input.View(),
			"(esc to cancel)",
		) + "\n"
	}

	return "\n" + m.list.View()
}

// Read password securely
func readPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password, err
}

func main() {
	// Check command line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: wallet <command>")
		fmt.Println("Commands: new, list, browse")
		os.Exit(1)
	}

	walletFile := "wallets.enc"
	walletMgr := NewWalletManager(walletFile)

	// Get master password
	password, err := readPassword("Enter master password: ")
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

	switch os.Args[1] {
	case "new":
		result := GenerateWallet()
		wallet, err := result.Unwrap()
		if err != nil {
			log.Fatal("Failed to generate wallet:", err)
		}

		fmt.Print("Enter wallet label (optional): ")
		var label string
		fmt.Scanln(&label)
		wallet.Label = strings.TrimSpace(label)

		if err := walletMgr.AddWallet(wallet); err != nil {
			log.Fatal("Failed to save wallet:", err)
		}

		fmt.Printf("New wallet created!\n")
		fmt.Printf("Address: 0x%s\n", hex.EncodeToString(wallet.Address[:]))
		fmt.Printf("Private Key: 0x%s\n", hex.EncodeToString(wallet.PrivateKey[:]))
		fmt.Println("\nIMPORTANT: Save your private key securely. It cannot be recovered!")

		// Zero the private key in memory
		for i := range wallet.PrivateKey {
			wallet.PrivateKey[i] = 0
		}

	case "list":
		wallets, err := walletMgr.ListWallets()
		if err != nil {
			log.Fatal("Failed to list wallets:", err)
		}

		fmt.Printf("Found %d wallet(s):\n\n", len(wallets))
		for _, wallet := range wallets {
			fmt.Printf("Address: 0x%s\n", hex.EncodeToString(wallet.Address[:]))
			fmt.Printf("Label: %s\n", wallet.Label)
			fmt.Printf("Created: %s\n", wallet.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Println("---")
		}

	case "browse":
		p := tea.NewProgram(initialModel(walletMgr))
		if _, err := p.Run(); err != nil {
			log.Fatal("Failed to run TUI:", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
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

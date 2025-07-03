package project

import (
	"crypto/ecdsa"
	"encoding/hex"
	"time"
)

// Core types for project management

// Address represents an Ethereum address
type Address [20]byte

// String returns the hex representation of the address
func (a Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

// PrivateKey represents an Ethereum private key
type PrivateKey [32]byte

// ProjectWallet extends the basic wallet with project-specific metadata
type ProjectWallet struct {
	PrivateKey PrivateKey `json:"-"`                    // Never serialized
	Address    Address    `json:"address"`
	Label      string     `json:"label"`
	Network    string     `json:"network"`              // "mainnet" or "testnet"
	Role       string     `json:"role,omitempty"`       // e.g., "deployer", "treasury"
	Tags       []string   `json:"tags,omitempty"`       // Custom tags
	Notes      string     `json:"notes,omitempty"`      // User notes
	CreatedAt  time.Time  `json:"created_at"`
	LastUsed   time.Time  `json:"last_used,omitempty"`
}

// ProjectInfo contains metadata about a project
type ProjectInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	LastAccessed time.Time        `json:"last_accessed"`
	WalletCount int               `json:"wallet_count"`
	NetworkDist map[string]int    `json:"network_distribution"`
	Settings    ProjectSettings   `json:"settings"`
}

// ProjectSettings contains project-specific configuration
type ProjectSettings struct {
	AutoLockMinutes       int    `json:"auto_lock_minutes"`
	DefaultNetwork        string `json:"default_network"`
	BulkCreationTemplate  string `json:"bulk_creation_template"`
	ExportRestrictions    bool   `json:"export_restrictions"`
}

// BulkConfig defines parameters for bulk wallet creation
type BulkConfig struct {
	Count           int               `json:"count"`
	LabelTemplate   string            `json:"label_template"`
	NetworkMapping  map[int]string    `json:"network_mapping"` // wallet index -> network
	Roles          []string          `json:"roles,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	DefaultNetwork string            `json:"default_network"`
}

// ExportedWallet contains wallet data for export
type ExportedWallet struct {
	Address    string    `json:"address"`
	PrivateKey string    `json:"private_key"`
	Label      string    `json:"label"`
	Network    string    `json:"network"`
	Role       string    `json:"role,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// WalletUpdate defines fields that can be updated on a wallet
type WalletUpdate struct {
	Label   *string   `json:"label,omitempty"`
	Role    *string   `json:"role,omitempty"`
	Tags    *[]string `json:"tags,omitempty"`
	Notes   *string   `json:"notes,omitempty"`
	Network *string   `json:"network,omitempty"`
}

// KDFParams for Argon2id key derivation
type KDFParams struct {
	Function    string `json:"function"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"`
	KeyLen      uint32 `json:"key_len"`
}

// ProjectStorageFile represents the encrypted project metadata file
type ProjectStorageFile struct {
	Version              string      `json:"version"`
	Project              ProjectInfo `json:"project"`
	Algorithm            string      `json:"algorithm"`
	KDF                  KDFParams   `json:"kdf"`
	MLKEMPublicKey       string      `json:"mlkem_public_key"`
	MLKEMPrivateKeyEnc   string      `json:"mlkem_private_key_enc"`
	MLKEMPrivateKeyNonce string      `json:"mlkem_private_key_nonce"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

// EncryptedProjectWallet for storage in wallets.enc
type EncryptedProjectWallet struct {
	Address      string    `json:"address"`
	EncryptedKey string    `json:"encrypted_key"`
	Nonce        string    `json:"nonce"`
	Label        string    `json:"label"`
	Network      string    `json:"network"`
	Role         string    `json:"role,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsed     time.Time `json:"last_used,omitempty"`
}

// WalletStorageFile represents the encrypted wallets storage file
type WalletStorageFile struct {
	Version              string                   `json:"version"`
	Algorithm            string                   `json:"algorithm"`
	KDF                  KDFParams                `json:"kdf"`
	EncryptedWalletsData string                   `json:"encrypted_wallets_data"`
	HMAC                 string                   `json:"hmac"`
	Wallets              []EncryptedProjectWallet `json:"wallets"` // Legacy support
	UpdatedAt            time.Time                `json:"updated_at"`
}

// SessionData holds decrypted project data in memory
type SessionData struct {
	ProjectInfo      ProjectInfo
	Wallets          []ProjectWallet
	MLKEMPrivateKey  []byte
	DerivedKey       []byte  // Store only the derived key, not password
	MLKEMPublicKey   []byte  // Store public key for saving operations
	KDFParams        KDFParams // Store KDF params for saving operations
	LastActivity     time.Time
	AutoLockTimer    *time.Timer
}

// ProjectManager interface defines project management operations
type ProjectManager interface {
	// Project lifecycle
	CreateProject(name, description string, password []byte) (*Project, error)
	ListProjects() ([]ProjectInfo, error)
	OpenProject(id string, password []byte) (*Project, error)
	DeleteProject(id string) error
	RenameProject(id string, newName string) error
	
	// Import/Export
	ExportProject(id string, path string) error
	ImportProject(path string, password []byte) (*Project, error)
	
	// Utilities
	ProjectExists(name string) bool
	GetProjectPath(id string) string
	ValidateProjectName(name string) error
}

// Project interface defines operations on an open project
type Project interface {
	// Project info
	GetInfo() ProjectInfo
	GetID() string
	GetName() string
	IsLocked() bool
	
	// Session management
	Lock() error
	Unlock(password []byte) error
	RefreshSession() error
	SetAutoLock(minutes int) error
	
	// Wallet operations
	CreateWallet(label, network string) (*ProjectWallet, error)
	BulkCreateWallets(config BulkConfig) ([]*ProjectWallet, error)
	ListWallets() ([]*ProjectWallet, error)
	GetWallet(address Address) (*ProjectWallet, error)
	UpdateWallet(address Address, updates WalletUpdate) error
	DeleteWallet(address Address) error
	
	// Export operations
	ExportWallet(address Address) (*ExportedWallet, error)
	ExportAllWallets() ([]*ExportedWallet, error)
	
	// Persistence
	Save() error
	Close() error
}

// ProjectError represents project-specific errors
type ProjectError struct {
	Code    string
	Message string
	Cause   error
}

func (e ProjectError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Common error codes
const (
	ErrCodeProjectNotFound     = "PROJECT_NOT_FOUND"
	ErrCodeProjectExists       = "PROJECT_EXISTS"
	ErrCodeInvalidName         = "INVALID_NAME"
	ErrCodeInvalidPassword     = "INVALID_PASSWORD"
	ErrCodeProjectLocked       = "PROJECT_LOCKED"
	ErrCodeSessionExpired      = "SESSION_EXPIRED"
	ErrCodeWalletNotFound      = "WALLET_NOT_FOUND"
	ErrCodeWalletExists        = "WALLET_EXISTS"
	ErrCodeInvalidNetwork      = "INVALID_NETWORK"
	ErrCodeBulkCreateFailed    = "BULK_CREATE_FAILED"
	ErrCodeTemplateInvalid     = "TEMPLATE_INVALID"
	ErrCodeEncryptionFailed    = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed    = "DECRYPTION_FAILED"
	ErrCodeStorageCorrupted    = "STORAGE_CORRUPTED"
	ErrCodeFileOperation       = "FILE_OPERATION"
)

// Error constructors
func NewProjectError(code, message string, cause error) *ProjectError {
	return &ProjectError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func ErrProjectNotFound(name string) *ProjectError {
	return NewProjectError(ErrCodeProjectNotFound, "project not found: "+name, nil)
}

func ErrProjectExists(name string) *ProjectError {
	return NewProjectError(ErrCodeProjectExists, "project already exists: "+name, nil)
}

func ErrInvalidPassword() *ProjectError {
	return NewProjectError(ErrCodeInvalidPassword, "invalid password", nil)
}

func ErrProjectLocked(name string) *ProjectError {
	return NewProjectError(ErrCodeProjectLocked, "project is locked: "+name, nil)
}

func ErrWalletNotFound(address string) *ProjectError {
	return NewProjectError(ErrCodeWalletNotFound, "wallet not found: "+address, nil)
}

// Utility functions

// ValidNetworks returns the list of supported networks
func ValidNetworks() []string {
	return []string{"mainnet", "testnet"}
}

// IsValidNetwork checks if a network name is valid
func IsValidNetwork(network string) bool {
	for _, valid := range ValidNetworks() {
		if network == valid {
			return true
		}
	}
	return false
}

// DefaultProjectSettings returns default settings for new projects
func DefaultProjectSettings() ProjectSettings {
	return ProjectSettings{
		AutoLockMinutes:      15,
		DefaultNetwork:       "testnet",
		BulkCreationTemplate: "{project}-{role}-{index}",
		ExportRestrictions:   false,
	}
}

// SecureZero zeros memory
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ToECDSAPrivateKey converts our PrivateKey to *ecdsa.PrivateKey
func (pk *PrivateKey) ToECDSA() (*ecdsa.PrivateKey, error) {
	// This would use go-ethereum's crypto.ToECDSA
	// Implementation will be added when integrating with main app
	return nil, nil
}
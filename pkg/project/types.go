package project

import (
	"time"
)

// NetworkType represents wallet network type
type NetworkType string

const (
	Mainnet NetworkType = "mainnet"
	Testnet NetworkType = "testnet"
)

// Project represents a project folder containing organized wallets
type Project interface {
	GetInfo() ProjectInfo
	GetWallets() ([]ProjectWallet, error)
	CreateWallet(label string, network NetworkType) (*ProjectWallet, error)
	BulkCreateWallets(config BulkConfig) ([]*ProjectWallet, error)
	EditWallet(address string, newLabel string, newNetwork NetworkType) error
	DeleteWallet(address string) error
	ExportWallet(address string) (string, error) // Returns private key hex
	Save() error
	Lock()
	IsLocked() bool
}

// ProjectManager manages all projects
type ProjectManager interface {
	ListProjects() ([]ProjectInfo, error)
	CreateProject(name string) (Project, error)
	OpenProject(name string) (Project, error)
	DeleteProject(name string) error
	GetProjectsDir() string
}

// ProjectInfo contains project metadata
type ProjectInfo struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	WalletCount int       `json:"wallet_count"`
	MainnetCount int      `json:"mainnet_count"`
	TestnetCount int      `json:"testnet_count"`
}

// ProjectWallet represents a wallet within a project
type ProjectWallet struct {
	Address     [20]byte    `json:"address"`
	PrivateKey  [32]byte    `json:"-"` // Never serialized
	Label       string      `json:"label"`
	Network     NetworkType `json:"network"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// EncryptedProjectWallet for storage
type EncryptedProjectWallet struct {
	Address      string      `json:"address"`
	EncryptedKey string      `json:"encrypted_key"`
	Nonce        string      `json:"nonce"`
	Label        string      `json:"label"`
	Network      NetworkType `json:"network"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// ProjectStorage represents the storage format for a project
type ProjectStorage struct {
	Version       string `json:"version"`
	Algorithm     string `json:"algorithm"`
	ProjectInfo   ProjectInfo `json:"project_info"`
	
	// Legacy ML-KEM encryption fields (for backward compatibility)
	KDF                  KDFParams `json:"kdf,omitempty"`
	MLKEMPublicKey       string    `json:"mlkem_public_key,omitempty"`
	MLKEMPrivateKeyEnc   string    `json:"mlkem_private_key_enc,omitempty"`
	MLKEMPrivateKeyNonce string    `json:"mlkem_private_key_nonce,omitempty"`
	
	// Legacy encrypted wallet data (for backward compatibility)
	EncryptedWallets string `json:"encrypted_wallets,omitempty"`
	HMAC            string `json:"hmac,omitempty"`
	
	// New lightweight wallet storage (per-wallet encryption)
	WalletsJSON string `json:"wallets_json,omitempty"`
	
	UpdatedAt time.Time `json:"updated_at"`
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

// BulkConfig for bulk wallet creation
type BulkConfig struct {
	Count         int                     `json:"count"`
	LabelTemplate string                  `json:"label_template"`
	NetworkConfig map[int]NetworkType     `json:"network_config"` // index -> network
	AutoLabel     bool                    `json:"auto_label"`
}

// ProjectTUIState represents the current state of the project TUI
type ProjectTUIState int

const (
	ProjectListState ProjectTUIState = iota
	ProjectWalletState
	BulkCreateState
)
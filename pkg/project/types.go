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

// Project represents a project folder containing organized wallet references
type Project interface {
	GetInfo() ProjectInfo
	GetWalletRefs() ([]WalletRef, error)
	AddWalletRef(address string, label string, network NetworkType) error
	EditWalletRef(address string, newLabel string, newNetwork NetworkType) error
	DeleteWalletRef(address string) error
	Save() error
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
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	WalletCount  int       `json:"wallet_count"`
	MainnetCount int       `json:"mainnet_count"`
	TestnetCount int       `json:"testnet_count"`
}

// WalletRef represents a reference to a wallet stored in the main wallet manager
type WalletRef struct {
	Address   string      `json:"address"`    // Hex address (without 0x prefix)
	Label     string      `json:"label"`      // Project-specific label
	Network   NetworkType `json:"network"`    // Network assignment
	CreatedAt time.Time   `json:"created_at"` // When added to project
	UpdatedAt time.Time   `json:"updated_at"` // Last updated in project
}

// ProjectStorage represents the simple storage format for a project
type ProjectStorage struct {
	Version     string      `json:"version"`
	ProjectInfo ProjectInfo `json:"project_info"`
	WalletRefs  []WalletRef `json:"wallet_refs"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// BulkConfig for bulk wallet creation
type BulkConfig struct {
	Count         int                 `json:"count"`
	LabelTemplate string              `json:"label_template"`
	NetworkConfig map[int]NetworkType `json:"network_config"` // index -> network
	AutoLabel     bool                `json:"auto_label"`
}

// ProjectTUIState represents the current state of the project TUI
type ProjectTUIState int

const (
	ProjectListState ProjectTUIState = iota
	ProjectWalletState
	BulkCreateState
)
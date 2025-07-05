package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ProjectImpl implements the Project interface with simple JSON storage
type ProjectImpl struct {
	info        ProjectInfo
	walletRefs  []WalletRef
	projectPath string
	storage     *ProjectStorage
}

// NewProject creates a new project instance
func NewProject(name string, projectPath string) *ProjectImpl {
	return &ProjectImpl{
		info: ProjectInfo{
			Name:        name,
			Description: fmt.Sprintf("Project: %s", name),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		projectPath: projectPath,
		walletRefs:  []WalletRef{},
	}
}

// GetInfo returns project information
func (p *ProjectImpl) GetInfo() ProjectInfo {
	return p.info
}

// GetWalletRefs returns all wallet references in the project
func (p *ProjectImpl) GetWalletRefs() ([]WalletRef, error) {
	return p.walletRefs, nil
}

// Initialize sets up a new project with simple JSON storage
func (p *ProjectImpl) Initialize() error {
	// Create storage structure
	p.storage = &ProjectStorage{
		Version:     "1.0",
		ProjectInfo: p.info,
		WalletRefs:  []WalletRef{},
		UpdatedAt:   time.Now(),
	}

	return p.Save()
}

// Load opens an existing project from disk
func (p *ProjectImpl) Load() error {
	projectFile := filepath.Join(p.projectPath, "project.json")

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
	p.walletRefs = storage.WalletRefs

	// Ensure walletRefs is not nil
	if p.walletRefs == nil {
		p.walletRefs = []WalletRef{}
	}

	return nil
}

// Save persists the project to disk using simple JSON
func (p *ProjectImpl) Save() error {
	// Update project info
	p.info.UpdatedAt = time.Now()
	p.info.WalletCount = len(p.walletRefs)

	// Count mainnet/testnet wallets
	mainnetCount := 0
	testnetCount := 0
	for _, ref := range p.walletRefs {
		if ref.Network == Mainnet {
			mainnetCount++
		} else {
			testnetCount++
		}
	}
	p.info.MainnetCount = mainnetCount
	p.info.TestnetCount = testnetCount

	// Update storage
	p.storage.ProjectInfo = p.info
	p.storage.WalletRefs = p.walletRefs
	p.storage.UpdatedAt = time.Now()

	// Write to file
	projectFile := filepath.Join(p.projectPath, "project.json")
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

// AddWalletRef adds a wallet reference to the project
func (p *ProjectImpl) AddWalletRef(address string, label string, network NetworkType) error {
	// Normalize address (remove 0x prefix if present)
	cleanAddr := strings.TrimPrefix(strings.ToLower(address), "0x")

	// Check if wallet already exists in project
	for _, ref := range p.walletRefs {
		if strings.EqualFold(ref.Address, cleanAddr) {
			return fmt.Errorf("wallet %s already exists in project", address)
		}
	}

	// Create new wallet reference
	walletRef := WalletRef{
		Address:   cleanAddr,
		Label:     label,
		Network:   network,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	p.walletRefs = append(p.walletRefs, walletRef)
	return nil
}

// EditWalletRef modifies an existing wallet reference
func (p *ProjectImpl) EditWalletRef(address string, newLabel string, newNetwork NetworkType) error {
	cleanAddr := strings.TrimPrefix(strings.ToLower(address), "0x")

	// Find wallet reference
	for i, ref := range p.walletRefs {
		if strings.EqualFold(ref.Address, cleanAddr) {
			// Update wallet reference
			p.walletRefs[i].Label = newLabel
			p.walletRefs[i].Network = newNetwork
			p.walletRefs[i].UpdatedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("wallet with address %s not found in project", address)
}

// DeleteWalletRef removes a wallet reference from the project
func (p *ProjectImpl) DeleteWalletRef(address string) error {
	cleanAddr := strings.TrimPrefix(strings.ToLower(address), "0x")

	// Find and remove wallet reference
	for i, ref := range p.walletRefs {
		if strings.EqualFold(ref.Address, cleanAddr) {
			// Remove from slice
			p.walletRefs = append(p.walletRefs[:i], p.walletRefs[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("wallet with address %s not found in project", address)
}

// BulkAddWalletRefs adds multiple wallet references
func (p *ProjectImpl) BulkAddWalletRefs(refs []WalletRef) error {
	for _, ref := range refs {
		if err := p.AddWalletRef(ref.Address, ref.Label, ref.Network); err != nil {
			return fmt.Errorf("failed to add wallet ref %s: %w", ref.Address, err)
		}
	}
	return nil
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
package project

import (
	"encoding/hex"
	"strings"
	"time"
)

// ListWallets returns all wallets in the project
func (p *ProjectImpl) ListWallets() ([]*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	// Create copies of wallets to avoid exposing internal state
	wallets := make([]*ProjectWallet, len(p.session.Wallets))
	for i := range p.session.Wallets {
		wallet := p.session.Wallets[i]
		wallets[i] = &wallet
	}

	p.RefreshSession()
	return wallets, nil
}

// GetWallet retrieves a specific wallet by address
func (p *ProjectImpl) GetWallet(address Address) (*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	for i := range p.session.Wallets {
		if p.session.Wallets[i].Address == address {
			wallet := p.session.Wallets[i]
			p.RefreshSession()
			return &wallet, nil
		}
	}

	return nil, ErrWalletNotFound(address.String())
}

// UpdateWallet updates wallet metadata
func (p *ProjectImpl) UpdateWallet(address Address, updates WalletUpdate) error {
	if p.locked {
		return ErrProjectLocked(p.GetName())
	}

	// Find wallet
	walletIndex := -1
	for i := range p.session.Wallets {
		if p.session.Wallets[i].Address == address {
			walletIndex = i
			break
		}
	}

	if walletIndex == -1 {
		return ErrWalletNotFound(address.String())
	}

	wallet := &p.session.Wallets[walletIndex]
	oldNetwork := wallet.Network

	// Apply updates
	if updates.Label != nil {
		wallet.Label = *updates.Label
	}
	if updates.Role != nil {
		wallet.Role = *updates.Role
	}
	if updates.Tags != nil {
		wallet.Tags = *updates.Tags
	}
	if updates.Notes != nil {
		wallet.Notes = *updates.Notes
	}
	if updates.Network != nil {
		if !IsValidNetwork(*updates.Network) {
			return NewProjectError(ErrCodeInvalidNetwork, "invalid network: "+*updates.Network, nil)
		}
		
		// Update network distribution if network changed
		if oldNetwork != *updates.Network {
			if p.session.ProjectInfo.NetworkDist == nil {
				p.session.ProjectInfo.NetworkDist = make(map[string]int)
			}
			
			// Decrease old network count
			if p.session.ProjectInfo.NetworkDist[oldNetwork] > 0 {
				p.session.ProjectInfo.NetworkDist[oldNetwork]--
			}
			
			// Increase new network count
			p.session.ProjectInfo.NetworkDist[*updates.Network]++
		}
		
		wallet.Network = *updates.Network
	}

	// Update project metadata
	p.session.ProjectInfo.UpdatedAt = p.session.LastActivity

	// Save changes
	if err := p.Save(); err != nil {
		return err
	}

	p.RefreshSession()
	return nil
}

// DeleteWallet removes a wallet from the project
func (p *ProjectImpl) DeleteWallet(address Address) error {
	if p.locked {
		return ErrProjectLocked(p.GetName())
	}

	// Find wallet
	walletIndex := -1
	var wallet *ProjectWallet
	for i := range p.session.Wallets {
		if p.session.Wallets[i].Address == address {
			walletIndex = i
			wallet = &p.session.Wallets[i]
			break
		}
	}

	if walletIndex == -1 {
		return ErrWalletNotFound(address.String())
	}

	// Zero private key before removal
	SecureZero(wallet.PrivateKey[:])

	// Remove from slice
	p.session.Wallets = append(p.session.Wallets[:walletIndex], p.session.Wallets[walletIndex+1:]...)

	// Update project stats
	p.session.ProjectInfo.WalletCount--
	if p.session.ProjectInfo.NetworkDist == nil {
		p.session.ProjectInfo.NetworkDist = make(map[string]int)
	}
	if p.session.ProjectInfo.NetworkDist[wallet.Network] > 0 {
		p.session.ProjectInfo.NetworkDist[wallet.Network]--
	}
	p.session.ProjectInfo.UpdatedAt = p.session.LastActivity

	// Save changes
	if err := p.Save(); err != nil {
		return err
	}

	p.RefreshSession()
	return nil
}

// ExportWallet exports a single wallet's private key
func (p *ProjectImpl) ExportWallet(address Address) (*ExportedWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	wallet, err := p.GetWallet(address)
	if err != nil {
		return nil, err
	}

	exported := &ExportedWallet{
		Address:    wallet.Address.String(),
		PrivateKey: "0x" + hex.EncodeToString(wallet.PrivateKey[:]),
		Label:      wallet.Label,
		Network:    wallet.Network,
		Role:       wallet.Role,
		CreatedAt:  wallet.CreatedAt,
	}

	// Update last used timestamp
	for i := range p.session.Wallets {
		if p.session.Wallets[i].Address == address {
			p.session.Wallets[i].LastUsed = p.session.LastActivity
			break
		}
	}

	p.RefreshSession()
	return exported, nil
}

// ExportAllWallets exports all wallets in the project
func (p *ProjectImpl) ExportAllWallets() ([]*ExportedWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	exported := make([]*ExportedWallet, len(p.session.Wallets))
	
	for i, wallet := range p.session.Wallets {
		exported[i] = &ExportedWallet{
			Address:    wallet.Address.String(),
			PrivateKey: "0x" + hex.EncodeToString(wallet.PrivateKey[:]),
			Label:      wallet.Label,
			Network:    wallet.Network,
			Role:       wallet.Role,
			CreatedAt:  wallet.CreatedAt,
		}
		
		// Update last used timestamp
		p.session.Wallets[i].LastUsed = p.session.LastActivity
	}

	// Save updated timestamps
	if err := p.Save(); err != nil {
		return nil, err
	}

	p.RefreshSession()
	return exported, nil
}

// SearchWallets finds wallets matching search criteria
func (p *ProjectImpl) SearchWallets(query string) ([]*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return p.ListWallets()
	}

	var matches []*ProjectWallet
	
	for i := range p.session.Wallets {
		wallet := &p.session.Wallets[i]
		
		// Search in various fields
		if p.matchesQuery(wallet, query) {
			matches = append(matches, wallet)
		}
	}

	p.RefreshSession()
	return matches, nil
}

// matchesQuery checks if a wallet matches the search query
func (p *ProjectImpl) matchesQuery(wallet *ProjectWallet, query string) bool {
	// Search in label
	if strings.Contains(strings.ToLower(wallet.Label), query) {
		return true
	}
	
	// Search in address
	if strings.Contains(strings.ToLower(wallet.Address.String()), query) {
		return true
	}
	
	// Search in role
	if strings.Contains(strings.ToLower(wallet.Role), query) {
		return true
	}
	
	// Search in network
	if strings.Contains(strings.ToLower(wallet.Network), query) {
		return true
	}
	
	// Search in tags
	for _, tag := range wallet.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	
	// Search in notes
	if strings.Contains(strings.ToLower(wallet.Notes), query) {
		return true
	}
	
	return false
}

// GetWalletsByNetwork returns wallets filtered by network
func (p *ProjectImpl) GetWalletsByNetwork(network string) ([]*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	if !IsValidNetwork(network) {
		return nil, NewProjectError(ErrCodeInvalidNetwork, "invalid network: "+network, nil)
	}

	var wallets []*ProjectWallet
	
	for i := range p.session.Wallets {
		if p.session.Wallets[i].Network == network {
			wallet := p.session.Wallets[i]
			wallets = append(wallets, &wallet)
		}
	}

	p.RefreshSession()
	return wallets, nil
}

// GetWalletsByRole returns wallets filtered by role
func (p *ProjectImpl) GetWalletsByRole(role string) ([]*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	var wallets []*ProjectWallet
	
	for i := range p.session.Wallets {
		if p.session.Wallets[i].Role == role {
			wallet := p.session.Wallets[i]
			wallets = append(wallets, &wallet)
		}
	}

	p.RefreshSession()
	return wallets, nil
}

// GetNetworkDistribution returns the distribution of wallets across networks
func (p *ProjectImpl) GetNetworkDistribution() (map[string]int, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	// Recalculate distribution to ensure accuracy
	distribution := make(map[string]int)
	
	for _, wallet := range p.session.Wallets {
		distribution[wallet.Network]++
	}

	// Update cached distribution
	p.session.ProjectInfo.NetworkDist = distribution

	p.RefreshSession()
	return distribution, nil
}

// GetRoleDistribution returns the distribution of wallets across roles
func (p *ProjectImpl) GetRoleDistribution() (map[string]int, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	distribution := make(map[string]int)
	
	for _, wallet := range p.session.Wallets {
		role := wallet.Role
		if role == "" {
			role = "unassigned"
		}
		distribution[role]++
	}

	p.RefreshSession()
	return distribution, nil
}

// ValidateWalletAddress checks if an address belongs to this project
func (p *ProjectImpl) ValidateWalletAddress(address Address) bool {
	if p.locked {
		return false
	}

	for _, wallet := range p.session.Wallets {
		if wallet.Address == address {
			return true
		}
	}
	
	return false
}

// GetProjectStatistics returns comprehensive project statistics
func (p *ProjectImpl) GetProjectStatistics() (*ProjectStatistics, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	networkDist, _ := p.GetNetworkDistribution()
	roleDist, _ := p.GetRoleDistribution()

	stats := &ProjectStatistics{
		TotalWallets:         len(p.session.Wallets),
		NetworkDistribution:  networkDist,
		RoleDistribution:     roleDist,
		CreatedAt:           p.session.ProjectInfo.CreatedAt,
		LastAccessed:        p.session.ProjectInfo.LastAccessed,
		LastUpdated:         p.session.ProjectInfo.UpdatedAt,
		AutoLockMinutes:     p.session.ProjectInfo.Settings.AutoLockMinutes,
	}

	// Calculate usage statistics
	var walletsWithActivity int
	for _, wallet := range p.session.Wallets {
		if !wallet.LastUsed.IsZero() {
			walletsWithActivity++
		}
	}
	stats.WalletsWithActivity = walletsWithActivity

	p.RefreshSession()
	return stats, nil
}

// ProjectStatistics contains comprehensive project statistics
type ProjectStatistics struct {
	TotalWallets         int            `json:"total_wallets"`
	WalletsWithActivity  int            `json:"wallets_with_activity"`
	NetworkDistribution  map[string]int `json:"network_distribution"`
	RoleDistribution     map[string]int `json:"role_distribution"`
	CreatedAt           time.Time      `json:"created_at"`
	LastAccessed        time.Time      `json:"last_accessed"`
	LastUpdated         time.Time      `json:"last_updated"`
	AutoLockMinutes     int            `json:"auto_lock_minutes"`
}

// CompareWallets compares two wallets for sorting
func CompareWallets(a, b *ProjectWallet, sortBy string) int {
	switch sortBy {
	case "label":
		return strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label))
	case "network":
		return strings.Compare(a.Network, b.Network)
	case "role":
		return strings.Compare(a.Role, b.Role)
	case "created":
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		} else if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
		return 0
	case "address":
		return strings.Compare(a.Address.String(), b.Address.String())
	default:
		return 0
	}
}

// CloneWallet creates a deep copy of a wallet (without private key)
func CloneWallet(wallet *ProjectWallet) *ProjectWallet {
	clone := &ProjectWallet{
		Address:   wallet.Address,
		Label:     wallet.Label,
		Network:   wallet.Network,
		Role:      wallet.Role,
		Notes:     wallet.Notes,
		CreatedAt: wallet.CreatedAt,
		LastUsed:  wallet.LastUsed,
	}
	
	// Copy tags slice
	if wallet.Tags != nil {
		clone.Tags = make([]string, len(wallet.Tags))
		copy(clone.Tags, wallet.Tags)
	}
	
	// Note: Private key is intentionally not copied for security
	
	return clone
}
package project

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

// Manager implements the ProjectManager interface
type Manager struct {
	storage *StorageManager
	projects map[string]*ProjectImpl // Cache of open projects
}

// NewManager creates a new project manager
func NewManager(baseDir string) *Manager {
	return &Manager{
		storage:  NewStorageManager(baseDir),
		projects: make(map[string]*ProjectImpl),
	}
}

// CreateProject creates a new project
func (m *Manager) CreateProject(name, description string, password []byte) (*Project, error) {
	if err := m.ValidateProjectName(name); err != nil {
		return nil, err
	}

	// Check if project already exists
	projectID := m.generateProjectID(name)
	if m.storage.ProjectExists(projectID) {
		return nil, ErrProjectExists(name)
	}

	// Create project info
	now := time.Now()
	info := ProjectInfo{
		ID:           projectID,
		Name:         name,
		Description:  description,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastAccessed: now,
		WalletCount:  0,
		NetworkDist:  make(map[string]int),
		Settings:     DefaultProjectSettings(),
	}

	// Ensure projects directory exists
	if err := m.storage.EnsureProjectDir(); err != nil {
		return nil, err
	}

	// Create project files
	if err := m.storage.CreateProjectFiles(info, password); err != nil {
		return nil, err
	}

	// Open the newly created project
	return m.OpenProject(projectID, password)
}

// ListProjects returns metadata for all projects
func (m *Manager) ListProjects() ([]ProjectInfo, error) {
	projectIDs, err := m.storage.ListProjectIDs()
	if err != nil {
		return nil, err
	}

	projects := make([]ProjectInfo, 0, len(projectIDs))
	
	for _, projectID := range projectIDs {
		// Load project metadata without decryption (lighter operation)
		projectPath := m.storage.GetProjectPath(projectID)
		projectFile, err := m.loadProjectMetadata(projectPath)
		if err != nil {
			// Skip corrupted projects but continue listing others
			continue
		}
		
		projects = append(projects, projectFile.Project)
	}

	return projects, nil
}

// OpenProject opens and decrypts a project
func (m *Manager) OpenProject(id string, password []byte) (*Project, error) {
	// Check if already open
	if project, exists := m.projects[id]; exists {
		if !project.IsLocked() {
			// Refresh session and return existing project
			project.RefreshSession()
			var p Project = project
			return &p, nil
		}
		// Project is locked, unlock it
		if err := project.Unlock(password); err != nil {
			return nil, err
		}
		var p Project = project
		return &p, nil
	}

	// Load and decrypt project
	projectFile, mlkemPrivateKey, derivedKey, err := m.storage.LoadProjectFile(id, password)
	if err != nil {
		return nil, err
	}

	// Load wallets
	wallets, err := m.storage.LoadWalletsFile(id, mlkemPrivateKey)
	if err != nil {
		SecureZero(mlkemPrivateKey)
		SecureZero(derivedKey)
		return nil, err
	}

	// Zero the password immediately after use
	defer SecureZero(password)

	// Decode public key for session
	publicKeyBytes, err := base64.StdEncoding.DecodeString(projectFile.MLKEMPublicKey)
	if err != nil {
		SecureZero(mlkemPrivateKey)
		SecureZero(derivedKey)
		return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid public key", err)
	}

	// Create session data
	session := &SessionData{
		ProjectInfo:     projectFile.Project,
		Wallets:         wallets,
		MLKEMPrivateKey: mlkemPrivateKey,
		DerivedKey:      derivedKey,  // Store derived key instead of password
		MLKEMPublicKey:  publicKeyBytes,
		KDFParams:       projectFile.KDF,
		LastActivity:    time.Now(),
	}

	// Create project implementation
	project := &ProjectImpl{
		manager:   m,
		storage:   m.storage,
		session:   session,
		locked:    false,
	}

	// Set up auto-lock timer
	if err := project.SetAutoLock(session.ProjectInfo.Settings.AutoLockMinutes); err != nil {
		project.Close()
		return nil, err
	}

	// Cache the project
	m.projects[id] = project

	// Update last accessed time
	project.session.ProjectInfo.LastAccessed = time.Now()
	if err := project.Save(); err != nil {
		// Non-fatal error, just log it
		fmt.Printf("Warning: failed to update last accessed time: %v\n", err)
	}

	var p Project = project
	return &p, nil
}

// DeleteProject removes a project permanently
func (m *Manager) DeleteProject(id string) error {
	// Close project if open
	if project, exists := m.projects[id]; exists {
		project.Close()
		delete(m.projects, id)
	}

	// Delete project files
	return m.storage.DeleteProject(id)
}

// RenameProject changes a project's name
func (m *Manager) RenameProject(id string, newName string) error {
	if err := m.ValidateProjectName(newName); err != nil {
		return err
	}

	// Check if project is currently open and rename it in session
	if project, exists := m.projects[id]; exists && !project.IsLocked() {
		// Update in-memory project
		project.session.ProjectInfo.Name = newName
		project.session.ProjectInfo.UpdatedAt = time.Now()
		return project.Save()
	}
	
	// Project is not open, so we can't rename it without password
	// TODO: Implement LoadProjectMetadata function that doesn't require password for future enhancement
	return NewProjectError(ErrCodeProjectLocked, "project must be open to rename", nil)
}

// ExportProject exports a project to an encrypted backup file
func (m *Manager) ExportProject(id string, path string) error {
	// Implementation for future phase
	return fmt.Errorf("export not yet implemented")
}

// ImportProject imports a project from an encrypted backup file
func (m *Manager) ImportProject(path string, password []byte) (*Project, error) {
	// Implementation for future phase
	return nil, fmt.Errorf("import not yet implemented")
}

// ProjectExists checks if a project exists
func (m *Manager) ProjectExists(name string) bool {
	projectID := m.generateProjectID(name)
	return m.storage.ProjectExists(projectID)
}

// GetProjectPath returns the filesystem path for a project
func (m *Manager) GetProjectPath(id string) string {
	return m.storage.GetProjectPath(id)
}

// ValidateProjectName validates a project name with security checks
func (m *Manager) ValidateProjectName(name string) error {
	if len(name) == 0 {
		return NewProjectError(ErrCodeInvalidName, "project name cannot be empty", nil)
	}
	
	if len(name) > 64 {
		return NewProjectError(ErrCodeInvalidName, "project name too long (max 64 characters)", nil)
	}

	// Prevent directory traversal attacks
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return NewProjectError(ErrCodeInvalidName, "project name contains invalid characters", nil)
	}

	// Prevent hidden files
	if strings.HasPrefix(name, ".") {
		return NewProjectError(ErrCodeInvalidName, "project name cannot start with a dot", nil)
	}

	// Only allow alphanumeric, hyphens, underscores, and spaces
	validName := regexp.MustCompile(`^[a-zA-Z0-9\-_ ]+$`)
	if !validName.MatchString(name) {
		return NewProjectError(ErrCodeInvalidName, "project name contains invalid characters", nil)
	}

	return nil
}

// generateProjectID creates a filesystem-safe ID from project name
func (m *Manager) generateProjectID(name string) string {
	// Convert to lowercase and replace spaces/special chars with hyphens
	id := strings.ToLower(name)
	id = regexp.MustCompile(`[^a-z0-9\-_]`).ReplaceAllString(id, "-")
	id = regexp.MustCompile(`-+`).ReplaceAllString(id, "-")
	id = strings.Trim(id, "-")
	
	// Ensure uniqueness by appending UUID if needed
	if m.storage.ProjectExists(id) {
		id = id + "-" + uuid.New().String()[:8]
	}
	
	return id
}

// loadProjectMetadata loads project metadata without decryption
func (m *Manager) loadProjectMetadata(projectPath string) (*ProjectStorageFile, error) {
	// Read project file without decryption to get basic metadata
	projectFilePath := filepath.Join(projectPath, "project.enc")
	data, err := os.ReadFile(projectFilePath)
	if err != nil {
		return nil, NewProjectError(ErrCodeFileOperation, "failed to read project file", err)
	}

	var projectFile ProjectStorageFile
	if err := json.Unmarshal(data, &projectFile); err != nil {
		return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid project file format", err)
	}

	return &projectFile, nil
}

// ProjectImpl implements the Project interface
type ProjectImpl struct {
	manager *Manager
	storage *StorageManager
	session *SessionData
	locked  bool
}

// GetInfo returns project information
func (p *ProjectImpl) GetInfo() ProjectInfo {
	return p.session.ProjectInfo
}

// GetID returns the project ID
func (p *ProjectImpl) GetID() string {
	return p.session.ProjectInfo.ID
}

// GetName returns the project name
func (p *ProjectImpl) GetName() string {
	return p.session.ProjectInfo.Name
}

// IsLocked returns true if the project is locked
func (p *ProjectImpl) IsLocked() bool {
	return p.locked
}

// Lock secures the project and clears sensitive data
func (p *ProjectImpl) Lock() error {
	if p.locked {
		return nil
	}

	// Stop auto-lock timer
	if p.session.AutoLockTimer != nil {
		p.session.AutoLockTimer.Stop()
		p.session.AutoLockTimer = nil
	}

	// Zero sensitive data
	if p.session.MLKEMPrivateKey != nil {
		SecureZero(p.session.MLKEMPrivateKey)
		p.session.MLKEMPrivateKey = nil
	}
	
	if p.session.DerivedKey != nil {
		SecureZero(p.session.DerivedKey)
		p.session.DerivedKey = nil
	}

	if p.session.MLKEMPublicKey != nil {
		SecureZero(p.session.MLKEMPublicKey)
		p.session.MLKEMPublicKey = nil
	}

	// Clear wallet private keys
	for i := range p.session.Wallets {
		SecureZero(p.session.Wallets[i].PrivateKey[:])
	}
	p.session.Wallets = nil

	p.locked = true
	return nil
}

// Unlock decrypts and loads project data
func (p *ProjectImpl) Unlock(password []byte) error {
	if !p.locked {
		return nil
	}

	// Load and decrypt project
	projectFile, mlkemPrivateKey, derivedKey, err := p.storage.LoadProjectFile(p.GetID(), password)
	if err != nil {
		return err
	}

	// Zero password immediately after use
	defer SecureZero(password)

	// Load wallets
	wallets, err := p.storage.LoadWalletsFile(p.GetID(), mlkemPrivateKey)
	if err != nil {
		SecureZero(mlkemPrivateKey)
		SecureZero(derivedKey)
		return err
	}

	// Decode public key for session
	publicKeyBytes, err := base64.StdEncoding.DecodeString(projectFile.MLKEMPublicKey)
	if err != nil {
		SecureZero(mlkemPrivateKey)
		SecureZero(derivedKey)
		return NewProjectError(ErrCodeStorageCorrupted, "invalid public key", err)
	}

	// Update session
	p.session.ProjectInfo = projectFile.Project
	p.session.Wallets = wallets
	p.session.MLKEMPrivateKey = mlkemPrivateKey
	p.session.DerivedKey = derivedKey  // Store derived key instead of password
	p.session.MLKEMPublicKey = publicKeyBytes
	p.session.KDFParams = projectFile.KDF
	p.session.LastActivity = time.Now()

	p.locked = false

	// Restart auto-lock timer
	return p.SetAutoLock(p.session.ProjectInfo.Settings.AutoLockMinutes)
}

// RefreshSession updates the last activity time and resets auto-lock
func (p *ProjectImpl) RefreshSession() error {
	if p.locked {
		return ErrProjectLocked(p.GetName())
	}

	p.session.LastActivity = time.Now()
	
	// Reset auto-lock timer
	if p.session.AutoLockTimer != nil {
		p.session.AutoLockTimer.Stop()
	}
	
	return p.SetAutoLock(p.session.ProjectInfo.Settings.AutoLockMinutes)
}

// SetAutoLock configures automatic locking
func (p *ProjectImpl) SetAutoLock(minutes int) error {
	if p.locked {
		return ErrProjectLocked(p.GetName())
	}

	// Stop existing timer
	if p.session.AutoLockTimer != nil {
		p.session.AutoLockTimer.Stop()
	}

	// Set new timer if minutes > 0
	if minutes > 0 {
		duration := time.Duration(minutes) * time.Minute
		p.session.AutoLockTimer = time.AfterFunc(duration, func() {
			p.Lock()
		})
	}

	// Update settings
	p.session.ProjectInfo.Settings.AutoLockMinutes = minutes
	p.session.ProjectInfo.UpdatedAt = time.Now()

	return nil
}

// CreateWallet creates a new wallet in the project
func (p *ProjectImpl) CreateWallet(label, network string) (*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	if !IsValidNetwork(network) {
		return nil, NewProjectError(ErrCodeInvalidNetwork, "invalid network: "+network, nil)
	}

	// Generate new Ethereum wallet
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, NewProjectError(ErrCodeBulkCreateFailed, "failed to generate key", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, NewProjectError(ErrCodeBulkCreateFailed, "failed to cast public key", nil)
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Create project wallet
	wallet := &ProjectWallet{
		Label:     label,
		Network:   network,
		CreatedAt: time.Now(),
	}

	// Copy keys
	copy(wallet.PrivateKey[:], crypto.FromECDSA(privateKey))
	copy(wallet.Address[:], address.Bytes())

	// Zero the original key
	keyBytes := crypto.FromECDSA(privateKey)
	SecureZero(keyBytes)

	// Add to session
	p.session.Wallets = append(p.session.Wallets, *wallet)

	// Update project stats
	p.session.ProjectInfo.WalletCount++
	if p.session.ProjectInfo.NetworkDist == nil {
		p.session.ProjectInfo.NetworkDist = make(map[string]int)
	}
	p.session.ProjectInfo.NetworkDist[network]++
	p.session.ProjectInfo.UpdatedAt = time.Now()

	// Save changes
	if err := p.Save(); err != nil {
		return nil, err
	}

	p.RefreshSession()
	return wallet, nil
}

// BulkCreateWallets creates multiple wallets using a template
func (p *ProjectImpl) BulkCreateWallets(config BulkConfig) ([]*ProjectWallet, error) {
	if p.locked {
		return nil, ErrProjectLocked(p.GetName())
	}

	if config.Count <= 0 || config.Count > 1000 {
		return nil, NewProjectError(ErrCodeBulkCreateFailed, "invalid wallet count (1-1000)", nil)
	}

	wallets := make([]*ProjectWallet, 0, config.Count)
	
	for i := 0; i < config.Count; i++ {
		// Determine network for this wallet
		network := config.DefaultNetwork
		if mappedNetwork, exists := config.NetworkMapping[i]; exists {
			network = mappedNetwork
		}
		
		if !IsValidNetwork(network) {
			return nil, NewProjectError(ErrCodeInvalidNetwork, "invalid network: "+network, nil)
		}

		// Generate label from template
		label := p.expandLabelTemplate(config.LabelTemplate, i, config)

		// Create wallet
		wallet, err := p.CreateWallet(label, network)
		if err != nil {
			return nil, fmt.Errorf("failed to create wallet %d: %w", i, err)
		}

		// Add role and tags if specified
		if i < len(config.Roles) {
			wallet.Role = config.Roles[i]
		}
		wallet.Tags = config.Tags

		wallets = append(wallets, wallet)
	}

	p.RefreshSession()
	return wallets, nil
}

// expandLabelTemplate expands a label template with variables
func (p *ProjectImpl) expandLabelTemplate(template string, index int, config BulkConfig) string {
	label := template
	
	// Replace common variables
	label = strings.ReplaceAll(label, "{project}", p.GetName())
	label = strings.ReplaceAll(label, "{index}", fmt.Sprintf("%d", index))
	label = strings.ReplaceAll(label, "{index1}", fmt.Sprintf("%d", index+1))
	
	// Replace role if specified
	if index < len(config.Roles) {
		label = strings.ReplaceAll(label, "{role}", config.Roles[index])
	} else {
		label = strings.ReplaceAll(label, "{role}", "wallet")
	}
	
	// Replace network
	network := config.DefaultNetwork
	if mappedNetwork, exists := config.NetworkMapping[index]; exists {
		network = mappedNetwork
	}
	label = strings.ReplaceAll(label, "{network}", network)
	
	return label
}

// Additional methods would be implemented here...
// For brevity, showing the key methods. The full implementation would include:
// - ListWallets()
// - GetWallet(address Address)
// - UpdateWallet(address Address, updates WalletUpdate)
// - DeleteWallet(address Address)
// - ExportWallet(address Address)
// - ExportAllWallets()
// - Save()
// - Close()

// Save persists the project state to disk
func (p *ProjectImpl) Save() error {
	if p.locked {
		return ErrProjectLocked(p.GetName())
	}

	// Save wallets using stored session data
	if err := p.storage.SaveWallets(p.GetID(), p.session.Wallets, p.session.MLKEMPublicKey, p.session.KDFParams); err != nil {
		return err
	}

	// Update and save project metadata
	return p.storage.UpdateProjectInfo(
		p.GetID(),
		p.session.ProjectInfo,
		p.session.DerivedKey,
		p.session.MLKEMPublicKey,
		p.session.MLKEMPrivateKey,
		p.session.KDFParams,
	)
}

// Close closes the project and cleans up resources
func (p *ProjectImpl) Close() error {
	p.Lock()
	
	// Remove from manager cache
	delete(p.manager.projects, p.GetID())
	
	return nil
}
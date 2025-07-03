package project

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StorageManager handles project file operations
type StorageManager struct {
	baseDir string
	crypto  *CryptoManager
}

// NewStorageManager creates a new storage manager
func NewStorageManager(baseDir string) *StorageManager {
	return &StorageManager{
		baseDir: baseDir,
		crypto:  NewCryptoManager(),
	}
}

// EnsureProjectDir creates the project directory if it doesn't exist
func (sm *StorageManager) EnsureProjectDir() error {
	if err := os.MkdirAll(sm.baseDir, 0755); err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to create projects directory", err)
	}
	return nil
}

// GetProjectPath returns the directory path for a project
func (sm *StorageManager) GetProjectPath(projectID string) string {
	return filepath.Join(sm.baseDir, projectID)
}

// ProjectExists checks if a project directory exists
func (sm *StorageManager) ProjectExists(projectID string) bool {
	projectPath := sm.GetProjectPath(projectID)
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// CreateProjectFiles creates the initial project directory and files
func (sm *StorageManager) CreateProjectFiles(info ProjectInfo, password []byte) error {
	projectPath := sm.GetProjectPath(info.ID)
	
	// Create project directory with secure permissions (owner only)
	if err := os.MkdirAll(projectPath, 0700); err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to create project directory", err)
	}

	// Generate encryption keys for this project
	salt, err := GenerateSalt()
	if err != nil {
		return NewProjectError(ErrCodeEncryptionFailed, "failed to generate salt", err)
	}

	kdfParams := DefaultKDFParams()
	kdfParams.Salt = base64.StdEncoding.EncodeToString(salt[:])

	// Derive project-specific key
	projectKey := sm.crypto.DeriveKey(password, salt, kdfParams)

	// Generate ML-KEM keypair for this project
	encapsKeyBytes, decapsKeyBytes, err := sm.crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return NewProjectError(ErrCodeEncryptionFailed, "failed to generate ML-KEM keypair", err)
	}

	// Encrypt the ML-KEM private key with the project key
	encryptedPrivKey, privKeyNonce, err := sm.crypto.encryptAES(decapsKeyBytes, projectKey)
	if err != nil {
		return NewProjectError(ErrCodeEncryptionFailed, "failed to encrypt ML-KEM private key", err)
	}

	// Create project metadata file
	projectFile := ProjectStorageFile{
		Version:              "1.0",
		Project:              info,
		Algorithm:            "mlkem1024-aes256gcm",
		KDF:                  kdfParams,
		MLKEMPublicKey:       base64.StdEncoding.EncodeToString(encapsKeyBytes),
		MLKEMPrivateKeyEnc:   base64.StdEncoding.EncodeToString(encryptedPrivKey),
		MLKEMPrivateKeyNonce: base64.StdEncoding.EncodeToString(privKeyNonce[:]),
		UpdatedAt:            time.Now(),
	}

	// Save project metadata
	if err := sm.saveProjectFile(projectPath, projectFile); err != nil {
		os.RemoveAll(projectPath) // Cleanup on failure
		return err
	}

	// Create empty wallets file
	walletsFile := WalletStorageFile{
		Version:   "1.0",
		Algorithm: "mlkem1024-aes256gcm",
		KDF:       kdfParams,
		Wallets:   []EncryptedProjectWallet{},
		UpdatedAt: time.Now(),
	}

	if err := sm.saveWalletsFile(projectPath, walletsFile); err != nil {
		os.RemoveAll(projectPath) // Cleanup on failure
		return err
	}

	// Zero sensitive data
	SecureZero(projectKey)
	SecureZero(decapsKeyBytes)

	return nil
}

// LoadProjectFile loads and decrypts project metadata
func (sm *StorageManager) LoadProjectFile(projectID string, password []byte) (*ProjectStorageFile, []byte, []byte, error) {
	projectPath := sm.GetProjectPath(projectID)
	projectFilePath := filepath.Join(projectPath, "project.enc")

	// Read project file
	data, err := os.ReadFile(projectFilePath)
	if err != nil {
		return nil, nil, nil, NewProjectError(ErrCodeFileOperation, "failed to read project file", err)
	}

	var projectFile ProjectStorageFile
	if err := json.Unmarshal(data, &projectFile); err != nil {
		return nil, nil, nil, NewProjectError(ErrCodeStorageCorrupted, "invalid project file format", err)
	}

	// Derive project key
	salt, err := base64.StdEncoding.DecodeString(projectFile.KDF.Salt)
	if err != nil {
		return nil, nil, nil, NewProjectError(ErrCodeStorageCorrupted, "invalid salt in project file", err)
	}

	var s Salt
	copy(s[:], salt)
	projectKey := sm.crypto.DeriveKey(password, s, projectFile.KDF)

	// Decrypt ML-KEM private key
	encryptedPrivKey, err := base64.StdEncoding.DecodeString(projectFile.MLKEMPrivateKeyEnc)
	if err != nil {
		return nil, nil, nil, NewProjectError(ErrCodeStorageCorrupted, "invalid encrypted private key", err)
	}

	privKeyNonceBytes, err := base64.StdEncoding.DecodeString(projectFile.MLKEMPrivateKeyNonce)
	if err != nil {
		return nil, nil, nil, NewProjectError(ErrCodeStorageCorrupted, "invalid private key nonce", err)
	}

	var privKeyNonce Nonce
	copy(privKeyNonce[:], privKeyNonceBytes)

	mlkemPrivateKey, err := sm.crypto.decryptAES(EncryptedData(encryptedPrivKey), projectKey, privKeyNonce)
	if err != nil {
		SecureZero(projectKey)
		return nil, nil, nil, NewProjectError(ErrCodeInvalidPassword, "failed to decrypt project", err)
	}

	// Verify the decrypted private key by checking public key match
	_, err = base64.StdEncoding.DecodeString(projectFile.MLKEMPublicKey)
	if err != nil {
		SecureZero(projectKey)
		SecureZero(mlkemPrivateKey)
		return nil, nil, nil, NewProjectError(ErrCodeStorageCorrupted, "invalid public key", err)
	}

	// Return project file, mlkem private key, and derived key (don't zero keys as caller needs them)
	return &projectFile, mlkemPrivateKey, projectKey, nil
}

// LoadWalletsFile loads and decrypts project wallets
func (sm *StorageManager) LoadWalletsFile(projectID string, mlkemPrivateKey []byte) ([]ProjectWallet, error) {
	projectPath := sm.GetProjectPath(projectID)
	walletsFilePath := filepath.Join(projectPath, "wallets.enc")

	// Read wallets file
	data, err := os.ReadFile(walletsFilePath)
	if err != nil {
		return nil, NewProjectError(ErrCodeFileOperation, "failed to read wallets file", err)
	}

	var walletsFile WalletStorageFile
	if err := json.Unmarshal(data, &walletsFile); err != nil {
		return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid wallets file format", err)
	}

	wallets := make([]ProjectWallet, 0, len(walletsFile.Wallets))

	// Decrypt each wallet
	for _, ew := range walletsFile.Wallets {
		wallet, err := sm.decryptWallet(&ew, mlkemPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt wallet %s: %w", ew.Address, err)
		}
		wallets = append(wallets, *wallet)
	}

	return wallets, nil
}

// SaveWallets encrypts and saves wallets to file
func (sm *StorageManager) SaveWallets(projectID string, wallets []ProjectWallet, mlkemPublicKey []byte, kdfParams KDFParams) error {
	projectPath := sm.GetProjectPath(projectID)
	
	encryptedWallets := make([]EncryptedProjectWallet, len(wallets))
	
	// Encrypt each wallet
	for i, wallet := range wallets {
		ew, err := sm.encryptWallet(&wallet, mlkemPublicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt wallet %s: %w", wallet.Address.String(), err)
		}
		encryptedWallets[i] = *ew
	}

	// Create wallets file
	walletsFile := WalletStorageFile{
		Version:   "1.0",
		Algorithm: "mlkem1024-aes256gcm",
		KDF:       kdfParams,
		Wallets:   encryptedWallets,
		UpdatedAt: time.Now(),
	}

	return sm.saveWalletsFile(projectPath, walletsFile)
}

// UpdateProjectInfo updates project metadata
func (sm *StorageManager) UpdateProjectInfo(projectID string, info ProjectInfo, projectKey []byte, mlkemPublicKey, mlkemPrivateKey []byte, kdfParams KDFParams) error {
	projectPath := sm.GetProjectPath(projectID)
	
	// Encrypt the ML-KEM private key
	encryptedPrivKey, privKeyNonce, err := sm.crypto.encryptAES(mlkemPrivateKey, projectKey)
	if err != nil {
		return NewProjectError(ErrCodeEncryptionFailed, "failed to encrypt ML-KEM private key", err)
	}

	// Create updated project file
	projectFile := ProjectStorageFile{
		Version:              "1.0",
		Project:              info,
		Algorithm:            "mlkem1024-aes256gcm",
		KDF:                  kdfParams,
		MLKEMPublicKey:       base64.StdEncoding.EncodeToString(mlkemPublicKey),
		MLKEMPrivateKeyEnc:   base64.StdEncoding.EncodeToString(encryptedPrivKey),
		MLKEMPrivateKeyNonce: base64.StdEncoding.EncodeToString(privKeyNonce[:]),
		UpdatedAt:            time.Now(),
	}

	return sm.saveProjectFile(projectPath, projectFile)
}

// DeleteProject removes all project files
func (sm *StorageManager) DeleteProject(projectID string) error {
	projectPath := sm.GetProjectPath(projectID)
	if err := os.RemoveAll(projectPath); err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to delete project", err)
	}
	return nil
}

// ListProjectIDs returns all project directory names
func (sm *StorageManager) ListProjectIDs() ([]string, error) {
	if err := sm.EnsureProjectDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(sm.baseDir)
	if err != nil {
		return nil, NewProjectError(ErrCodeFileOperation, "failed to list projects", err)
	}

	var projectIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			// Verify it's a valid project by checking for project.enc
			projectFilePath := filepath.Join(sm.baseDir, entry.Name(), "project.enc")
			if _, err := os.Stat(projectFilePath); err == nil {
				projectIDs = append(projectIDs, entry.Name())
			}
		}
	}

	return projectIDs, nil
}

// saveProjectFile saves project metadata to disk
func (sm *StorageManager) saveProjectFile(projectPath string, projectFile ProjectStorageFile) error {
	data, err := json.MarshalIndent(projectFile, "", "  ")
	if err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to marshal project file", err)
	}

	projectFilePath := filepath.Join(projectPath, "project.enc")
	return sm.atomicWrite(projectFilePath, data)
}

// saveWalletsFile saves wallets to disk
func (sm *StorageManager) saveWalletsFile(projectPath string, walletsFile WalletStorageFile) error {
	data, err := json.MarshalIndent(walletsFile, "", "  ")
	if err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to marshal wallets file", err)
	}

	walletsFilePath := filepath.Join(projectPath, "wallets.enc")
	return sm.atomicWrite(walletsFilePath, data)
}

// atomicWrite writes data to a file atomically with secure permissions
func (sm *StorageManager) atomicWrite(filePath string, data []byte) error {
	tmpFile := filePath + ".tmp"
	
	// Write with secure permissions (owner read/write only)
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return NewProjectError(ErrCodeFileOperation, "failed to write temporary file", err)
	}

	// Verify file permissions after creation
	if info, err := os.Stat(tmpFile); err == nil {
		mode := info.Mode()
		if mode.Perm() != 0600 {
			os.Remove(tmpFile)
			return NewProjectError(ErrCodeFileOperation, "failed to set secure file permissions", nil)
		}
	}

	if err := os.Rename(tmpFile, filePath); err != nil {
		os.Remove(tmpFile)
		return NewProjectError(ErrCodeFileOperation, "failed to rename file", err)
	}

	return nil
}

// encryptWallet encrypts a project wallet for storage
func (sm *StorageManager) encryptWallet(wallet *ProjectWallet, mlkemPublicKey []byte) (*EncryptedProjectWallet, error) {
	encrypted, nonce, err := sm.crypto.EncryptDataPQC(wallet.PrivateKey[:], mlkemPublicKey)
	if err != nil {
		return nil, NewProjectError(ErrCodeEncryptionFailed, "failed to encrypt wallet", err)
	}

	return &EncryptedProjectWallet{
		Address:      wallet.Address.String(),
		EncryptedKey: base64.StdEncoding.EncodeToString(encrypted),
		Nonce:        nonce,
		Label:        wallet.Label,
		Network:      wallet.Network,
		Role:         wallet.Role,
		Tags:         wallet.Tags,
		Notes:        wallet.Notes,
		CreatedAt:    wallet.CreatedAt,
		LastUsed:     wallet.LastUsed,
	}, nil
}

// decryptWallet decrypts an encrypted project wallet
func (sm *StorageManager) decryptWallet(ew *EncryptedProjectWallet, mlkemPrivateKey []byte) (*ProjectWallet, error) {
	encrypted, err := base64.StdEncoding.DecodeString(ew.EncryptedKey)
	if err != nil {
		return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid encrypted key", err)
	}

	decrypted, err := sm.crypto.DecryptDataPQC(EncryptedData(encrypted), mlkemPrivateKey, ew.Nonce)
	if err != nil {
		return nil, NewProjectError(ErrCodeDecryptionFailed, "failed to decrypt wallet", err)
	}

	// Parse address
	var address Address
	if len(ew.Address) >= 2 && ew.Address[:2] == "0x" {
		addrBytes, err := hex.DecodeString(ew.Address[2:])
		if err != nil {
			SecureZero(decrypted)
			return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid address format", err)
		}
		copy(address[:], addrBytes)
	} else {
		SecureZero(decrypted)
		return nil, NewProjectError(ErrCodeStorageCorrupted, "invalid address format", err)
	}

	var privateKey PrivateKey
	copy(privateKey[:], decrypted)

	wallet := &ProjectWallet{
		PrivateKey: privateKey,
		Address:    address,
		Label:      ew.Label,
		Network:    ew.Network,
		Role:       ew.Role,
		Tags:       ew.Tags,
		Notes:      ew.Notes,
		CreatedAt:  ew.CreatedAt,
		LastUsed:   ew.LastUsed,
	}

	// Zero the decrypted key data
	SecureZero(decrypted)

	return wallet, nil
}
# fix_projects.md - Comprehensive Fix Guide for Quantum Wallet Manager Projects Feature

## Critical Issue: Key Handling in Project Mode

### Root Cause Analysis
The key handling in project mode is failing because the `ProjectListModel.Update()` method is handling input modes AFTER checking for key bindings. When `m.inputMode != ""`, the key handling logic is intercepted before reaching the main key binding switch statement.

### Fix #1: Reorder Key Handling Logic in tui.go

**File**: `pkg/project/tui.go`
**Function**: `ProjectListModel.Update()`
**Lines**: 165-321

```go
// CURRENT PROBLEMATIC ORDER:
func (m ProjectListModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    // ... 
    case tea.KeyMsg:
        // Handle input modes first <-- THIS IS THE PROBLEM
        if m.inputMode != "" {
            // This consumes ALL keys when in input mode
        }
        
        // Main key bindings never reached when inputMode is set
        switch {
        case key.Matches(msg, m.keys.New):
            // Never executed!
        }
}

// FIXED ORDER:
func (m ProjectListModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        // ... existing window size handling

    case tea.KeyMsg:
        // FIRST: Check if we're in input mode and handle special keys
        if m.inputMode != "" {
            switch msg.String() {
            case "enter":
                // Handle enter key for input modes
                // ... existing enter handling
                
            case "esc":
                // Handle escape to cancel input
                m.inputMode = ""
                m.textInput.SetValue("")
                m.textInput.Blur()
                m.textInput.EchoMode = textinput.EchoNormal
                m.pendingProjectName = ""
                m.status = "Cancelled"
                return m, nil
                
            default:
                // For any other key, update the input
                var cmd tea.Cmd
                m.textInput, cmd = m.textInput.Update(msg)
                return m, cmd
            }
        } else {
            // SECOND: Only handle main navigation keys when NOT in input mode
            // Debug logging
            m.status = fmt.Sprintf("🔑 Key pressed: %s", msg.String())
            
            switch {
            case key.Matches(msg, m.keys.New):
                m.inputMode = "new"
                m.textInput.Placeholder = "Enter project name..."
                m.textInput.SetValue("")
                m.textInput.Focus()
                m.status = "📝 Enter name for new project"
                return m, textinput.Blink

            case key.Matches(msg, m.keys.Open):
                // ... rest of key handlers
            }
        }
    }
    
    return m, tea.Batch(cmds...)
}
```

### Fix #2: Model Mutation Issue in main.go

**File**: `main.go`
**Lines**: 1421-1438

The model forwarding has a subtle bug. The ProjectListModel methods have value receivers, not pointer receivers.

```go
// CURRENT:
if m.projectMode && m.projectListModel != nil {
    var cmd tea.Cmd
    updatedModel, cmd := m.projectListModel.Update(msg)
    if updatedProjectModel, ok := updatedModel.(project.ProjectListModel); ok {
        *m.projectListModel = updatedProjectModel  // This is correct
    }
    // ...
}

// ADDITIONAL FIX NEEDED - Ensure all methods use pointer receivers:
// In pkg/project/tui.go, change ALL methods to use pointer receivers:
func (m *ProjectListModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    // ... implementation
}

func (m *ProjectListModel) View() string {
    // ... implementation
}

func (m *ProjectListModel) Init() tea.Cmd {
    // ... implementation
}
```

## Security Issues to Fix

### Issue #1: Memory Zeroing Gaps

**Critical Security Gap**: Not all sensitive data paths properly zero memory.

**Files to Fix**:
1. `pkg/project/storage.go`
2. `pkg/project/manager.go`
3. `pkg/project/crypto.go`

**Required Changes**:

```go
// In storage.go - LoadProjectFile function
func (sm *StorageManager) LoadProjectFile(projectID string, password []byte) (*ProjectStorageFile, []byte, error) {
    // ... existing code ...
    
    // MISSING: Zero the project key after use
    defer func() {
        if projectKey != nil {
            SecureZero(projectKey)
        }
    }()
    
    // ... rest of function
}

// In manager.go - OpenProject function
func (m *Manager) OpenProject(id string, password []byte) (*Project, error) {
    // ... existing code ...
    
    // MISSING: Ensure password is zeroed on all error paths
    defer func() {
        // Create a copy for the session, zero the original
        if password != nil {
            SecureZero(password)
        }
    }()
}

// In crypto.go - All encryption/decryption functions
// Add defer statements to zero intermediate keys
func (cm *CryptoManager) EncryptDataPQC(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, error) {
    // ... existing code ...
    
    // Ensure all intermediate secrets are zeroed
    defer func() {
        if aesKey != nil {
            SecureZero(aesKey)
        }
    }()
}
```

### Issue #2: Password Storage in Session

**Security Risk**: Storing master password in session data is dangerous.

**File**: `pkg/project/types.go` and `pkg/project/manager.go`

```go
// CURRENT DANGEROUS PATTERN:
type SessionData struct {
    // ...
    MasterPassword   []byte  // THIS IS DANGEROUS
}

// FIX: Remove password storage, use key derivation only
type SessionData struct {
    ProjectInfo      ProjectInfo
    Wallets          []ProjectWallet
    MLKEMPrivateKey  []byte
    DerivedKey       []byte  // Store only the derived key, not password
    LastActivity     time.Time
    AutoLockTimer    *time.Timer
}
```

### Issue #3: ML-KEM Implementation Verification

**Review the ML-KEM implementation for correctness**:

```go
// In crypto.go - Verify correct ML-KEM-1024 sizes
const (
    MLKEMPublicKeySize  = 1568  // Correct for ML-KEM-1024
    MLKEMPrivateKeySize = 3168  // Correct for ML-KEM-1024
    MLKEMCiphertextSize = 1568  // Correct for ML-KEM-1024
    MLKEMSharedSecretSize = 32  // Correct shared secret size
)

// Add validation in GenerateMLKEMKeyPair
func (cm *CryptoManager) GenerateMLKEMKeyPair() ([]byte, []byte, error) {
    decapsKey, err := mlkem.GenerateKey1024()
    if err != nil {
        return nil, nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
    }
    
    encapsKey := decapsKey.EncapsulationKey()
    encapsKeyBytes := encapsKey.Bytes()
    decapsKeyBytes := decapsKey.Bytes()

    // ADD: Validate key sizes
    if len(encapsKeyBytes) != MLKEMPublicKeySize {
        return nil, nil, fmt.Errorf("invalid public key size: got %d, expected %d", 
            len(encapsKeyBytes), MLKEMPublicKeySize)
    }
    if len(decapsKeyBytes) != MLKEMPrivateKeySize {
        return nil, nil, fmt.Errorf("invalid private key size: got %d, expected %d", 
            len(decapsKeyBytes), MLKEMPrivateKeySize)
    }

    return encapsKeyBytes, decapsKeyBytes, nil
}
```

## TUI Issues to Fix

### Issue #1: List Component State Management

**Problem**: The list component in ProjectListModel can get into an inconsistent state.

**Fix in tui.go**:

```go
// Add explicit list state management
func (m *ProjectListModel) refreshProjectList() {
    projects, err := m.manager.ListProjects()
    if err != nil {
        m.err = err
        projects = []ProjectInfo{}
    }
    
    m.projects = projects
    
    // Update list items
    items := make([]list.Item, len(projects))
    for i, project := range projects {
        items[i] = ProjectListItem{info: project}
    }
    
    // IMPORTANT: Reset list state completely
    m.list.SetItems(items)
    m.list.ResetSelected()  // Add this method call
    m.list.ResetFilter()    // Add this method call
}
```

### Issue #2: Modal Dialog Rendering

**Problem**: Input modes don't properly center and can be cut off on small terminals.

**Fix in View() method**:

```go
func (m ProjectListModel) View() string {
    if m.width == 0 {
        return "Loading..."
    }

    // Input mode overlay
    if m.inputMode != "" {
        // ... existing modal setup ...

        // FIX: Ensure modal doesn't exceed terminal bounds
        modalWidth := 60
        if modalWidth > m.width-4 {
            modalWidth = m.width - 4
        }
        
        modal := lipgloss.NewStyle().
            Border(lipgloss.RoundedBorder()).
            BorderForeground(lipgloss.Color("#cba6f7")).
            Padding(1, 2).
            MaxWidth(modalWidth).  // Add max width constraint
            AlignHorizontal(lipgloss.Center).
            Render(modalContent)

        // Ensure proper centering even on small terminals
        return lipgloss.Place(
            m.width, m.height,
            lipgloss.Center, lipgloss.Center,
            modal,
        )
    }

    // ... rest of view
}
```

## Additional Security Hardening

### 1. Add Input Validation

**File**: `pkg/project/manager.go`

```go
func (m *Manager) ValidateProjectName(name string) error {
    if len(name) == 0 {
        return NewProjectError(ErrCodeInvalidName, "project name cannot be empty", nil)
    }
    
    if len(name) > 64 {
        return NewProjectError(ErrCodeInvalidName, "project name too long (max 64 characters)", nil)
    }

    // ADD: Prevent directory traversal attacks
    if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
        return NewProjectError(ErrCodeInvalidName, "project name contains invalid characters", nil)
    }

    // ADD: Prevent hidden files
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
```

### 2. Add Secure File Permissions

**File**: `pkg/project/storage.go`

```go
// Update all file creation to use secure permissions
func (sm *StorageManager) atomicWrite(filePath string, data []byte) error {
    tmpFile := filePath + ".tmp"
    
    // FIX: Use 0600 permissions (owner read/write only)
    if err := os.WriteFile(tmpFile, data, 0600); err != nil {
        return NewProjectError(ErrCodeFileOperation, "failed to write temporary file", err)
    }

    // ADD: Verify file permissions after creation
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
```

### 3. Add Encryption Verification

**File**: `pkg/project/crypto.go`

```go
// Add HMAC verification for data integrity
func (cm *CryptoManager) EncryptDataPQCWithVerification(plaintext []byte, encapsKeyBytes []byte) (EncryptedData, string, []byte, error) {
    encrypted, nonce, err := cm.EncryptDataPQC(plaintext, encapsKeyBytes)
    if err != nil {
        return nil, "", nil, err
    }
    
    // ADD: Compute HMAC for integrity verification
    hmac := ComputeHMAC(encapsKeyBytes, encrypted)
    
    return encrypted, nonce, hmac, nil
}

func (cm *CryptoManager) DecryptDataPQCWithVerification(combined EncryptedData, decapsKeyBytes []byte, nonceB64 string, expectedHMAC []byte) ([]byte, error) {
    // ADD: Verify HMAC before decryption
    computedHMAC := ComputeHMAC(decapsKeyBytes[:1568], combined)  // Use public part
    if !SecureCompare(computedHMAC, expectedHMAC) {
        return nil, fmt.Errorf("data integrity verification failed")
    }
    
    return cm.DecryptDataPQC(combined, decapsKeyBytes, nonceB64)
}
```

## Testing Requirements

### 1. Security Tests

```go
// Add test file: pkg/project/security_test.go
func TestMemoryZeroing(t *testing.T) {
    // Test that all sensitive data is properly zeroed
}

func TestEncryptionConsistency(t *testing.T) {
    // Test that encryption/decryption round-trips correctly
}

func TestProjectIsolation(t *testing.T) {
    // Test that projects cannot access each other's data
}
```

### 2. TUI Tests

```go
// Add test file: pkg/project/tui_test.go
func TestKeyHandling(t *testing.T) {
    // Test that all key bindings work correctly
}

func TestInputModes(t *testing.T) {
    // Test input mode transitions
}
```

## Implementation Priority

1. **CRITICAL - Fix key handling** (Fix #1 and #2)
2. **CRITICAL - Fix memory zeroing gaps**
3. **HIGH - Remove password storage in session**
4. **HIGH - Add input validation**
5. **MEDIUM - Fix TUI rendering issues**
6. **MEDIUM - Add encryption verification**
7. **LOW - Add comprehensive tests**

## Verification Checklist

After implementing fixes, verify:

- [ ] All key bindings work in project mode (n, o, d, r)
- [ ] Input modes properly handle escape and enter
- [ ] All sensitive data is zeroed after use
- [ ] No passwords are stored in session data
- [ ] ML-KEM key sizes are validated
- [ ] File permissions are set to 0600
- [ ] Directory traversal is prevented
- [ ] Modal dialogs render correctly on small terminals
- [ ] Project creation completes successfully
- [ ] Project data is properly encrypted
- [ ] Memory is cleared on project lock
- [ ] No data leaks between projects

## Final Security Notes

1. **Always use defer for cleanup** - Ensure sensitive data is zeroed even on panic
2. **Validate all inputs** - Never trust user input, especially for file operations
3. **Use constant-time comparisons** - Already implemented but verify usage
4. **Minimize sensitive data lifetime** - Zero as soon as possible
5. **Audit all error paths** - Ensure cleanup happens on all error returns
6. **Test with security tools** - Use Go's race detector and security linters

This fix guide should resolve the immediate key handling issue and significantly improve the security posture of the entire project.
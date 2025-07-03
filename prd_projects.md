prd.md
markdown

Copy
# Projects Feature PRD - Quantum Wallet Manager

## 1. Executive Summary

### 1.1 Feature Overview
Add a Project management system to the Quantum Wallet Manager that allows developers to organize wallets into project-specific encrypted containers. Each project acts as a secure folder containing multiple wallets with streamlined bulk creation and management capabilities optimized for development workflows.

### 1.2 Value Proposition
- **Developer Efficiency**: Bulk create and label wallets for new projects
- **Organization**: Keep wallets organized by project/dApp
- **Security**: Project-level encryption with single authentication
- **Workflow Optimization**: Quick access to project wallets without repeated authentication
- **Network Separation**: Built-in mainnet/testnet wallet labeling

## 2. Feature Requirements

### 2.1 Core Functionality

#### 2.1.1 Project Management
- **Create Project**: Initialize new encrypted project container
- **List Projects**: Display all available projects
- **Open Project**: Authenticate and load project wallets
- **Delete Project**: Remove project and all contained wallets
- **Rename Project**: Change project display name
- **Export Project**: Backup entire project as encrypted file
- **Import Project**: Restore project from backup

#### 2.1.2 Project Structure
projects/
my-defi-app/
project.enc # Project metadata and config
wallets.enc # Encrypted wallet storage
nft-marketplace/
project.enc
wallets.enc

sql_more

Copy

#### 2.1.3 Bulk Wallet Creation
- **Batch Size**: Create 1-100 wallets in single operation
- **Label Templates**: Auto-generate labels with patterns
  - `{project}-deployer`
  - `{project}-user-{index}`
  - `{project}-{network}-{index}`
- **Network Assignment**: Mark wallets as mainnet/testnet
- **CSV Import**: Import wallet labels from CSV
- **Preview**: Show wallet addresses before confirmation

#### 2.1.4 Project-Level Security
- **Single Authentication**: One password to unlock entire project
- **Session Management**: Keep project unlocked during session
- **Auto-lock**: Configure timeout for automatic locking
- **Quick Export**: Export private keys without re-authentication
- **Memory Protection**: Clear all project data on lock

### 2.2 User Interface Updates

#### 2.2.1 Main Screen Additions
- Add `[P]rojects` to main navigation
- Show current project name in header
- Display project wallet count

#### 2.2.2 Project List Screen
┌─────────────────────────────────────────────────────┐
│ 📁 Projects (3) [B]ack │
├─────────────────────────────────────────────────────┤
│ [N]ew [O]pen [D]elete [R]ename [E]xport │
├─────────────────────────────────────────────────────┤
│ │
│ ▶ 🏗️ my-defi-app │
│ 12 wallets • Created 2 days ago │
│ Last opened: 1 hour ago │
│ │
│ 🎨 nft-marketplace │
│ 8 wallets • Created 1 week ago │
│ Last opened: 3 days ago │
│ │
│ 🔄 uniswap-integration │
│ 5 wallets • Created 2 weeks ago │
│ Last opened: 5 days ago │
└─────────────────────────────────────────────────────┘


Copy

#### 2.2.3 Bulk Creation Wizard
┌─────────────────────────────────────────────────────┐
│ 🏗️ Bulk Wallet Creation - my-defi-app │
├─────────────────────────────────────────────────────┤
│ │
│ Number of wallets: [5 ] │
│ │
│ Label pattern: [{project}-{role}-{index} ] │
│ │
│ Wallet Configuration: │
│ ┌─────────────────────────────────────────────┐ │
│ │ 1. my-defi-app-deployer [✓] Mainnet │ │
│ │ 2. my-defi-app-treasury [✓] Mainnet │ │
│ │ 3. my-defi-app-test-1 [✓] Testnet │ │
│ │ 4. my-defi-app-test-2 [✓] Testnet │ │
│ │ 5. my-defi-app-test-3 [✓] Testnet │ │
│ └─────────────────────────────────────────────┘ │
│ │
│ [Tab] Next field [Space] Toggle network │
│ [Enter] Create [Esc] Cancel │
└─────────────────────────────────────────────────────┘


Copy

#### 2.2.4 Project Wallet View
┌─────────────────────────────────────────────────────┐
│ 📁 my-defi-app • 12 wallets • Unlocked 🔓 [L]ock│
├─────────────────────────────────────────────────────┤
│ [N]ew [B]ulk [E]xport All [C]opy [D]elete │
├─────────────────────────────────────────────────────┤
│ Mainnet (5) │
│ ├─ 🟢 deployer (0x742d...e8e0) │
│ ├─ 🟢 treasury (0x5aAe...eAed) │
│ ├─ 🟢 rewards-pool (0xfB69...d359) │
│ ├─ 🟢 team-vesting (0x9b5E...4a2C) │
│ └─ 🟢 liquidity (0x3D4C...8f1B) │
│ │
│ Testnet (7) │
│ ├─ 🟡 test-deployer (0x1a2B...3c4D) │
│ ├─ 🟡 test-user-1 (0x5e6F...7a8B) │
│ ├─ 🟡 test-user-2 (0x9c0D...1e2F) │
│ ├─ 🟡 test-user-3 (0x3a4B...5c6D) │
│ ├─ 🟡 faucet (0x7e8F...9a0B) │
│ ├─ 🟡 integration-test (0x1c2D...3e4F) │
│ └─ 🟡 staging (0x5a6B...7c8D) │
└─────────────────────────────────────────────────────┘

json

Copy

### 2.3 Technical Implementation

#### 2.3.1 Project Storage Format
```json
{
  "version": "1.0",
  "project": {
    "id": "uuid-v4",
    "name": "my-defi-app",
    "description": "DeFi application wallets",
    "created_at": "2025-01-15T10:00:00Z",
    "updated_at": "2025-01-15T14:30:00Z",
    "last_accessed": "2025-01-15T14:30:00Z",
    "settings": {
      "auto_lock_minutes": 15,
      "default_network": "mainnet",
      "bulk_creation_template": "{project}-{role}-{index}"
    }
  },
  "encryption": {
    "algorithm": "mlkem1024-aes256gcm",
    "kdf": { /* same as main wallet format */ },
    "mlkem_public_key": "...",
    "mlkem_private_key_enc": "...",
    "mlkem_private_key_nonce": "..."
  },
  "wallet_count": 12,
  "network_distribution": {
    "mainnet": 5,
    "testnet": 7
  }
}
2.3.2 Extended Wallet Structure
go

Copy
type ProjectWallet struct {
    Wallet
    Network     string    `json:"network"` // "mainnet" or "testnet"
    Role        string    `json:"role,omitempty"`
    Tags        []string  `json:"tags,omitempty"`
    Notes       string    `json:"notes,omitempty"`
    LastUsed    time.Time `json:"last_used,omitempty"`
}
2.3.3 New Interfaces
go

Copy
type ProjectManager interface {
    CreateProject(name string, password []byte) (*Project, error)
    ListProjects() ([]ProjectInfo, error)
    OpenProject(id string, password []byte) (*Project, error)
    DeleteProject(id string) error
    RenameProject(id string, newName string) error
    ExportProject(id string, path string) error
    ImportProject(path string, password []byte) (*Project, error)
}

type Project interface {
    GetInfo() ProjectInfo
    CreateWallet(label string, network string) (*ProjectWallet, error)
    BulkCreateWallets(config BulkConfig) ([]*ProjectWallet, error)
    ListWallets() ([]*ProjectWallet, error)
    ExportWallet(address Address) (*ExportedWallet, error)
    ExportAllWallets() ([]*ExportedWallet, error)
    DeleteWallet(address Address) error
    UpdateWallet(address Address, updates WalletUpdate) error
    Lock() error
    IsLocked() bool
}

type BulkConfig struct {
    Count           int
    LabelTemplate   string
    NetworkMapping  map[int]string // wallet index -> network
    Roles          []string
    Tags           []string
}
2.4 Security Considerations
2.4.1 Project Isolation
Each project uses unique encryption keys
No cross-project wallet access
Separate KDF salt per project
Project files are independently encrypted
2.4.2 Session Security
Configurable auto-lock timeout
Manual lock option
Clear memory on lock
Re-authentication required after lock
2.4.3 Export Security
Exported private keys remain in memory briefly
Option to export encrypted bundle
Audit log for all exports
Warning dialogs for bulk exports
2.5 Configuration Options
2.5.1 Global Settings
toml

Copy
[projects]
default_directory = "~/.qwallet/projects"
auto_lock_minutes = 15
max_wallets_per_project = 1000
enable_audit_log = true

[bulk_creation]
default_template = "{project}-{role}-{index}"
default_network_split = 0.3  # 30% mainnet, 70% testnet
max_bulk_size = 100
2.5.2 Project Settings
Auto-lock timeout override
Default network for new wallets
Custom label templates
Export restrictions
3. User Flows
3.1 Create New Project
Press 'p' from main screen
Press 'n' for new project
Enter project name
Enter project password
Project created and opened
3.2 Bulk Create Wallets
Open project
Press 'b' for bulk create
Enter number of wallets
Configure labels and networks
Review and confirm
Wallets created
3.3 Quick Export Flow
Open project (enter password once)
Navigate to wallet
Press 'e' to export
Private key displayed immediately
No additional password required
4. Success Metrics
4.1 Performance
Project open time < 500ms for 1000 wallets
Bulk creation < 100ms per wallet
Export time < 50ms per wallet
4.2 Usability
80% of users successfully create projects
90% prefer bulk creation over individual
95% successful wallet exports
4.3 Security
Zero security incidents
100% proper memory clearing
All exports logged
5. Future Enhancements
5.1 Phase 2
Project templates for common dApp types
Wallet balance monitoring per project
Transaction history by project
Project-level analytics
5.2 Phase 3
Team collaboration (encrypted sharing)
Hardware wallet integration per project
CI/CD integration for deployments
Project archival and compression
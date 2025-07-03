# 🔒 Quantum-Resistant Ethereum Wallet

[![CodeQL](https://github.com/ngmisl/etherml/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ngmisl/etherml/actions/workflows/github-code-scanning/codeql) [![Go](https://github.com/ngmisl/etherml/actions/workflows/go.yml/badge.svg)](https://github.com/ngmisl/etherml/actions/workflows/go.yml)

A **quantum-resistant** Ethereum wallet manager with post-quantum **ML-KEM-1024** encryption and an elegant terminal user interface. Built with Go 1.24.4 and designed for the post-quantum era.

## 🌟 Features

- 🛡️ **Post-Quantum Security**
  - **ML-KEM-1024** (NIST-standardized post-quantum encryption)
  - Hybrid encryption: ML-KEM-1024 + AES-256-GCM  
  - Future-proof against quantum computer attacks
  - No legacy encryption fallbacks - pure post-quantum always

- 🔐 **Deniable Encryption**
  - **Dual-password system** for plausible deniability
  - **"$5 wrench password"** - shows convincing dummy wallets
  - **Real password** - reveals actual wallet data
  - Automatic password type detection
  - Realistic decoy wallets with valid addresses

- 📁 **Project-Based Organization**
  - **Folder-like projects** for wallet organization
  - **Bulk wallet creation** (1-100 wallets at once)
  - **Mainnet/Testnet toggle** with spacebar
  - **Wallet label editing** and network switching
  - **Project-level encryption** with ML-KEM-1024

- 🔐 **Advanced Cryptography**
  - Argon2id key derivation with secure parameters
  - Secure memory handling with automatic key zeroing
  - Password re-authentication for private key access
  - Cryptographically secure random number generation

- 💻 **Elegant Terminal Interface**
  - Beautiful TUI with professional styling and colors
  - Real-time search and filtering
  - Inline wallet label editing
  - One-click address copying to clipboard
  - Modal dialogs for secure operations
  - Responsive design with proper scrolling

- 🚀 **Modern Go Implementation**
  - Built with Go 1.24.4 (uses crypto/mlkem standard library)
  - Type-safe design with comprehensive error handling
  - Cross-platform clipboard support
  - Efficient memory management

## 🚀 Installation

### Prerequisites
- Go 1.24.4 or higher (required for crypto/mlkem)
- Git
- System dependencies (for clipboard support):
  - Linux: `libx11-dev` 
  - macOS: Xcode command line tools
  - Windows: No additional deps needed

### Quick Start
```bash
# Clone the repository
git clone https://github.com/ngmisl/etherml.git
cd etherml

# Build the wallet
go build -o wallet

# Run the wallet
./wallet
```

### System Dependencies (Linux)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libx11-dev

# RHEL/CentOS/Fedora  
sudo dnf install libX11-devel
```

## 🛠️ Usage

### Interactive Terminal Interface
```bash
# Launch the wallet TUI
./wallet
```

When prompted, enter your master password to unlock the encrypted wallet storage.

### TUI Controls

#### Main Wallet View
- **`n`** - Create new wallet with optional label
- **`⏎`** - Edit wallet label (hover and press Enter)
- **`c`** - Copy selected wallet address to clipboard  
- **`e`** - Export private key (requires password re-authentication)
- **`d`** - Delete wallet (with confirmation)
- **`/`** - Search wallets by label or address
- **`p`** - Switch to project mode
- **`↑/↓`** - Navigate wallet list
- **`q`** - Quit application

#### Project Mode
- **`n`** - Create new project
- **`⏎`** - Open selected project
- **`d`** - Delete project (with confirmation)
- **`b`** - Back to main wallet view
- **`↑/↓`** - Navigate project list

#### Inside Projects
- **`n`** - Create single wallet
- **`B`** - Bulk create wallets (1-100 with network toggle)
- **`e`** - Edit wallet label
- **`space`** - Toggle wallet network (mainnet/testnet)
- **`c`** - Copy wallet address
- **`x`** - Export private key
- **`d`** - Delete wallet
- **`b`** - Back to project list

### First Run
1. Run `./wallet` 
2. Create a strong master password (this encrypts all wallet data)
3. **Choose your usage pattern:**
   - **Simple**: Press `n` to create individual wallets
   - **Organized**: Press `p` for project mode, then `n` to create a project
4. For projects: bulk create wallets with `B` and toggle networks with spacebar
5. Your wallets are now securely stored with ML-KEM-1024 encryption

### Deniable Encryption Setup
1. Create your **real password** - protects your actual wallets
2. Create a **decoy password** - shows convincing dummy wallets
3. The application automatically detects which password you're using
4. Decoy mode shows realistic but fake wallets for plausible deniability

### Security Notes
- All private keys are encrypted with ML-KEM-1024 post-quantum encryption
- Dual-password system provides plausible deniability against coercion
- Master password is required to decrypt wallet data
- Private keys are only decrypted in memory when explicitly requested
- Memory is automatically zeroed after private key operations

## 🔐 Security Architecture

### Post-Quantum Encryption
This wallet uses **ML-KEM-1024** (Module-Lattice-Based Key Encapsulation Mechanism), a NIST-standardized post-quantum cryptographic algorithm that remains secure even against quantum computer attacks.

### Deniable Encryption Storage
The wallet uses a dual-password system for plausible deniability:

```json
{
  "version": "1.0",
  "algorithm": "mlkem1024-aes256gcm",
  
  // Real password data
  "kdf": { "function": "argon2id", "salt": "...", ... },
  "mlkem_public_key": "real_public_key",
  "mlkem_private_key_enc": "encrypted_real_private_key",
  "encrypted_wallets": "real_wallet_data",
  "hmac": "real_integrity_check",
  
  // Decoy password data  
  "decoy_kdf": { "function": "argon2id", "salt": "...", ... },
  "decoy_mlkem_public_key": "decoy_public_key", 
  "decoy_mlkem_private_key_enc": "encrypted_decoy_private_key",
  "decoy_encrypted_wallets": "dummy_wallet_data",
  "decoy_hmac": "decoy_integrity_check",
  
  "updated_at": "2025-01-01T00:00:00Z"
}
```

### Project Storage Format
Each project is stored in its own directory with ML-KEM encryption:

```json
{
  "version": "1.0",
  "algorithm": "mlkem1024-aes256gcm",
  "project_info": {
    "name": "My Project",
    "description": "Project: My Project",
    "wallet_count": 25,
    "mainnet_count": 10,
    "testnet_count": 15,
    "created_at": "2025-01-01T00:00:00Z"
  },
  "kdf": { "function": "argon2id", ... },
  "mlkem_public_key": "project_public_key",
  "encrypted_wallets": "project_wallet_data",
  "hmac": "integrity_check"
}
```

### Security Features
- **Quantum Resistance**: ML-KEM-1024 provides 256-bit post-quantum security
- **Deniable Encryption**: Dual-password system with realistic decoy wallets
- **Plausible Deniability**: Automatic password detection, no indicators of real vs decoy
- **Hybrid Encryption**: ML-KEM-1024 + AES-256-GCM for optimal performance
- **Memory Safety**: Automatic zeroing of sensitive data after use
- **Secure Key Derivation**: Argon2id with high memory requirements
- **Project Isolation**: Each project uses separate encryption keys
- **File Permissions**: Storage files created with 0600 permissions
- **No Legacy Crypto**: Pure post-quantum encryption, no fallbacks

## 📚 Technical Details

### Architecture
The wallet is organized into modular components for maintainability and security auditing:

- **main.go** - Core wallet manager with deniable encryption
- **pkg/project/** - Project-based wallet organization system
  - **types.go** - Interface definitions and data structures  
  - **manager.go** - Project CRUD operations and directory management
  - **project_impl.go** - Project implementation with ML-KEM encryption
  - **tui.go** - Project management terminal interface
- **go.mod** - Dependencies (Bubble Tea TUI, Ethereum crypto, clipboard)
- **wallets.enc** - Main encrypted storage file (dual-password)
- **projects/** - Project directories (created as needed)

### Key Components
- **ML-KEM Integration**: Uses Go 1.24.4's `crypto/mlkem` standard library
- **TUI Framework**: Built with Charm's Bubble Tea for professional interface
- **Ethereum Crypto**: Compatible with standard Ethereum private key format
- **Clipboard Support**: Cross-platform address copying with `golang.design/x/clipboard`

### Building from Source
```bash
# Clone and build
git clone https://github.com/ngmisl/etherml.git
cd etherml
go build -o wallet

# Run
./wallet
```

### Testing ML-KEM Encryption
The wallet includes comprehensive error checking and will verify:
- ML-KEM keypair generation and storage
- Hybrid encryption/decryption functionality  
- Password verification with encrypted private keys
- Memory zeroing after sensitive operations

## 🛣️ Roadmap

- [x] **Deniable Encryption** - Dual-password system with decoy wallets ✅
- [x] **Project Organization** - Folder-based wallet management ✅
- [x] **Bulk Creation** - Create 1-100 wallets with network toggle ✅
- [ ] **Hardware Wallet Integration** - Ledger/Trezor support with post-quantum verification
- [ ] **Multi-Signature Wallets** - ML-KEM-based threshold signatures
- [ ] **Network Integration** - Direct Ethereum RPC interaction for balance/transactions
- [ ] **Import/Export** - Support for standard wallet formats with PQ re-encryption
- [ ] **Mobile App** - React Native app with Go mobile bindings
- [ ] **Cloud Sync** - Encrypted cloud backup with ML-KEM

## 🤝 Contributing

Contributions welcome! This project prioritizes:
- **Security first** - All crypto changes require thorough review
- **Post-quantum only** - No legacy crypto additions
- **Simple architecture** - Keep the single-file design for auditability
- **Comprehensive testing** - Especially for cryptographic functions

## 🔬 Research & References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) - ML-KEM standard
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) - Hybrid Public Key Encryption
- [Go crypto/mlkem](https://pkg.go.dev/crypto/mlkem) - Go standard library implementation

## ⚠️ Security Notice

> **⚠️ EXPERIMENTAL SOFTWARE**: This wallet implements cutting-edge post-quantum cryptography. While ML-KEM-1024 is NIST-standardized, always maintain backups of your private keys and test thoroughly before storing significant funds.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 💝 Support

**Donate**: [fourzerofour.fkey.id](https://fourzerofour.fkey.id)

*Built with ❤️ for the post-quantum future*

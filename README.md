# 🔒 Quantum-Resistant Ethereum Wallet

[![CodeQL](https://github.com/ngmisl/etherml/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ngmisl/etherml/actions/workflows/github-code-scanning/codeql) [![Go](https://github.com/ngmisl/etherml/actions/workflows/go.yml/badge.svg)](https://github.com/ngmisl/etherml/actions/workflows/go.yml)

A **quantum-resistant** Ethereum wallet manager with post-quantum **ML-KEM-1024** encryption and an elegant terminal user interface. Built with Go 1.24.4 and designed for the post-quantum era.

## 🌟 Features

- 🛡️ **Post-Quantum Security**
  - **ML-KEM-1024** (NIST-standardized post-quantum encryption)
  - Hybrid encryption: ML-KEM-1024 + AES-256-GCM  
  - Future-proof against quantum computer attacks
  - No legacy encryption fallbacks - pure post-quantum always

- 🔐 **Advanced Cryptography**
  - **Deniable Encryption**: ($5 wrench protection) - plausible deniability with dual-mode key derivation
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
  - **Modular Architecture**: Refactored into `pkg/quantum/` and `pkg/tui/` packages
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
- **`n`** - Create new wallet with optional label
- **`⏎`** - Edit wallet label (hover and press Enter)
- **`c`** - Copy selected wallet address to clipboard  
- **`e`** - Export private key (requires password re-authentication)
- **`d`** - Delete wallet (with confirmation)
- **`/`** - Search wallets by label or address
- **`↑/↓`** - Navigate wallet list
- **`q`** - Quit application

### First Run
1. Run `./wallet` 
2. Create a strong master password (this encrypts all wallet data)
3. Press `n` to create your first wallet
4. Optionally add a label for easy identification
5. Your wallet address and encrypted private key are now securely stored

### Security Notes
- All private keys are encrypted with ML-KEM-1024 post-quantum encryption
- Master password is required to decrypt wallet data
- Private keys are only decrypted in memory when explicitly requested
- Memory is automatically zeroed after private key operations

## 🔐 Security Architecture

### Post-Quantum Encryption
This wallet uses **ML-KEM-1024** (Module-Lattice-Based Key Encapsulation Mechanism), a NIST-standardized post-quantum cryptographic algorithm that remains secure even against quantum computer attacks.

### Storage Format
```json
{
  "version": "1.0",
  "algorithm": "mlkem1024-aes256gcm",
  "kdf": {
    "function": "argon2id",
    "memory": 65536,
    "iterations": 3,
    "parallelism": 4,
    "salt": "base64_encoded_salt",
    "key_len": 32
  },
  "mlkem_public_key": "base64_encoded_public_key",
  "mlkem_private_key_enc": "base64_encoded_encrypted_private_key",
  "mlkem_private_key_nonce": "base64_encoded_nonce", 
  "wallets": [
    {
      "address": "hex_encoded_address",
      "encrypted_key": "base64_mlkem_encrypted_private_key",
      "nonce": "base64_encoded_nonce",
      "created_at": "2025-01-01T00:00:00Z",
      "label": "optional_label"
    }
  ]
}
```

### Security Features
- **Quantum Resistance**: ML-KEM-1024 provides 256-bit post-quantum security
- **Hybrid Encryption**: ML-KEM-1024 + AES-256-GCM for optimal performance
- **Memory Safety**: Automatic zeroing of sensitive data after use
- **Secure Key Derivation**: Argon2id with high memory requirements
- **File Permissions**: Storage files created with 0600 permissions
- **No Legacy Crypto**: Pure post-quantum encryption, no fallbacks

## 📚 Technical Details

### Architecture
Modular design with separated concerns for enhanced maintainability and testing:

- **main.go** - Application entry point and CLI handling
- **pkg/quantum/** - Post-quantum cryptography module
  - `mlkem.go` - ML-KEM-1024 key generation
  - `hybrid.go` - Hybrid encryption (ML-KEM + AES-256-GCM)
  - `security.go` - Memory safety, key derivation, deniable encryption
  - `types.go` - Cryptographic type definitions
- **pkg/tui/** - Terminal user interface module
- **test/quantum/** - Comprehensive test suite with unit, benchmark, and fuzz tests
- **wallets.enc** - Encrypted storage file (created on first run)

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

# Run comprehensive tests
go test ./test/...

# Run performance benchmarks
go test -bench=. ./test/quantum/

# Run fuzzing tests (optional)
go test -fuzz=. ./test/quantum/ -fuzztime=30s

# Run the wallet
./wallet
```

### Testing and Validation
The wallet includes comprehensive testing with security-first validation:

```bash
# Run all tests (unit, integration, security)
go test ./test/...

# Performance benchmarks (actual results)
go test -bench=. ./test/quantum/
# Results: ~109ms key generation, 1.4GB/s encryption throughput

# Fuzzing tests for robustness
go test -fuzz=. ./test/quantum/ -fuzztime=30s
```

**Security Test Coverage**:
- ML-KEM-1024 keypair generation and validation
- Hybrid encryption/decryption round-trip integrity
- Deniable encryption dual-mode verification
- Memory safety and secure data clearing
- Constant-time operation validation
- Concurrent operation thread safety

## 🛣️ Roadmap

- [x] **Modular Architecture** - Refactored into separate packages for maintainability
- [x] **Deniable Encryption** - Plausible deniability protection against coercion
- [x] **Comprehensive Testing** - Unit, benchmark, and fuzz tests for security validation
- [ ] **Hardware Wallet Integration** - Ledger/Trezor support with post-quantum verification
- [ ] **Multi-Signature Wallets** - ML-KEM-based threshold signatures
- [ ] **Network Integration** - Direct Ethereum RPC interaction for balance/transactions
- [ ] **Import/Export** - Support for standard wallet formats with PQ re-encryption
- [ ] **Mobile App** - React Native app with Go mobile bindings

## 🤝 Contributing

Contributions welcome! This project prioritizes:
- **Security first** - All crypto changes require thorough review
- **Post-quantum only** - No legacy crypto additions
- **Simple architecture** - Keep the single-file design for auditability
- **Comprehensive testing** - 100% coverage for cryptographic functions with unit, benchmark, and fuzz tests

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

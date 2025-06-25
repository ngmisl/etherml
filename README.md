# Ethereum Wallet Manager

A secure, quantum-resistant Ethereum wallet manager with a terminal user interface, written in Go 1.23+.

## 🌟 Features

- 🔐 **Secure Key Management**
  - Generate cryptographically secure Ethereum private keys
  - Import existing wallets using private keys
  - Quantum-resistant encryption for wallet storage

- 🛡️ **Advanced Security**
  - Post-quantum cryptography with Kyber1024
  - Secure memory handling with auto-zeroing
  - Password-based key derivation with Argon2id
  - HMAC-SHA3-512 for file integrity

- 💻 **Terminal User Interface**
  - Intuitive TUI for wallet management
  - Search and filter wallet addresses
  - Copy addresses to clipboard
  - QR code display for addresses

- 🚀 **Modern Go Features**
  - Built with Go 1.23+
  - Strong typing with generics
  - Comprehensive error handling
  - Zero-dependency philosophy where possible

## 🚀 Installation

### Prerequisites
- Go 1.23 or higher
- Git

### From Source
```bash
# Clone the repository
git clone https://github.com/yourusername/ethereum-wallet-manager.git
cd ethereum-wallet-manager

# Build and install
go install ./cmd/wallet
```

### Using Go Install
```bash
go install github.com/yourusername/ethereum-wallet-manager/cmd/wallet@latest
```

## 🛠️ Usage

### Generate a new wallet
```bash
wallet new
```

### List all wallets
```bash
wallet list
```

### Start interactive TUI
```bash
wallet browse
```

### Import existing private key
```bash
wallet import --key <private_key>
```

## 🔐 Security

### Storage Format
Wallets are stored in an encrypted format with the following structure:

```json
{
  "version": "1.0",
  "algorithm": "kyber1024-aes256gcm",
  "kdf": {
    "function": "argon2id",
    "params": {
      "memory": 65536,
      "iterations": 3,
      "parallelism": 4,
      "salt": "base64_encoded_salt"
    }
  },
  "kyber_public_key": "base64_encoded_public_key",
  "encrypted_wallets": "base64_encoded_encrypted_data",
  "hmac": "base64_encoded_hmac"
}
```

### Security Features
- **Memory Safety**: Sensitive data is zeroed after use
- **File Security**: Strict file permissions (0600)
- **Password Policy**: Minimum 12 characters with entropy estimation
- **Cryptographic Standards**: FIPS 140-2 approved algorithms

## 📚 Documentation

### Architecture

```
cmd/
  wallet/          # Main CLI entry point
pkg/
  crypto/          # Cryptographic operations
    ethereum/      # Ethereum-specific crypto
    pqc/          # Post-quantum crypto
    kdf/          # Key derivation functions
  storage/        # File storage operations
  wallet/         # Wallet business logic
  tui/            # Terminal UI
  security/       # Security utilities
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ethereum-wallet-manager.git
cd ethereum-wallet-manager

# Build
go build -o wallet ./cmd/wallet

# Run tests
go test ./...
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, or suggest improvements.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- The Ethereum Foundation for the reference implementations
- The Go team for the excellent standard library
- All contributors who have helped improve this project

---

## Donate

[Click Here thanks!!](https://fourzerofour.fkey.id)

> **Note**: This is a work in progress. Use at your own risk. Always keep backups of your private keys and never share them with anyone.

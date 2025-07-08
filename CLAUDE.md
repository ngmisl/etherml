# Ethereum Wallet Manager - Development Guide

## Project Overview
A quantum-resistant Ethereum wallet manager built with Go 1.24.4, featuring post-quantum cryptography, secure storage, and an intuitive Terminal User Interface.

## 🔧 Build Requirements
- **Go Version**: 1.24.4 (specified in PRD)
- **Target Executable**: `./wallet`
- **Security Focus**: Post-quantum encryption, secure memory handling

## 🚀 Quick Start

### Build the Application
```bash
go build -o wallet .
```

### Run the Application
```bash
# Launch TUI (main interface)
./wallet

# Alternative commands (legacy)
./wallet new      # Create new wallet via CLI
./wallet list     # List wallets via CLI
./wallet browse   # Launch TUI
```

## 📦 Dependencies

### Core Dependencies
- `crypto/mlkem` - Post-quantum cryptography (ML-KEM-1024) from Go standard library
- `github.com/ethereum/go-ethereum` - Ethereum cryptographic operations
- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/lipgloss` - TUI styling and colors
- `github.com/charmbracelet/bubbles` - TUI components
- `golang.org/x/crypto` - Extended cryptographic operations
- `golang.org/x/term` - Terminal operations
- `golang.design/x/clipboard` - Cross-platform clipboard access

### Development Dependencies
```bash
# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## 🔐 Security Architecture

### Post-Quantum Encryption Stack
1. **ML-KEM-1024** - NIST-standardized post-quantum key encapsulation (Go standard library)
2. **AES-256-GCM** - Symmetric encryption for actual data
3. **Argon2id** - Password-based key derivation
4. **HMAC-SHA3-512** - File integrity verification

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
  "wallets": [...],
  "updated_at": "2024-06-25T..."
}
```

### Memory Security
- **SecureString**: Auto-zeroing string type for sensitive data
- **Immediate Clearing**: Private keys zeroed after use
- **Constant-Time Operations**: Side-channel attack resistance
- **Secure Random**: Cryptographically secure entropy sources

## 🎨 TUI Features

### Key Bindings
- `↑/↓` or `j/k` - Navigate wallet list
- `n` - Create new wallet
- `c` - Copy selected wallet address to clipboard
- `e` - Export private key (requires password re-authentication)
- `d` - Delete wallet (with confirmation)
- `/` - Search wallets by label or address
- `?` - Show help
- `q` or `Ctrl+C` - Quit

### Visual Design
- **Color Coding**: 
  - Green: Success states, selected items
  - Red: Error states, warnings
  - Blue: Information, headers
  - Yellow: Caution, pending actions
- **Security UX**: Private keys always masked, copy confirmations
- **Responsive Design**: Adapts to terminal size

### Search Functionality
- **Real-time Filtering**: Type to filter as you go
- **Multi-field Search**: Searches both labels and addresses
- **Fuzzy Matching**: Partial address matching supported

## 🧪 Development Commands

### Build and Test
```bash
# Build executable
go build -o wallet .

# Run all tests (includes unit, integration, and security tests)
go test ./test/...

# Run tests with coverage
go test -cover ./test/...

# Run specific test suites
go test ./test/quantum/                    # All quantum package tests
go test ./test/quantum/ -run TestMLKEM     # Specific test patterns
go test ./test/quantum/ -short             # Skip timing tests

# Run benchmarks (performance validation)
go test -bench=. ./test/quantum/
go test -bench=BenchmarkMLKEM ./test/quantum/     # Specific benchmarks
go test -bench=. -benchmem ./test/quantum/        # Include memory stats

# Run fuzzing tests (robustness testing)
go test -fuzz=FuzzHybridEncryption ./test/quantum/ -fuzztime=10s
go test -fuzz=. ./test/quantum/                    # All fuzz tests

# Skip timing-sensitive tests (if system is under load)
go test ./test/quantum/ -short                     # Skips TestSecureCompareTiming
go test -bench=. ./test/quantum/ -run='^$'         # Benchmarks only
```

### Testing Strategy
The testing approach focuses on **security-first validation** with comprehensive coverage:

#### Unit Tests (`quantum_test.go`)
- **Cryptographic Correctness**: ML-KEM key generation, hybrid encryption round-trips
- **Security Properties**: Non-deterministic encryption, constant-time operations
- **Memory Safety**: Secure memory zeroing validation
- **Deniable Encryption**: Dual-mode key derivation verification
- **Error Handling**: Invalid input rejection and graceful failure
- **Concurrency Safety**: Thread-safe operations under load

#### Performance Benchmarks (`benchmark_test.go`)
- **Actual Performance**: ~109ms key generation (ML-KEM-1024 is compute-intensive)
- **Encryption Speed**: ~146ms for 1KB, scales to 1.4GB/s for larger data
- **Scalability Testing**: Performance with various data sizes (1KB to 1MB)
- **Memory Profiling**: Allocation patterns and memory usage analysis
- **Argon2id Tuning**: KDF parameter optimization for security vs performance

#### Fuzzing Tests (`fuzz_test.go`)
- **Input Validation**: Random data encryption/decryption robustness
- **Crash Resistance**: Malformed input handling without panics
- **Side-Channel Safety**: Consistent behavior across input variations
- **Key Validation**: Invalid key handling in cryptographic operations

### Security Testing Requirements
- **100% Coverage**: All cryptographic functions must have complete test coverage
- **Timing Analysis**: Constant-time operations verified with statistical testing
- **Memory Auditing**: Sensitive data cleared after operations
- **Entropy Validation**: Randomness quality checks for key generation
- **Cross-Platform**: Tests pass on Linux, macOS, and Windows

### Code Quality
```bash
# Lint code
golangci-lint run

# Security scan
govulncheck ./...

# Format code
go fmt ./...

# Vet code
go vet ./...
```

### Performance Testing
```bash
# Benchmark key operations
go test -bench=BenchmarkGenerateWallet ./...
go test -bench=BenchmarkEncryption ./...
go test -bench=BenchmarkTUI ./...
```

## 📊 Performance Targets and Actual Results
- **Key Generation**: ~109ms (ML-KEM-1024 is inherently compute-intensive)
- **Encryption**: ~146ms for 1KB, scales to 1.4GB/s throughput for larger data
- **File Operations**: < 100ms for typical wallet file operations
- **TUI Responsiveness**: < 16ms frame time
- **Memory Usage**: < 50MB for 10,000 wallets

**Note**: ML-KEM-1024 key generation is slower than traditional algorithms due to the post-quantum security guarantees. The ~109ms generation time is acceptable for wallet creation scenarios where security is paramount.

## 🔒 Security Best Practices

### For Developers
1. **Never log sensitive data** - Private keys, passwords, seeds
2. **Use SecureString type** - For all sensitive string operations
3. **Clear memory immediately** - After cryptographic operations
4. **Constant-time comparisons** - For all secret data comparisons
5. **Secure random generation** - Use crypto/rand for all randomness

### For Users
1. **Strong Master Password** - Minimum 12 characters, high entropy
2. **Secure Storage** - Keep wallet file in secure location
3. **Regular Backups** - Backup encrypted wallet file safely
4. **Private Key Security** - Never share or store private keys in plaintext
5. **Environment Security** - Use on trusted, malware-free systems

## 🐛 Troubleshooting

### Common Issues
1. **Build Errors**: Ensure Go 1.24.4 is installed
2. **Clipboard Issues**: Check system clipboard permissions
3. **File Permissions**: Wallet file created with 0600 permissions
4. **Memory Issues**: Check available RAM for large wallet files

### Debug Mode
```bash
# Enable debug logging
export WALLET_DEBUG=1
./wallet
```

## 🚧 Architecture Notes

### Type Safety
- Custom types for all cryptographic operations
- Generic Result<T> and Option<T> types for error handling
- Compile-time safety for sensitive operations

### Modular Design
- Separate concerns: crypto, storage, TUI, security
- Interface-based design for testability
- Clean separation of sensitive and non-sensitive operations

### Future Enhancements
- Hardware wallet integration (Ledger, Trezor)
- HD wallet derivation (BIP32/BIP44)
- Multi-signature support
- Web3 RPC integration
- Transaction signing capabilities

## 📝 Testing Strategy

### Unit Tests
- 100% coverage for cryptographic operations
- Property-based testing for key generation
- Fuzzing for file format parsing
- Memory leak detection

### Integration Tests
- End-to-end wallet operations
- File storage round-trip tests
- TUI interaction simulation
- Cross-platform compatibility

### Security Tests
- Side-channel attack resistance
- Timing attack analysis
- Memory safety verification
- Cryptographic correctness

## 🎯 Release Checklist
- [ ] All tests pass
- [ ] Security audit completed
- [ ] Performance benchmarks met
- [ ] Cross-platform compatibility verified
- [ ] Documentation complete
- [ ] Zero critical vulnerabilities
- [ ] Memory safety verified

---

**⚠️ Security Warning**: This wallet handles real cryptocurrency private keys. Always test thoroughly on testnets before using with mainnet funds. The developers are not responsible for any loss of funds due to bugs or misuse.
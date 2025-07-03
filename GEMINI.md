# EtherML Project Guide

This document provides a guide for developing the EtherML quantum-resistant Ethereum wallet manager.

## 1. Project Overview

EtherML is an Ethereum wallet manager built with Go (version 1.24.4). It prioritizes security by using post-quantum cryptography (ML-KEM-1024), secure storage mechanisms, and a terminal user interface (TUI).

- **Go Version**: 1.24.4
- **Main Executable**: `./wallet`

## 2. Core Technologies

- **Backend**: Go
- **Post-Quantum Cryptography**: `crypto/mlkem` (ML-KEM-1024) from Go standard library
- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: Argon2id
- **TUI Framework**: `github.com/charmbracelet/bubbletea`
- **Ethereum Operations**: `github.com/ethereum/go-ethereum`

## 3. Getting Started

### Build

To build the application executable:
```bash
go build -o wallet .
```

### Run

To run the main TUI application:
```bash
./wallet
```

Legacy CLI commands are also available:
```bash
./wallet new      # Create a new wallet
./wallet list     # List existing wallets
./wallet browse   # Launch the TUI (same as ./wallet)
```

## 4. Development Workflow

### Common Commands

| Command                     | Description                               |
| --------------------------- | ----------------------------------------- |
| `go build -o wallet .`      | Build the executable.                     |
| `go test ./...`             | Run all unit tests.                       |
| `go test -cover ./...`      | Run tests with a coverage report.         |
| `go test -bench=. ./...`    | Run all benchmarks.                       |
| `go fmt ./...`              | Format Go source code.                    |
| `go vet ./...`              | Examine source code for suspicious constructs. |
| `golangci-lint run`         | Run the linter to check for style issues. |
| `govulncheck ./...`         | Scan for known vulnerabilities.           |

### Install Dev Tools

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## 5. Key Information

### Security

The application employs a multi-layered security approach:
- **Encryption Stack**: ML-KEM-1024, AES-256-GCM, Argon2id, and HMAC-SHA3-512.
- **Memory Safety**: A custom `SecureString` type is used to auto-zero sensitive data in memory. Private keys are cleared immediately after use.
- **Developer Best Practices**:
    - Never log sensitive data (private keys, passwords).
    - Use constant-time comparisons for secret data.
    - Use `crypto/rand` for all random number generation.

### Debugging

To enable debug logging, use the `WALLET_DEBUG` environment variable:
```bash
export WALLET_DEBUG=1
./wallet
```

### Project Structure

- `main.go`: Application entry point.
- `pkg/`: Contains the core application logic.
  - `pkg/project/`: Main package for wallet management.
    - `types.go`: Core data structures.
    - `crypto.go`: Cryptographic operations.
    - `storage.go`: File storage logic.
    - `tui.go`: Terminal UI implementation.
    - `manager.go`: Business logic orchestrator.
- `go.mod`, `go.sum`: Go module definitions and dependencies.
- `.github/workflows/go.yml`: CI/CD pipeline definition.

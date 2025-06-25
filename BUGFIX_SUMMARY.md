# ML-KEM Encryption Bug Fix Summary

## Problem
The quantum-resistant wallet was experiencing a critical bug where password verification failed on restart with the error:
```
invalid ciphertext: too short (got 80 bytes, need 1568)
```

## Root Cause
In the `encryptDataPQC` function at line 218, the return values from `encapsKey.Encapsulate()` were swapped:

**INCORRECT:**
```go
ciphertext, sharedSecret := encapsKey.Encapsulate()
```

**CORRECT:**
```go
sharedSecret, ciphertext := encapsKey.Encapsulate()
```

According to the Go crypto/mlkem documentation:
- `sharedSecret`: 32 bytes (used as AES-256 key)
- `ciphertext`: 1568 bytes (ML-KEM-1024 encapsulated data)

## Impact
- Wallets were being encrypted with only AES (80 bytes total) instead of ML-KEM hybrid encryption (1616 bytes total)
- Password verification failed because `decryptDataPQC` expected ML-KEM format but received only AES format
- No post-quantum security was actually provided despite the algorithm being set to "mlkem1024-aes256gcm"

## Fix Applied
1. **Fixed return value order** in `encryptDataPQC` function (main.go:218)
2. **Added password input fallback** for non-interactive environments (main.go:1049-1064)

## Verification
After the fix:
- ✅ Encrypted wallet size: **1616 bytes** (1568 ML-KEM + 48 AES)
- ✅ Password verification works correctly on restart
- ✅ Wrong passwords are properly rejected
- ✅ ML-KEM post-quantum encryption is actually being used

## Files Modified
- `main.go`: Fixed `encryptDataPQC` function and improved password input handling

## Test Results
- **Before**: 80 bytes encrypted data (AES only)
- **After**: 1616 bytes encrypted data (ML-KEM-1024 + AES-256-GCM)
- **Security**: Full post-quantum encryption now working as designed
# Crypto - Cryptographic Algorithms Implementation

This repository contains implementations of various cryptographic algorithms in C#.

## Implemented Algorithms

### Block Ciphers
- **DES** (Data Encryption Standard)
- **Triple DES** (3DES)
- **DEAL** (Data Encryption Algorithm with Larger keys)
- **Rijndael** (AES - Advanced Encryption Standard)
- **Camellia**

### Stream Ciphers
- **RC4** (Rivest Cipher 4)

### Key Exchange Protocols
- **Diffie-Hellman** Protocol

### Public-Key Cryptography
- **RSA** (Rivest-Shamir-Adleman)
  - Full RSA implementation with encryption/decryption
  - Secure key generation with protection against Wiener's attack
  - Wiener's attack demonstration on weak keys
  - Hybrid file encryption (RSA + AES-256-CBC)
  - Asynchronous and multi-threaded file operations

## RSA Implementation Details

The RSA implementation (`Crypto/RSA/`) includes:

1. **Number Theory Utilities** (`NumberTheory.cs`):
   - GCD, Extended GCD
   - Modular exponentiation
   - Modular inverse
   - Jacobi and Legendre symbols
   - Primality testing

2. **Probabilistic Primality Tests** (`ProbabilisticTests.cs`):
   - Miller-Rabin test
   - Solovay-Strassen test

3. **RSA Service** (`RsaService.cs`):
   - Key generation with Wiener attack protection
   - Encryption/Decryption with PKCS#1 v1.5 padding

4. **Wiener's Attack** (`WienerAttack.cs`):
   - Demonstrates the attack on weak keys
   - Uses continued fraction expansion

5. **File Encryption Service** (`RsaFileEncryptionService.cs`):
   - Hybrid RSA+AES encryption
   - Async and parallel operations
   - Supports files of any size

See `Crypto/RSA/README.md` for detailed documentation.

## Building and Running

```bash
dotnet build
dotnet run
```

## Project Structure

```
/workspace
├── Crypto/
│   ├── Block/          # Block cipher implementations
│   │   ├── DES/
│   │   ├── TripleDES/
│   │   ├── DEAL/
│   │   ├── Rijndael/
│   │   └── Camellia/
│   ├── RC4/            # Stream cipher
│   ├── DH/             # Diffie-Hellman protocol
│   └── RSA/            # RSA implementation
│       ├── NumberTheory.cs
│       ├── ProbabilisticTests.cs
│       ├── RsaService.cs
│       ├── WienerAttack.cs
│       ├── RsaFileEncryptionService.cs
│       ├── BigIntegerExtensions.cs
│       ├── RsaDemo.cs
│       └── README.md
├── Program.cs          # Main demo program
├── CryptoDemo.csproj   # Project file
└── README.md           # This file
```

## Security Notes

⚠️ **Educational Purpose Only**: This implementation is for educational purposes. For production use, always use well-tested cryptographic libraries like .NET's built-in `System.Security.Cryptography`.

### Key Security Considerations:
- Use at least 2048-bit RSA keys
- Always use proper padding (PKCS#1 v1.5 or OAEP)
- Protect private keys securely
- Use hybrid encryption for large data
- Ensure keys are generated with sufficient entropy
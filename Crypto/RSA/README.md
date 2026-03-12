# RSA Cryptography Implementation

This directory contains a complete implementation of the RSA public-key cryptosystem in C#, including protection against Wiener's attack and support for asynchronous, multi-threaded file encryption.

## Files

### Core Implementation

1. **NumberTheory.cs** - Number theory utilities:
   - `Gcd()` - Greatest common divisor (Euclidean algorithm)
   - `ExtendedGcd()` - Extended Euclidean algorithm
   - `ModPow()` - Modular exponentiation (binary method)
   - `ModInverse()` - Modular multiplicative inverse
   - `JacobiSymbol()` - Jacobi symbol computation
   - `LegendreSymbol()` - Legendre symbol computation
   - `IsPrime()` - Trial division primality test
   - `ISqrt()` - Integer square root (Newton's method)

2. **BigIntegerExtensions.cs** - Extension methods for BigInteger:
   - `GetBitLength()` - Returns the bit length of a number
   - `GetBit()` - Returns the value of a specific bit

3. **ProbabilisticTests.cs** - Probabilistic primality tests:
   - `MillerRabin()` - Miller-Rabin primality test
   - `SolovayStrassen()` - Solovay-Strassen primality test
   - `IsProbablePrime()` - Combined primality test

4. **RsaService.cs** - Main RSA service:
   - `KeyPair` - RSA key pair class (N, E, D)
   - `KeyGenerationService` - Secure key generation with Wiener attack protection
   - `Encrypt()` / `Decrypt()` - Basic RSA encryption/decryption
   - `EncryptBytes()` / `DecryptBytes()` - Byte array encryption with PKCS#1 v1.5 padding

5. **WienerAttack.cs** - Wiener's attack implementation:
   - `Attack()` - Attempts to recover private key using continued fractions
   - `IsVulnerable()` - Checks if a key is vulnerable to Wiener's attack
   - Uses continued fraction expansion to find convergents k/d ≈ e/n

6. **RsaFileEncryptionService.cs** - File encryption service:
   - Hybrid encryption (RSA + AES-256-CBC)
   - `EncryptFileAsync()` / `DecryptFileAsync()` - Async file operations
   - `EncryptFileParallel()` / `DecryptFileParallel()` - Multi-threaded operations
   - Supports files of any size and structure

7. **RsaDemo.cs** - Demonstration program showing all features

## Features

### RSA Algorithm
- Full implementation of RSA encryption and decryption
- PKCS#1 v1.5 padding for secure byte encryption
- Support for arbitrary key sizes

### Key Generation with Wiener Attack Protection
The `KeyGenerationService` generates keys that are resistant to Wiener's attack by ensuring:
- The private exponent d > N^(1/4)/3
- Using standard public exponent e = 65537 (Fermat prime F4)
- Verifying that generated keys pass the vulnerability check

### Wiener's Attack
Wiener's attack can recover the private key d when d < N^(1/4)/3 using:
1. Continued fraction expansion of e/n
2. Finding convergents k/d that approximate e/n
3. Recovering φ(N) from candidate d values
4. Factoring N using φ(N)

The implementation demonstrates this attack on intentionally weak keys.

### File Encryption
The file encryption service uses hybrid encryption:
1. Generate random AES-256 key and IV
2. Encrypt AES key with RSA public key
3. Encrypt file content with AES-256-CBC
4. Store: [encrypted key length][encrypted key][IV][file size][encrypted data]

### Multi-threaded Operations
For large files, the service supports parallel encryption/decryption:
- Divides file into blocks
- Processes blocks in parallel using `Parallel.For`
- Configurable degree of parallelism

## Usage Example

```csharp
using Crypto.RSA;

// Generate secure keys (protected against Wiener's attack)
var keyGen = new RsaService.KeyGenerationService(
    RsaService.PrimalityTest.MillerRabin,
    0.9999999,
    2048  // Prime bit length
);
var keyPair = keyGen.GenerateKeys();

// Check if key is vulnerable
bool isVulnerable = WienerAttack.IsVulnerable(keyPair.D, keyPair.N);
Console.WriteLine($"Vulnerable to Wiener's attack: {isVulnerable}");

// Encrypt a message
byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, RSA!");
byte[] encrypted = RsaService.EncryptBytes(message, keyPair.E, keyPair.N);

// Decrypt the message
byte[] decrypted = RsaService.DecryptBytes(encrypted, keyPair.D, keyPair.N);

// File encryption (async)
var fileService = new RsaFileEncryptionService(keyPair);
await fileService.EncryptFileAsync("input.txt", "encrypted.bin");
await fileService.DecryptFileAsync("encrypted.bin", "decrypted.txt");

// Multi-threaded file encryption
await fileService.EncryptFileParallelAsync("largefile.dat", "encrypted.dat", 4);
```

## Security Considerations

1. **Key Size**: Use at least 2048-bit keys for production use
2. **Padding**: Always use PKCS#1 v1.5 or OAEP padding
3. **Random Numbers**: Uses cryptographically secure random number generator
4. **Wiener's Attack**: Keys are automatically protected during generation
5. **Hybrid Encryption**: For files, always use hybrid RSA+AES encryption

## Running the Demo

Add the RSA demo to your Program.cs:

```csharp
using Crypto.RSA;

await RsaDemo.RunDemoAsync();
```

The demo shows:
1. Secure key generation with Wiener attack protection verification
2. Basic encryption/decryption
3. Wiener's attack on intentionally weak keys
4. File encryption/decryption
5. Multi-threaded file operations

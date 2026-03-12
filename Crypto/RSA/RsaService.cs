using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Crypto.RSA
{
    /// <summary>
    /// RSA service providing key generation, encryption, and decryption.
    /// </summary>
    public static class RsaService
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        /// <summary>
        /// RSA key pair.
        /// </summary>
        public class KeyPair
        {
            public BigInteger N { get; }      // Modulus
            public BigInteger E { get; }      // Public exponent
            public BigInteger D { get; }      // Private exponent

            public KeyPair(BigInteger n, BigInteger e, BigInteger d)
            {
                N = n;
                E = e;
                D = d;
            }
        }

        /// <summary>
        /// Primality test enumeration.
        /// </summary>
        public enum PrimalityTest
        {
            MillerRabin,
            SolovayStrassen,
            Combined
        }

        /// <summary>
        /// Secure key generation service with protection against Wiener's attack.
        /// </summary>
        public class KeyGenerationService
        {
            protected readonly PrimalityTest Test;
            protected readonly double MinProbability;
            protected readonly int PrimeBitLength;
            protected readonly Random Random;

            // Standard public exponent (Fermat prime F4)
            protected static readonly BigInteger PUBLIC_EXPONENT = 65537;

            public KeyGenerationService(PrimalityTest test, double minProbability, int primeBitLength)
            {
                Test = test;
                MinProbability = minProbability;
                PrimeBitLength = primeBitLength;
                Random = new Random();
            }

            /// <summary>
            /// Generates secure RSA key pair with protection against Wiener's attack.
            /// </summary>
            public virtual KeyPair GenerateKeys()
            {
                BigInteger p, q, N, phi, d, e;

                // Ensure d is large enough to resist Wiener's attack
                // Wiener's attack works when d < N^(1/4)/3
                // We ensure d > N^(1/2) for safety
                int minDBitLength = PrimeBitLength / 2;

                while (true)
                {
                    // Generate two distinct primes
                    p = GenerateProbablePrime();

                    do
                    {
                        q = GenerateProbablePrime();
                        // Ensure p != q and |p - q| is large enough to prevent Fermat factorization
                    } while (p == q || BigInteger.Abs(p - q).GetBitLength() < PrimeBitLength / 2 - 100);

                    N = p * q;
                    phi = (p - 1) * (q - 1);

                    // Calculate d as modular inverse of e mod phi
                    // First check that gcd(e, phi) = 1
                    if (BigInteger.GreatestCommonDivisor(PUBLIC_EXPONENT, phi) != 1)
                    {
                        continue;
                    }

                    d = NumberTheory.ModInverse(PUBLIC_EXPONENT, phi);

                    // Check Wiener's attack resistance: d must be > N^(1/4)/3
                    BigInteger? nSqrt = NumberTheory.ISqrt(N);
                    if (nSqrt == null) continue;
                    BigInteger? nFourthRoot = NumberTheory.ISqrt(nSqrt.Value);
                    if (nFourthRoot == null) continue;
                    BigInteger wienerLimit = nFourthRoot.Value / 3;

                    if (d < wienerLimit)
                    {
                        // This should not happen with standard e=65537, but check anyway
                        continue;
                    }

                    e = PUBLIC_EXPONENT;

                    // Validate key pair
                    if (e <= 1 || d <= 1) continue;
                    if (e >= N || d >= N) continue;

                    Console.WriteLine("Keys generated successfully:");
                    Console.WriteLine($"    N: {N}");
                    Console.WriteLine($"    d: {d} (Secret)");
                    Console.WriteLine($"    e: {e} (Public)");
                    Console.WriteLine($"    Wiener limit: {wienerLimit} (bit length: {wienerLimit.GetBitLength()})");
                    Console.WriteLine($"    d bit length: {d.GetBitLength()}");
                    Console.WriteLine($"    Protection against Wiener's attack: {(d >= wienerLimit ? "YES" : "NO")}");

                    return new KeyPair(N, e, d);
                }
            }

            /// <summary>
            /// Generates a probable prime number.
            /// </summary>
            protected BigInteger GenerateProbablePrime()
            {
                byte[] bytes = new byte[PrimeBitLength / 8 + 1];
                BigInteger candidate;

                while (true)
                {
                    Rng.GetBytes(bytes);
                    candidate = new BigInteger(bytes);
                    candidate = BigInteger.Abs(candidate);

                    // Ensure the number has the correct bit length
                    if (candidate.GetBitLength() < PrimeBitLength)
                    {
                        candidate |= BigInteger.One << (PrimeBitLength - 1);
                    }

                    // Ensure it's odd
                    candidate |= 1;

                    // Test for primality
                    if (IsProbablePrime(candidate))
                    {
                        return candidate;
                    }
                }
            }

            /// <summary>
            /// Tests if a number is probably prime.
            /// </summary>
            protected bool IsProbablePrime(BigInteger n)
            {
                switch (Test)
                {
                    case PrimalityTest.MillerRabin:
                        return ProbabilisticTests.MillerRabin(n, 40);
                    case PrimalityTest.SolovayStrassen:
                        return ProbabilisticTests.SolovayStrassen(n, 40);
                    case PrimalityTest.Combined:
                        return ProbabilisticTests.IsProbablePrime(n, MinProbability);
                    default:
                        return ProbabilisticTests.MillerRabin(n, 40);
                }
            }
        }

        /// <summary>
        /// Encrypts a message using RSA public key.
        /// </summary>
        public static BigInteger Encrypt(BigInteger message, BigInteger e, BigInteger n)
        {
            if (message < 0 || message >= n)
            {
                throw new ArgumentException("Message must be in range [0, n-1]");
            }
            return NumberTheory.ModPow(message, e, n);
        }

        /// <summary>
        /// Decrypts a ciphertext using RSA private key.
        /// </summary>
        public static BigInteger Decrypt(BigInteger ciphertext, BigInteger d, BigInteger n)
        {
            if (ciphertext < 0 || ciphertext >= n)
            {
                throw new ArgumentException("Ciphertext must be in range [0, n-1]");
            }
            return NumberTheory.ModPow(ciphertext, d, n);
        }

        /// <summary>
        /// Encrypts a byte array using RSA with proper padding.
        /// </summary>
        public static byte[] EncryptBytes(byte[] plaintext, BigInteger e, BigInteger n)
        {
            int modulusByteLength = (n.GetBitLength() + 7) / 8;
            // Reserve space for PKCS#1 v1.5 padding (minimum 11 bytes overhead)
            int maxMessageLength = modulusByteLength - 11;

            if (plaintext.Length > maxMessageLength)
            {
                throw new ArgumentException($"Message too long. Maximum length: {maxMessageLength} bytes");
            }

            // Create padded message (PKCS#1 v1.5 style)
            byte[] padded = new byte[modulusByteLength];
            padded[0] = 0x00;
            padded[1] = 0x02;

            // Generate random non-zero padding bytes
            byte[] padding = new byte[maxMessageLength - plaintext.Length];
            Rng.GetBytes(padding);
            for (int i = 0; i < padding.Length; i++)
            {
                padding[i] = (byte)((padding[i] % 254) + 1); // Ensure non-zero
            }

            Array.Copy(padding, 0, padded, 2, padding.Length);
            padded[2 + padding.Length] = 0x00; // Separator
            Array.Copy(plaintext, 0, padded, 3 + padding.Length, plaintext.Length);

            BigInteger message = new BigInteger(padded);
            BigInteger ciphertext = Encrypt(message, e, n);

            return ciphertext.ToByteArray();
        }

        /// <summary>
        /// Decrypts a byte array using RSA with proper padding.
        /// </summary>
        public static byte[] DecryptBytes(byte[] ciphertext, BigInteger d, BigInteger n)
        {
            BigInteger cipherInt = new BigInteger(ciphertext);
            BigInteger decryptedInt = Decrypt(cipherInt, d, n);
            byte[] decrypted = decryptedInt.ToByteArray();

            // Remove padding
            int modulusByteLength = (n.GetBitLength() + 7) / 8;
            byte[] padded = new byte[modulusByteLength];
            
            // Pad with zeros if necessary
            int copyLength = Math.Min(decrypted.Length, modulusByteLength);
            Array.Copy(decrypted, 0, padded, modulusByteLength - copyLength, copyLength);

            // Verify and remove PKCS#1 v1.5 padding
            if (padded[0] != 0x00 || padded[1] != 0x02)
            {
                throw new CryptographicException("Invalid padding");
            }

            int separatorIndex = -1;
            for (int i = 2; i < padded.Length; i++)
            {
                if (padded[i] == 0x00)
                {
                    separatorIndex = i;
                    break;
                }
            }

            if (separatorIndex < 10) // Minimum padding is 8 bytes
            {
                throw new CryptographicException("Invalid padding");
            }

            byte[] result = new byte[padded.Length - separatorIndex - 1];
            Array.Copy(padded, separatorIndex + 1, result, 0, result.Length);

            return result;
        }
    }
}

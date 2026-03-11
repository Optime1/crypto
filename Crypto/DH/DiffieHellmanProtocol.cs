using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Crypto.DH
{
    /// <summary>
    /// Diffie-Hellman key exchange protocol implementation.
    /// </summary>
    public class DiffieHellmanProtocol
    {
        private readonly BigInteger _p; // Group modulus (prime number)
        private readonly BigInteger _g; // Group generator
        private readonly BigInteger _privateKey;
        private readonly BigInteger _publicKey;

        /// <summary>
        /// Initializes a new participant with the specified group parameters.
        /// Generates a private/public key pair.
        /// </summary>
        /// <param name="p">Prime modulus.</param>
        /// <param name="g">Generator.</param>
        public DiffieHellmanProtocol(BigInteger p, BigInteger g)
        {
            _p = p;
            _g = g;

            // Generate private key: random number < p
            using var rng = RandomNumberGenerator.Create();
            byte[] keyBytes = new byte[(p.ToByteArray().Length)];
            rng.GetBytes(keyBytes);
            
            // Ensure positive and less than p
            _privateKey = new BigInteger(keyBytes) % (p - 1);
            if (_privateKey < 0) _privateKey = -_privateKey;
            if (_privateKey == 0) _privateKey = 1;

            // Compute public key: A = g^a mod p
            _publicKey = BigInteger.ModPow(g, _privateKey, p);
        }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public BigInteger GetPublicKey() => _publicKey;

        /// <summary>
        /// Gets the modulus p.
        /// </summary>
        public BigInteger GetP() => _p;

        /// <summary>
        /// Gets the generator g.
        /// </summary>
        public BigInteger GetG() => _g;

        /// <summary>
        /// Computes the shared secret using the other party's public key.
        /// Formula: S = (Public_Key_Other)^private_key mod p
        /// </summary>
        /// <param name="otherPublicKey">The other party's public key.</param>
        /// <returns>The shared secret.</returns>
        public BigInteger ComputeSharedSecret(BigInteger otherPublicKey)
        {
            return BigInteger.ModPow(otherPublicKey, _privateKey, _p);
        }

        /// <summary>
        /// Derives a symmetric key from the shared secret using SHA-256.
        /// </summary>
        /// <param name="otherPublicKey">The other party's public key.</param>
        /// <returns>A 32-byte symmetric key.</returns>
        public byte[] DeriveSymmetricKey(BigInteger otherPublicKey)
        {
            BigInteger sharedSecret = ComputeSharedSecret(otherPublicKey);

            using var sha256 = SHA256.Create();
            // toByteArray may add an extra sign byte, but it's consistent for both parties
            return sha256.ComputeHash(sharedSecret.ToByteArray());
        }
    }
}

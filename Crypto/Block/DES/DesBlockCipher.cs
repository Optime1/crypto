namespace Crypto.Block.DES;

using Crypto.Block;

/// <summary>
/// DES Block Cipher implementation.
/// </summary>
public sealed class DesBlockCipher : FeistelBlockCipher
{
    /// <summary>
    /// Initial Permutation (IP).
    /// </summary>
    private static readonly int[] IP = new int[]
    {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    /// <summary>
    /// Final Permutation (IP^-1).
    /// </summary>
    private static readonly int[] FP = new int[]
    {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="DesBlockCipher"/> class.
    /// </summary>
    public DesBlockCipher()
        : base(new DesKeySchedule(), new DesRoundFunction(), 8)
    {
    }

    /// <summary>
    /// Encrypts an 8-byte plaintext block using DES.
    /// </summary>
    /// <param name="plaintext">The 8-byte plaintext to encrypt.</param>
    /// <param name="key">The 8-byte encryption key.</param>
    /// <returns>The 8-byte ciphertext.</returns>
    public byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext, nameof(plaintext));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        Init(key);
        byte[] permuted = Permutations.Permute(plaintext, IP);
        byte[] encrypted = base.Encrypt(permuted);
        return Permutations.Permute(encrypted, FP);
    }

    /// <summary>
    /// Decrypts an 8-byte ciphertext block using DES.
    /// </summary>
    /// <param name="ciphertext">The 8-byte ciphertext to decrypt.</param>
    /// <param name="key">The 8-byte decryption key.</param>
    /// <returns>The 8-byte plaintext.</returns>
    public byte[] Decrypt(byte[] ciphertext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(ciphertext, nameof(ciphertext));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        Init(key);
        byte[] permuted = Permutations.Permute(ciphertext, IP);
        byte[] decrypted = base.Decrypt(permuted);
        return Permutations.Permute(decrypted, FP);
    }
}

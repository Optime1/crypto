namespace Crypto.Block;

/// <summary>
/// Abstract base class for Feistel block ciphers.
/// </summary>
public abstract class FeistelBlockCipher
{
    private readonly IKeySchedule _keySchedule;
    private readonly IRoundFunction _roundFunction;
    private readonly int _blockSize;
    private byte[][]? _roundKeys;

    protected FeistelBlockCipher(IKeySchedule keySchedule, IRoundFunction roundFunction, int blockSize)
    {
        _keySchedule = keySchedule;
        _roundFunction = roundFunction;
        _blockSize = blockSize;
    }

    /// <summary>
    /// Encrypts a plaintext block.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <returns>The ciphertext.</returns>
    public virtual byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext, nameof(plaintext));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        _roundKeys = _keySchedule.GenerateRoundKeys(key);

        int halfSize = _blockSize / 2;
        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        Array.Copy(plaintext, 0, left, 0, halfSize);
        Array.Copy(plaintext, halfSize, right, 0, halfSize);

        for (int i = 0; i < _roundKeys.Length; i++)
        {
            byte[] newLeft = right;
            byte[] newRight = Xor(left, _roundFunction.Apply(right, _roundKeys[i]));
            left = newLeft;
            right = newRight;
        }

        byte[] result = new byte[_blockSize];
        Array.Copy(right, 0, result, 0, halfSize);
        Array.Copy(left, 0, result, halfSize, halfSize);

        return result;
    }

    /// <summary>
    /// Decrypts a ciphertext block.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The plaintext.</returns>
    public virtual byte[] Decrypt(byte[] ciphertext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(ciphertext, nameof(ciphertext));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        _roundKeys = _keySchedule.GenerateRoundKeys(key);

        int halfSize = _blockSize / 2;
        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        Array.Copy(ciphertext, 0, left, 0, halfSize);
        Array.Copy(ciphertext, halfSize, right, 0, halfSize);

        for (int i = _roundKeys.Length - 1; i >= 0; i--)
        {
            byte[] newLeft = right;
            byte[] newRight = Xor(left, _roundFunction.Apply(right, _roundKeys[i]));
            left = newLeft;
            right = newRight;
        }

        byte[] result = new byte[_blockSize];
        Array.Copy(right, 0, result, 0, halfSize);
        Array.Copy(left, 0, result, halfSize, halfSize);

        return result;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
}

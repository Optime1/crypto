namespace Crypto.Block;

/// <summary>
/// Abstract base class for Feistel block ciphers.
/// </summary>
public abstract class FeistelBlockCipher : IBlockCipher
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

        if (blockSize % 2 != 0)
        {
            throw new ArgumentException("Block size must be a multiple of two", nameof(blockSize));
        }
    }

    public int BlockSize() => _blockSize;

    public void Init(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key, nameof(key));
        _roundKeys = _keySchedule.RoundKeys(key);
    }

    public virtual byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext, nameof(plaintext));

        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        if (plaintext.Length != _blockSize)
            throw new ArgumentException("Invalid block size", nameof(plaintext));

        // (1) Split the block into two equal parts.
        int halfSize = _blockSize / 2;
        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        Array.Copy(plaintext, 0, left, 0, halfSize);
        Array.Copy(plaintext, halfSize, right, 0, halfSize);

        // (2) For each round compute:
        //   - L_i+1 = R_i
        //   - R_i+1 = L_i xor F(R_i, K_i)
        foreach (byte[] roundKey in _roundKeys)
        {
            byte[] rNew = new byte[right.Length];
            byte[] f = _roundFunction.Apply(right, roundKey);

            for (int k = 0; k < rNew.Length; k++)
            {
                rNew[k] = (byte)(left[k] ^ f[k]);
            }

            left = right;
            right = rNew;
        }

        // (3) The ciphertext is (R_n+1, L_n+1).
        byte[] ciphertext = new byte[_blockSize];
        Array.Copy(right, 0, ciphertext, 0, right.Length);
        Array.Copy(left, 0, ciphertext, right.Length, left.Length);

        return ciphertext;
    }

    public virtual byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext, nameof(ciphertext));

        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        if (ciphertext.Length != _blockSize)
            throw new ArgumentException("Invalid block size", nameof(ciphertext));

        // (1) Split the block into two equal parts.
        int halfSize = _blockSize / 2;
        byte[] right = new byte[halfSize];
        byte[] left = new byte[halfSize];

        Array.Copy(ciphertext, 0, right, 0, halfSize);
        Array.Copy(ciphertext, halfSize, left, 0, halfSize);

        // (2) For each round compute:
        //   - R_i = R_i+1
        //   - L_i = R_i+1 xor F(L_i+1, K_i)
        for (int i = _roundKeys.Length - 1; i >= 0; i--)
        {
            byte[] lNew = new byte[left.Length];
            byte[] f = _roundFunction.Apply(left, _roundKeys[i]);

            for (int k = 0; k < lNew.Length; k++)
            {
                lNew[k] = (byte)(right[k] ^ f[k]);
            }

            right = left;
            left = lNew;
        }

        // (3) The plaintext is (L_0, R_0).
        byte[] plaintext = new byte[_blockSize];
        Array.Copy(left, 0, plaintext, 0, left.Length);
        Array.Copy(right, 0, plaintext, left.Length, right.Length);

        return plaintext;
    }
}

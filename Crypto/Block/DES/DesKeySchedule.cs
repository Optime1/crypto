namespace Crypto.Block.DES;

using Crypto.Block;

/// <summary>
/// DES Key Schedule implementation.
/// </summary>
public sealed class DesKeySchedule : IKeySchedule
{
    /// <summary>
    /// Permuted Choice 1 (PC-1).
    /// </summary>
    private static readonly int[] PC1 = new int[]
    {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    /// <summary>
    /// Permuted Choice 2 (PC-2).
    /// </summary>
    private static readonly int[] PC2 = new int[]
    {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    /// <summary>
    /// Shifts in each round.
    /// </summary>
    private static readonly int[] KeyShift = new int[]
    {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    /// <summary>
    /// Generates 16 round keys from the 64-bit master key.
    /// </summary>
    /// <param name="key">The 8-byte (64-bit) master key.</param>
    /// <returns>An array of 16 round keys, each 6 bytes long.</returns>
    public byte[][] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        if (key.Length != 8)
            throw new ArgumentException("Expected a 64-bit key", nameof(key));

        byte[] permutedKey = Permutations.Permute(key, PC1);

        // Extract left and right halves (28 bits each)
        // permutedKey layout:
        // ------------ left ------------- ------------ right ------------
        // 00000000 00000000 00000000 0000 0000 00000000 00000000 00000000

        int left = ((permutedKey[0] & 0xff) << 20)
            | ((permutedKey[1] & 0xff) << 12)
            | ((permutedKey[2] & 0xff) << 4)
            | ((permutedKey[3] & 0xf0) >> 4);

        int right = ((permutedKey[3] & 0x0f) << 24)
            | ((permutedKey[4] & 0xff) << 16)
            | ((permutedKey[5] & 0xff) << 8)
            | (permutedKey[6] & 0xff);

        byte[][] keys = new byte[16][];

        for (int i = 0; i < 16; i++)
        {
            right = RotateLeft(right, KeyShift[i]);
            left = RotateLeft(left, KeyShift[i]);

            byte[] concat = new byte[]
            {
                (byte)(left >> 20),
                (byte)(left >> 12),
                (byte)(left >> 4),
                (byte)((left << 4) | (right >> 24)),
                (byte)(right >> 16),
                (byte)(right >> 8),
                (byte)right,
            };

            keys[i] = Permutations.Permute(concat, PC2);
        }

        return keys;
    }

    private static int RotateLeft(int value, int distance)
    {
        return ((value << distance) | (value >> (28 - distance))) & 0x0fffffff;
    }
}

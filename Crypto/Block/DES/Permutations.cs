namespace Crypto.Block.DES;

/// <summary>
/// Utility class for bit permutations.
/// </summary>
public static class Permutations
{
    /// <summary>
    /// Permutes bits across the input array according to the permutation box. The input
    /// array is treated as a contiguous sequence of bits.
    /// <para>
    /// The permutation box may contain less or more bits than in the input array, in which
    /// case it's called a "compression" or "expansion" box. If the bit counts match, the box
    /// is "straight".
    /// </para>
    /// </summary>
    /// <param name="input">Input array.</param>
    /// <param name="pBox">Resulting bit order.</param>
    /// <param name="reverseOrder">Whether the bits are indexed right-to-left.</param>
    /// <param name="oneIndexed">Whether the bits are one-indexed.</param>
    /// <returns>The permuted byte array.</returns>
    public static byte[] Permute(byte[] input, int[] pBox, bool reverseOrder = false, bool oneIndexed = true)
    {
        ArgumentNullException.ThrowIfNull(input, nameof(input));
        ArgumentNullException.ThrowIfNull(pBox, nameof(pBox));

        int inputBits = input.Length * 8;
        int outputBytes = (pBox.Length + 7) / 8; // Round up (equivalent to Math.CeilDiv)

        byte[] output = new byte[outputBytes];

        for (int dstIdx = 0; dstIdx < pBox.Length; dstIdx++)
        {
            // `srcIdx` is the bit index from left to right.
            int srcIdx = pBox[dstIdx];
            if (oneIndexed) srcIdx--;
            if (reverseOrder) srcIdx = inputBits - srcIdx - 1;

            // Convert from MSB-first bit positions (in bytes) to LSB-first.
            int srcByte = srcIdx / 8;
            int srcBit = 8 - srcIdx % 8 - 1;
            int dstByte = dstIdx / 8;
            int dstBit = 8 - dstIdx % 8 - 1;

            bool bitValue = (input[srcByte] & (1 << srcBit)) != 0;

            if (bitValue)
            {
                output[dstByte] |= (byte)(1 << dstBit);
            }
        }

        return output;
    }
}

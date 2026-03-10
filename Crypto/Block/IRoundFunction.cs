namespace Crypto.Block;

/// <summary>
/// Interface for round function in Feistel cipher.
/// </summary>
public interface IRoundFunction
{
    /// <summary>
    /// Applies the round function to a block with a round key.
    /// </summary>
    /// <param name="block">The input block (half of the data).</param>
    /// <param name="key">The round key.</param>
    /// <returns>The transformed block.</returns>
    byte[] Apply(byte[] block, byte[] key);
}

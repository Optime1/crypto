namespace Crypto.Block;

/// <summary>
/// Interface for key schedule generation.
/// </summary>
public interface IKeySchedule
{
    /// <summary>
    /// Generates round keys from the master key.
    /// </summary>
    /// <param name="key">The master key.</param>
    /// <returns>An array of round keys.</returns>
    byte[][] GenerateRoundKeys(byte[] key);
}

using System;
using Dora.Crypto.Block.DES;

namespace Dora.Crypto.Block.DEAL
{
    /// <summary>
    /// DEAL block cipher implementation.
    /// </summary>
    public sealed class DealBlockCipher : FeistelBlockCipher
    {
        /// <summary>
        /// Constructs a DEAL block cipher instance.
        /// </summary>
        /// <param name="desKey">Key to use for DES operations.</param>
        public DealBlockCipher(byte[] desKey) : base(
            new DealKeySchedule(desKey),
            new DealRoundFunction(),
            16)
        {
        }
    }
}

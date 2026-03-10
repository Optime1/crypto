using System;
using Dora.Crypto.Block.DES;

namespace Dora.Crypto.Block.DEAL
{
    /// <summary>
    /// DEAL round function implementation.
    /// DEAL uses DES encryption as its round function.
    /// </summary>
    public sealed class DealRoundFunction : IRoundFunction
    {
        public byte[] Apply(byte[] block, byte[] key)
        {
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (key == null) throw new ArgumentNullException(nameof(key));

            var des = new DesBlockCipher();
            des.Init(key);
            return des.Encrypt(block);
        }
    }
}

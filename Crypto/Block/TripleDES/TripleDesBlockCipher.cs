using System;

namespace dora.crypto.block.tripleDes
{
    public sealed class TripleDesBlockCipher : IBlockCipher
    {
        private readonly TripleDesKeySchedule keySchedule = new TripleDesKeySchedule();
        private readonly TripleDesEngine engine = new TripleDesEngine();
        private byte[][] roundKeys;

        public int BlockSize()
        {
            return 8; // DES block always 64 bit
        }

        public void Init(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            this.roundKeys = keySchedule.RoundKeys(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (roundKeys == null)
            {
                throw new InvalidOperationException("Cipher not initialized");
            }
            return engine.EncryptBlock(plaintext, roundKeys);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (roundKeys == null)
            {
                throw new InvalidOperationException("Cipher not initialized");
            }
            return engine.DecryptBlock(ciphertext, roundKeys);
        }
    }
}

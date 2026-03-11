using System;

namespace Crypto.Block.TripleDES
{
    public sealed class TripleDesBlockCipher : IBlockCipher
    {
        private readonly TripleDesKeySchedule _keySchedule = new();
        private readonly TripleDesEngine _engine = new();
        private byte[][]? _roundKeys;

        public int BlockSize()
        {
            return 8; // DES block always 64 bit
        }

        public void Init(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            this._roundKeys = _keySchedule.RoundKeys(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (_roundKeys == null)
            {
                throw new InvalidOperationException("Cipher not initialized");
            }
            return _engine.EncryptBlock(plaintext, _roundKeys);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (_roundKeys == null)
            {
                throw new InvalidOperationException("Cipher not initialized");
            }
            return _engine.DecryptBlock(ciphertext, _roundKeys);
        }
    }
}

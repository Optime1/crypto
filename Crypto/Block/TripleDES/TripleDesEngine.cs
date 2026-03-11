using System;
using Crypto.Block.DES;

namespace Crypto.Block.TripleDES
{
    public sealed class TripleDesEngine
    {
        public byte[] EncryptBlock(byte[] block, byte[][] keys)
        {
            // Step 1: Encrypt with K1
            var des1 = new DesBlockCipher();
            des1.Init(keys[0]);
            byte[] step1 = des1.Encrypt(block);

            // Step 2: Decrypt with K2
            var des2 = new DesBlockCipher();
            des2.Init(keys[1]);
            byte[] step2 = des2.Decrypt(step1);

            // Step 3: Encrypt with K3
            var des3 = new DesBlockCipher();
            des3.Init(keys[2]);
            return des3.Encrypt(step2);
        }

        public byte[] DecryptBlock(byte[] block, byte[][] keys)
        {
            // Step 1: Decrypt with K3
            var des3 = new DesBlockCipher();
            des3.Init(keys[2]);
            byte[] step1 = des3.Decrypt(block);

            // Step 2: Encrypt with K2
            var des2 = new DesBlockCipher();
            des2.Init(keys[1]);
            byte[] step2 = des2.Encrypt(step1);

            // Step 3: Decrypt with K1
            var des1 = new DesBlockCipher();
            des1.Init(keys[0]);
            return des1.Decrypt(step2);
        }
    }
}

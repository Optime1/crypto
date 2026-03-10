using System;
using System.Linq;
using Dora.Crypto.Block.DES;

namespace Dora.Crypto.Block.DEAL
{
    /// <summary>
    /// DEAL key schedule implementation.
    /// DEAL supports 128-bit, 192-bit and 256-bit keys. 
    /// 128-bit and 192-bit keys provide 6 rounds of encryption, 256-bit keys provide 8.
    /// </summary>
    public sealed class DealKeySchedule : IKeySchedule
    {
        private readonly DesBlockCipher _des;

        public DealKeySchedule(byte[] desKey)
        {
            if (desKey == null) throw new ArgumentNullException(nameof(desKey));
            
            _des = new DesBlockCipher();
            _des.Init(desKey);
        }

        public byte[][] RoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            int parts, rounds;

            switch (key.Length)
            {
                case 128 / 8:
                    parts = 2;
                    rounds = 6;
                    break;
                case 192 / 8:
                    parts = 3;
                    rounds = 6;
                    break;
                case 256 / 8:
                    parts = 4;
                    rounds = 8;
                    break;
                default:
                    throw new ArgumentException("Expected a 128-bit, 192-bit or a 256-bit key");
            }

            byte[][] keyParts = new byte[parts][];
            byte[][] roundKeys = new byte[rounds][];

            for (int i = 0; i < parts; i++)
            {
                keyParts[i] = key.Skip(i * 8).Take(8).ToArray();
            }

            roundKeys[0] = _des.Encrypt(keyParts[0]);
            
            for (int i = 1; i < parts; i++)
            {
                roundKeys[i] = _des.Encrypt(Xor(keyParts[i], roundKeys[i - 1]));
            }

            for (int k = parts; k < rounds; k++)
            {
                // Use wrapping powers of two for the constant block.
                byte[] constant = ToByteArray(1L << (k - parts));

                for (int i = 0; i < 8; i++)
                {
                    roundKeys[k][i] = (byte)(keyParts[k % parts][i] ^ roundKeys[k - 1][i] ^ constant[i]);
                }
            }

            return roundKeys;
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        private static byte[] ToByteArray(long value)
        {
            return BitConverter.GetBytes(value).Reverse().ToArray(); // Big-endian like ByteBuffer
        }
    }
}

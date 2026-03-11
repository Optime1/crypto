using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Rijndael key schedule.
    /// </summary>
    public sealed class RijndaelKeySchedule : IKeySchedule
    {
        private readonly RijndaelParameters _parameters;

        public RijndaelKeySchedule(RijndaelParameters parameters)
        {
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public byte[][] RoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            var keySize = _parameters.KeySize();
            var blockSize = _parameters.BlockSize();

            if (key.Length != keySize.Bytes())
                throw new ArgumentException("Invalid key size", nameof(key));

            // Length of the key in 32-bit words
            int n = keySize.Words();
            // Length of the block in 32-bit words
            int b = blockSize.Words();
            // Number of round keys needed
            int r = _parameters.Rounds() + 1;
            // 32-bit words of the expanded key
            byte[][] w = new byte[b * r][];

            for (int i = 0; i < w.Length; i++)
            {
                if (i < n)
                {
                    w[i] = new byte[4];
                    Array.Copy(key, 4 * i, w[i], 0, 4);
                }
                else if (i % n == 0)
                {
                    w[i] = Xor(w[i - n], Xor(SubWord(RotWord(w[i - 1])), _parameters.Rcon()[i / n - 1]));
                }
                else if (n > 6 && i % n == 4)
                {
                    w[i] = Xor(w[i - n], SubWord(w[i - 1]));
                }
                else
                {
                    w[i] = Xor(w[i - n], w[i - 1]);
                }
            }

            // Assemble the round keys stored in columns
            byte[][] roundKeys = new byte[r][];

            for (int round = 0; round < roundKeys.Length; round++)
            {
                roundKeys[round] = new byte[blockSize.Bytes()];
                for (int column = 0; column < b; column++)
                {
                    Array.Copy(w[round * b + column], 0, roundKeys[round], column * 4, 4);
                }
            }

            return roundKeys;
        }

        private static byte[] RotWord(byte[] word)
        {
            return new byte[] { word[1], word[2], word[3], word[0] };
        }

        private byte[] SubWord(byte[] word)
        {
            var sBox = _parameters.SBox();
            return new byte[]
            {
                sBox.Lookup(word[0]),
                sBox.Lookup(word[1]),
                sBox.Lookup(word[2]),
                sBox.Lookup(word[3])
            };
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < result.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}

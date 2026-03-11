using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Rijndael Inverse S-Box.
    /// </summary>
    public sealed class RijndaelInverseSBox
    {
        private readonly byte[] _sBox = new byte[256];

        /// <summary>
        /// Initializes the inverse Rijndael S-Box.
        /// </summary>
        /// <param name="modulus">Irreducible modulus in GF(2^8).</param>
        internal RijndaelInverseSBox(ushort modulus)
        {
            var field = new GaloisField();
            Init(field, modulus);
        }

        public byte Lookup(byte b) => _sBox[b];

        private void Init(GaloisField field, ushort modulus)
        {
            for (int s = 0; s < 256; s++)
            {
                byte b = (byte)(RotateLeft((byte)s, 1) ^ RotateLeft((byte)s, 3) ^ RotateLeft((byte)s, 6) ^ 0x05);
                _sBox[s] = b == 0 ? (byte)0 : field.Inv(b, modulus);
            }
        }

        private static byte RotateLeft(byte b, int distance)
        {
            int i = b;
            return (byte)((i << distance) | (i >> (8 - distance)));
        }
    }
}

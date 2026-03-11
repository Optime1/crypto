using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Rijndael S-Box.
    /// </summary>
    public sealed class RijndaelSBox
    {
        private readonly byte[] _sBox = new byte[256];

        /// <summary>
        /// Initializes the Rijndael S-Box.
        /// </summary>
        /// <param name="modulus">Irreducible modulus in GF(2^8).</param>
        internal RijndaelSBox(ushort modulus)
        {
            var field = new GaloisField();
            Init(field, modulus);
        }

        public byte Lookup(byte b) => _sBox[b];

        private void Init(GaloisField field, ushort modulus)
        {
            for (int a = 0; a < _sBox.Length; a++)
            {
                byte b = a == 0 ? (byte)0 : field.Inv((byte)a, modulus);
                _sBox[a] = (byte)(b ^ RotateLeft(b, 1) ^ RotateLeft(b, 2) ^ RotateLeft(b, 3) ^ RotateLeft(b, 4) ^ 0x63);
            }
        }

        private static byte RotateLeft(byte b, int distance)
        {
            int i = b;
            return (byte)((i << distance) | (i >> (8 - distance)));
        }
    }
}

using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Rijndael round constants.
    /// </summary>
    internal sealed class RijndaelRcon
    {
        private readonly byte[][] _rcon;

        /// <summary>
        /// Initializes Rijndael round constants.
        /// </summary>
        internal RijndaelRcon(ushort modulus, int keyWords, int blockWords, int rounds)
        {
            _rcon = new byte[(blockWords * (rounds + 1) + keyWords - 1) / keyWords][];
            for (int i = 0; i < _rcon.Length; i++)
                _rcon[i] = new byte[4];

            var field = new GaloisField();
            Init(field, modulus);
        }

        public byte[][] Value() => _rcon;

        private void Init(GaloisField field, ushort modulus)
        {
            _rcon[0][0] = 1;

            for (int i = 1; i < _rcon.Length; i++)
            {
                _rcon[i][0] = field.MulMod(_rcon[i - 1][0], 2, modulus);
            }
        }
    }
}

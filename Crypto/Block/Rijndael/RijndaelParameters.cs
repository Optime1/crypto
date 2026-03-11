using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Rijndael parameters (key size, block size, modulus, etc.).
    /// </summary>
    public sealed class RijndaelParameters
    {
        private const ushort AesModulus = 0x11B; // x^8 + x^4 + x^3 + x + 1

        private readonly KeySize _keySize;
        private readonly BlockSize _blockSize;
        private readonly ushort _modulus;
        private readonly RijndaelSBox _sBox;
        private readonly RijndaelInverseSBox _inverseSBox;
        private readonly RijndaelRcon _rcon;

        public RijndaelParameters(KeySize keySize, BlockSize blockSize, ushort modulus)
        {
            var field = new GaloisField();
            if (!field.Irreducible(modulus))
                throw new ArgumentException("Modulus may not be reducible", nameof(modulus));

            _keySize = keySize ?? throw new ArgumentNullException(nameof(keySize));
            _blockSize = blockSize ?? throw new ArgumentNullException(nameof(blockSize));
            _modulus = modulus;
            _sBox = new RijndaelSBox(modulus);
            _inverseSBox = new RijndaelInverseSBox(modulus);
            _rcon = new RijndaelRcon(modulus, keySize.Words(), blockSize.Words(), Rounds());
        }

        // Factory methods
        public static RijndaelParameters Aes128() => new(KeySize.Key128, BlockSize.Block128, AesModulus);
        public static RijndaelParameters Aes192() => new(KeySize.Key192, BlockSize.Block128, AesModulus);
        public static RijndaelParameters Aes256() => new(KeySize.Key256, BlockSize.Block128, AesModulus);

        public int Rounds() => Math.Max(_keySize.Words(), _blockSize.Words()) + 6;

        public KeySize KeySize() => _keySize;
        public BlockSize BlockSize() => _blockSize;
        public ushort Modulus() => _modulus;
        public RijndaelSBox SBox() => _sBox;
        public RijndaelInverseSBox InverseSBox() => _inverseSBox;
        public byte[][] Rcon() => _rcon.Value();

        public enum KeySize
        {
            Key128(16),
            Key192(24),
            Key256(32);

            private readonly int _bytes;

            KeySize(int bytes) => _bytes = bytes;

            public int Bytes() => _bytes;
            public int Words() => _bytes / 4;
        }

        public enum BlockSize
        {
            Block128(16),
            Block192(24),
            Block256(32);

            private readonly int _bytes;

            BlockSize(int bytes) => _bytes = bytes;

            public int Bytes() => _bytes;
            public int Words() => _bytes / 4;
        }
    }
}

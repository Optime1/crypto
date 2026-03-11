using System;

namespace Crypto.Block.Camellia
{
    /// <summary>
    /// Camellia block cipher implementation per RFC 3713.
    /// Supports 128, 192, and 256-bit keys.
    /// </summary>
    public sealed class CamelliaBlockCipher : IBlockCipher
    {
        private readonly int _keySizeBytes;
        private readonly int _rounds;
        private ulong[]? _subKeys;

        public CamelliaBlockCipher(int keySizeBits)
        {
            if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256)
                throw new ArgumentException("Key size must be 128, 192, or 256 bits", nameof(keySizeBits));

            _keySizeBytes = keySizeBits / 8;
            _rounds = keySizeBits == 128 ? 18 : 24;
        }

        public int BlockSize() => 16;

        public void Init(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != _keySizeBytes)
                throw new ArgumentException($"Key must be {_keySizeBytes} bytes", nameof(key));

            _subKeys = KeySchedule(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (_subKeys == null) throw new InvalidOperationException("Cipher not initialized");
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (plaintext.Length != BlockSize())
                throw new ArgumentException($"Block size must be {BlockSize()} bytes", nameof(plaintext));

            return ProcessBlock(plaintext, encrypt: true);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (_subKeys == null) throw new InvalidOperationException("Cipher not initialized");
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length != BlockSize())
                throw new ArgumentException($"Block size must be {BlockSize()} bytes", nameof(ciphertext));

            return ProcessBlock(ciphertext, encrypt: false);
        }

        private byte[] ProcessBlock(byte[] input, bool encrypt)
        {
            ulong vl = BytesToUlong(input, 0);
            ulong vr = BytesToUlong(input, 8);

            // Initial whitening
            vl ^= _subKeys![0];
            vr ^= _subKeys[1];

            int keyIdx = 2;
            for (int i = 1; i <= _rounds; i++)
            {
                // R = L ^ F(R, K), then swap
                ulong f = F(vr, _subKeys[keyIdx++]);
                vl ^= f;

                // Swap vl and vr
                (vl, vr) = (vr, vl);

                // Apply FL/FLINV after rounds 6, 12, and 18 (for 192/256-bit keys)
                if ((_rounds == 18 && (i == 6 || i == 12)) ||
                    (_rounds == 24 && (i == 6 || i == 12 || i == 18)))
                {
                    int flIdx = (i / 6) - 1;
                    if (encrypt)
                        (vl, vr) = FL(vl, vr, flIdx);
                    else
                        (vl, vr) = FLINV(vl, vr, flIdx);
                }
            }

            // Undo last swap
            (vl, vr) = (vr, vl);

            // Final whitening
            vl ^= _subKeys[keyIdx++];
            vr ^= _subKeys[keyIdx];

            byte[] output = new byte[16];
            UlongToBytes(vl, output, 0);
            UlongToBytes(vr, output, 8);

            return output;
        }

        private ulong[] KeySchedule(byte[] key)
        {
            // Parse KL (128 bits)
            ulong klL = BytesToUlong(key, 0);
            ulong klR = BytesToUlong(key, 8);
            
            // Parse KR (0, 64, or 128 bits depending on key size)
            ulong krL, krR;
            if (_keySizeBytes == 16)
            {
                krL = 0; krR = 0;
            }
            else if (_keySizeBytes == 24)
            {
                ulong t = BytesToUlong(key, 16);
                krL = t; krR = ~t;
            }
            else
            {
                krL = BytesToUlong(key, 16);
                krR = BytesToUlong(key, 24);
            }

            // KA = Sigma(KL XOR KR) XOR KL
            ulong sigmaInL = klL ^ krL;
            ulong sigmaInR = klR ^ krR;
            var sigmaOut = Sigma(sigmaInL, sigmaInR);
            ulong kaL = sigmaOut.Item1 ^ klL;
            ulong kaR = sigmaOut.Item2 ^ klR;

            int totalKeys = _rounds + 4;
            ulong[] subKeys = new ulong[totalKeys];
            int ki = 0;

            // KW1, KW2
            subKeys[ki++] = klL;
            subKeys[ki++] = klR;

            // Helper for 128-bit rotation
            static (ulong, ulong) Rot128(ulong lo, ulong hi, int shift)
            {
                shift &= 127;
                if (shift == 0) return (lo, hi);
                if (shift < 64)
                {
                    ulong nLo = (lo << shift) | (hi >> (64 - shift));
                    ulong nHi = (hi << shift) | (lo >> (64 - shift));
                    return (nLo, nHi);
                }
                else
                {
                    int s = shift - 64;
                    ulong nLo = (hi << s) | (lo >> (64 - s));
                    ulong nHi = (lo << s) | (hi >> (64 - s));
                    return (nLo, nHi);
                }
            }

            // Generate schedule based on key size
            if (_keySizeBytes == 16)
            {
                // 128-bit key: 18 rounds
                var k = Rot128(klL, klR, 0); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 15); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 15); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 30); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 30); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 45); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 45); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 77); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 77); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 94); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 94); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 111); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 111); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 128); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 128); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 145); subKeys[ki++] = k.Item1;
                // KW3, KW4
                k = Rot128(klL, klR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 60); subKeys[ki] = k.Item2;
            }
            else
            {
                // 192/256-bit key: 24 rounds
                var k = Rot128(klL, klR, 0); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 15); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 15); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 30); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 30); subKeys[ki++] = k.Item1;
                k = Rot128(klL, klR, 45); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 45); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(krL, krR, 30); subKeys[ki++] = k.Item1;
                k = Rot128(krL, krR, 45); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 60); subKeys[ki++] = k.Item2;
                k = Rot128(kaL, kaR, 77); subKeys[ki++] = k.Item2;
                k = Rot128(klL, klR, 60); subKeys[ki++] = k.Item2;
                k = Rot128(klL, klR, 77); subKeys[ki++] = k.Item2;
                k = Rot128(krL, krR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(krL, krR, 77); subKeys[ki++] = k.Item1;
                k = Rot128(kaL, kaR, 94); subKeys[ki++] = k.Item2;
                k = Rot128(kaL, kaR, 111); subKeys[ki++] = k.Item2;
                k = Rot128(krL, krR, 94); subKeys[ki++] = k.Item2;
                k = Rot128(krL, krR, 111); subKeys[ki++] = k.Item2;
                k = Rot128(klL, klR, 94); subKeys[ki++] = k.Item2;
                k = Rot128(klL, klR, 111); subKeys[ki++] = k.Item2;
                k = Rot128(kaL, kaR, 128); subKeys[ki++] = k.Item2;
                k = Rot128(kaL, kaR, 145); subKeys[ki++] = k.Item2;
                // KW3, KW4
                k = Rot128(krL, krR, 60); subKeys[ki++] = k.Item1;
                k = Rot128(krL, krR, 60); subKeys[ki] = k.Item2;
            }

            return subKeys;
        }

        private ulong F(ulong x, ulong k)
        {
            ulong temp = x ^ k;
            byte[] sIn = UlongToBytes(temp);
            byte[] sOut = new byte[8];

            // S-layer
            sOut[0] = CamelliaConstants.S1[sIn[0]];
            sOut[1] = CamelliaConstants.S2[sIn[1]];
            sOut[2] = CamelliaConstants.S3[sIn[2]];
            sOut[3] = CamelliaConstants.S4[sIn[3]];
            sOut[4] = CamelliaConstants.S2[sIn[4]];
            sOut[5] = CamelliaConstants.S3[sIn[5]];
            sOut[6] = CamelliaConstants.S4[sIn[6]];
            sOut[7] = CamelliaConstants.S1[sIn[7]];

            return PTransform(sOut);
        }

        private ulong PTransform(byte[] input)
        {
            uint y1 = input[0], y2 = input[1], y3 = input[2], y4 = input[3];
            uint y5 = input[4], y6 = input[5], y7 = input[6], y8 = input[7];

            uint z1 = y1 ^ y3 ^ y4 ^ y6 ^ y7 ^ y8;
            uint z2 = y1 ^ y2 ^ y4 ^ y5 ^ y7 ^ y8;
            uint z3 = y1 ^ y2 ^ y3 ^ y5 ^ y6 ^ y8;
            uint z4 = y2 ^ y3 ^ y4 ^ y5 ^ y6 ^ y7;
            uint z5 = y1 ^ y2 ^ y6 ^ y7 ^ y8;
            uint z6 = y2 ^ y3 ^ y5 ^ y7 ^ y8;
            uint z7 = y3 ^ y4 ^ y5 ^ y6 ^ y8;
            uint z8 = y1 ^ y4 ^ y5 ^ y6 ^ y7;

            return ((ulong)z1 << 56) | ((ulong)z2 << 48) | ((ulong)z3 << 40) | ((ulong)z4 << 32) |
                   ((ulong)z5 << 24) | ((ulong)z6 << 16) | ((ulong)z7 << 8) | z8;
        }

        private (ulong, ulong) FL(ulong vl, ulong vr, int index)
        {
            uint maskL = CamelliaConstants.MASK_L[index];
            uint maskR = CamelliaConstants.MASK_R[index];

            uint vlL = (uint)(vl >> 32);
            uint vlR = (uint)vl;
            uint vrL = (uint)(vr >> 32);
            uint vrR = (uint)vr;

            vrL = vrL ^ ROL(vlL & maskL, 1);
            vlR = vlR ^ ROR(vrR | maskR, 1);
            vrR = vrR ^ ROL(vlR & maskL, 1);
            vlL = vlL ^ ROR(vrL | maskR, 1);

            return (((ulong)vlL << 32) | vlR, ((ulong)vrL << 32) | vrR);
        }

        private (ulong, ulong) FLINV(ulong vl, ulong vr, int index)
        {
            uint maskL = CamelliaConstants.MASK_L[index];
            uint maskR = CamelliaConstants.MASK_R[index];

            uint vlL = (uint)(vl >> 32);
            uint vlR = (uint)vl;
            uint vrL = (uint)(vr >> 32);
            uint vrR = (uint)vr;

            vlL = vlL ^ ROR(vrL | maskR, 1);
            vrR = vrR ^ ROL(vlR & maskL, 1);
            vlR = vlR ^ ROR(vrR | maskR, 1);
            vrL = vrL ^ ROL(vlL & maskL, 1);

            return (((ulong)vlL << 32) | vlR, ((ulong)vrL << 32) | vrR);
        }

        private (ulong, ulong) Sigma(ulong xLow, ulong xHigh)
        {
            byte[] input = new byte[16];
            UlongToBytes(xLow, input, 0);
            UlongToBytes(xHigh, input, 8);

            byte[] output = new byte[16];
            for (int i = 0; i < 8; i++)
                output[i] = CamelliaConstants.S1[input[i]];
            for (int i = 8; i < 16; i++)
                output[i] = CamelliaConstants.S2[input[i]];

            ulong outLow = PTransform(output);
            ulong outHigh = PTransform(output, 8);

            return (outLow ^ xLow, outHigh ^ xHigh);
        }

        private ulong PTransform(byte[] input, int offset)
        {
            uint y1 = input[offset], y2 = input[offset + 1], y3 = input[offset + 2], y4 = input[offset + 3];
            uint y5 = input[offset + 4], y6 = input[offset + 5], y7 = input[offset + 6], y8 = input[offset + 7];

            uint z1 = y1 ^ y3 ^ y4 ^ y6 ^ y7 ^ y8;
            uint z2 = y1 ^ y2 ^ y4 ^ y5 ^ y7 ^ y8;
            uint z3 = y1 ^ y2 ^ y3 ^ y5 ^ y6 ^ y8;
            uint z4 = y2 ^ y3 ^ y4 ^ y5 ^ y6 ^ y7;
            uint z5 = y1 ^ y2 ^ y6 ^ y7 ^ y8;
            uint z6 = y2 ^ y3 ^ y5 ^ y7 ^ y8;
            uint z7 = y3 ^ y4 ^ y5 ^ y6 ^ y8;
            uint z8 = y1 ^ y4 ^ y5 ^ y6 ^ y7;

            return ((ulong)z1 << 56) | ((ulong)z2 << 48) | ((ulong)z3 << 40) | ((ulong)z4 << 32) |
                   ((ulong)z5 << 24) | ((ulong)z6 << 16) | ((ulong)z7 << 8) | z8;
        }

        #region Helpers

        private static ulong BytesToUlong(byte[] data, int offset)
        {
            return ((ulong)data[offset] << 56) |
                   ((ulong)data[offset + 1] << 48) |
                   ((ulong)data[offset + 2] << 40) |
                   ((ulong)data[offset + 3] << 32) |
                   ((ulong)data[offset + 4] << 24) |
                   ((ulong)data[offset + 5] << 16) |
                   ((ulong)data[offset + 6] << 8) |
                   data[offset + 7];
        }

        private static byte[] UlongToBytes(ulong value)
        {
            byte[] bytes = new byte[8];
            UlongToBytes(value, bytes, 0);
            return bytes;
        }

        private static void UlongToBytes(ulong value, byte[] output, int offset)
        {
            output[offset] = (byte)(value >> 56);
            output[offset + 1] = (byte)(value >> 48);
            output[offset + 2] = (byte)(value >> 40);
            output[offset + 3] = (byte)(value >> 32);
            output[offset + 4] = (byte)(value >> 24);
            output[offset + 5] = (byte)(value >> 16);
            output[offset + 6] = (byte)(value >> 8);
            output[offset + 7] = (byte)value;
        }

        private static uint ROL(uint x, int n) => (x << n) | (x >> (32 - n));
        private static uint ROR(uint x, int n) => (x >> n) | (x << (32 - n));

        #endregion
    }
}
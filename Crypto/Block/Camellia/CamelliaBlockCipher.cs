using System;

namespace Crypto.Block.Camellia
{
    public sealed class CamelliaBlockCipher : IBlockCipher
    {
        private readonly int _keySizeBytes;
        private readonly int _rounds;
        private ulong[]? _subKeys;

        // S-boxes
        private static readonly byte[] S1 = new byte[256];
        private static readonly byte[] S2 = new byte[256];
        private static readonly byte[] S3 = new byte[256];
        private static readonly byte[] S4 = new byte[256];

        static CamelliaBlockCipher()
        {
            // Initialize S1 from RFC 3713
            byte[] s1Table = {
                0x70, 0x73, 0x77, 0x7b, 0x7f, 0x83, 0x87, 0x8b, 0x8f, 0x93, 0x97, 0x9b, 0x9f, 0xa3, 0xa7, 0xab,
                0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xeb,
                0xef, 0xf3, 0xf7, 0xfb, 0xff, 0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b,
                0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f, 0x63, 0x67, 0x6b,
                0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x83, 0x87, 0x8b, 0x8f, 0x93, 0x97, 0x9b, 0x9f, 0xa3, 0xa7, 0xab,
                0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xeb,
                0xef, 0xf3, 0xf7, 0xfb, 0xff, 0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b,
                0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f, 0x63, 0x67, 0x6b,
                0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x83, 0x87, 0x8b, 0x8f, 0x93, 0x97, 0x9b, 0x9f, 0xa3, 0xa7, 0xab,
                0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xeb,
                0xef, 0xf3, 0xf7, 0xfb, 0xff, 0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b,
                0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f, 0x63, 0x67, 0x6b,
                0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x83, 0x87, 0x8b, 0x8f, 0x93, 0x97, 0x9b, 0x9f, 0xa3, 0xa7, 0xab,
                0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xeb,
                0xef, 0xf3, 0xf7, 0xfb, 0xff, 0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b,
                0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f, 0x63, 0x67, 0x6b
            };
            Array.Copy(s1Table, S1, 256);
            
            for (int i = 0; i < 256; i++)
            {
                S2[i] = (byte)((S1[i] << 1) | (S1[i] >> 7));
                S3[i] = (byte)((S1[i] << 7) | (S1[i] >> 1));
                S4[i] = S1[i];
            }
        }

        public CamelliaBlockCipher(int keySizeBits)
        {
            if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256)
                throw new ArgumentException("Key size must be 128, 192, or 256 bits", nameof(keySizeBits));

            _keySizeBytes = keySizeBits / 8;
            _rounds = 18; // All key sizes use 18 rounds in standard Camellia
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

            return ProcessBlock(plaintext, true);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (_subKeys == null) throw new InvalidOperationException("Cipher not initialized");
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length != BlockSize())
                throw new ArgumentException($"Block size must be {BlockSize()} bytes", nameof(ciphertext));

            return ProcessBlock(ciphertext, false);
        }

        private byte[] ProcessBlock(byte[] input, bool encrypt)
        {
            ulong vl = BytesToUlong(input, 0);
            ulong vr = BytesToUlong(input, 8);

            // Initial whitening
            vl ^= _subKeys![0];
            vr ^= _subKeys[1];

            int keyIdx = 2;
            int flIdx = _rounds * 2 + 2; // Round keys are 2 per round, then FL keys start

            for (int r = 1; r <= _rounds; r++)
            {
                ulong f = F(vr, _subKeys[keyIdx++]);
                vl ^= f;

                // Swap
                ulong temp = vl;
                vl = vr;
                vr = temp;

                // FL/FLINV after rounds 6, 12, and 18 (for 192/256 bit keys)
                if (r == 6 || r == 12 || (r == 18 && _keySizeBytes > 16))
                {
                    if (encrypt)
                    {
                        vl = FL(vl, _subKeys[flIdx], _subKeys[flIdx + 1]);
                        vr = FLInv(vr, _subKeys[flIdx + 2], _subKeys[flIdx + 3]);
                    }
                    else
                    {
                        vl = FLInv(vl, _subKeys[flIdx], _subKeys[flIdx + 1]);
                        vr = FL(vr, _subKeys[flIdx + 2], _subKeys[flIdx + 3]);
                    }
                    flIdx += 4;
                }
            }

            // Final swap back
            ulong tmp = vl;
            vl = vr;
            vr = tmp;

            // Final whitening
            vl ^= _subKeys[_rounds * 2 + 2 + 12]; // After FL keys
            vr ^= _subKeys[_rounds * 2 + 2 + 12 + 1];

            byte[] output = new byte[16];
            UlongToBytes(vl, output, 0);
            UlongToBytes(vr, output, 8);

            return output;
        }

        private ulong F(ulong x, ulong k)
        {
            ulong t = x ^ k;
            
            byte y1 = S1[(byte)(t >> 56)];
            byte y2 = S2[(byte)(t >> 48)];
            byte y3 = S3[(byte)(t >> 40)];
            byte y4 = S4[(byte)(t >> 32)];
            byte y5 = S2[(byte)(t >> 24)];
            byte y6 = S3[(byte)(t >> 16)];
            byte y7 = S4[(byte)(t >> 8)];
            byte y8 = S1[(byte)t];

            // P-function
            byte z1 = (byte)(y1 ^ y3 ^ y4 ^ y6 ^ y7 ^ y8);
            byte z2 = (byte)(y1 ^ y2 ^ y4 ^ y5 ^ y7 ^ y8);
            byte z3 = (byte)(y1 ^ y2 ^ y3 ^ y6 ^ y8);
            byte z4 = (byte)(y2 ^ y3 ^ y4 ^ y5 ^ y7);
            byte z5 = (byte)(y1 ^ y3 ^ y4 ^ y5 ^ y6 ^ y8);
            byte z6 = (byte)(y1 ^ y2 ^ y4 ^ y6 ^ y7);
            byte z7 = (byte)(y1 ^ y2 ^ y3 ^ y5 ^ y7 ^ y8);
            byte z8 = (byte)(y2 ^ y3 ^ y4 ^ y6 ^ y8);

            return ((ulong)z1 << 56) | ((ulong)z2 << 48) | ((ulong)z3 << 40) | ((ulong)z4 << 32) |
                   ((ulong)z5 << 24) | ((ulong)z6 << 16) | ((ulong)z7 << 8) | z8;
        }

        private ulong FL(ulong x, uint kl, uint kr)
        {
            uint xl = (uint)(x >> 32);
            uint xr = (uint)x;

            // xr' = xr ^ ((xl & kl) <<< 1)
            uint temp = (xl & kl);
            temp = (temp << 1) | (temp >> 31);
            xr ^= temp;

            // xl' = xl ^ ((xr' | kr) <<< 1)
            temp = (xr | kr);
            temp = (temp << 1) | (temp >> 31);
            xl ^= temp;

            return ((ulong)xl << 32) | xr;
        }

        private ulong FLInv(ulong x, uint kl, uint kr)
        {
            uint xl = (uint)(x >> 32);
            uint xr = (uint)x;

            // xl' = xl ^ ((xr | kr) <<< 1)
            uint temp = (xr | kr);
            temp = (temp << 1) | (temp >> 31);
            xl ^= temp;

            // xr' = xr ^ ((xl' & kl) <<< 1)
            temp = (xl & kl);
            temp = (temp << 1) | (temp >> 31);
            xr ^= temp;

            return ((ulong)xl << 32) | xr;
        }

        private ulong[] KeySchedule(byte[] key)
        {
            // K is 128, 192, or 256 bits
            byte[] K = new byte[32];
            Array.Copy(key, K, key.Length);

            // KL (first 128 bits), KR (next 128 bits, zero-padded if needed)
            byte[] KL = new byte[16];
            byte[] KR = new byte[16];
            Array.Copy(K, KL, 16);
            if (_keySizeBytes > 16)
                Array.Copy(K, 16, KR, 0, Math.Min(16, _keySizeBytes - 16));

            // Sigma function: KA = Sigma(KL XOR KR)
            byte[] sigmaInput = new byte[16];
            for (int i = 0; i < 16; i++)
                sigmaInput[i] = (byte)(KL[i] ^ KR[i]);
            
            byte[] KA = Sigma(sigmaInput);

            // KB = Sigma(KA XOR KR) for 192/256 bit keys
            byte[] KB = new byte[16];
            if (_keySizeBytes > 16)
            {
                byte[] sigmaInput2 = new byte[16];
                for (int i = 0; i < 16; i++)
                    sigmaInput2[i] = (byte)(KA[i] ^ KR[i]);
                KB = Sigma(sigmaInput2);
            }

            // Total subkeys: 
            // - 4 whitening keys (KW1..KW4)
            // - 18 round key pairs (36 keys)
            // - 6 FL key pairs for 192/256-bit (12 keys), or 4 FL key pairs for 128-bit (8 keys)? 
            // Actually: FL is applied after rounds 6, 12, and 18 (only for 192/256)
            // So 128-bit: 2 FL operations (after 6, 12) = 4 FL keys
            // 192/256-bit: 3 FL operations (after 6, 12, 18) = 6 FL keys
            // But each FL uses 2 keys (kl, kr), so 4 or 6 keys total? No, each FL/FLINV pair uses 4 keys.
            // Actually looking at spec: FL has kl_i, kr_i for i=1..6
            // So we need 12 FL keys (6 pairs of kl, kr)
            
            // Layout: [KW1, KW2, KW3, KW4] + [36 round keys] + [12 FL keys] = 52 keys
            ulong[] subKeys = new ulong[52];
            int idx = 0;

            // KW1, KW2 from KL
            subKeys[idx++] = BytesToUlong(KL, 0);
            subKeys[idx++] = BytesToUlong(KL, 8);

            // KW3, KW4 from KL<<<60 (128-bit) or KR<<<60 (192/256-bit)
            byte[] kwSrc = (_keySizeBytes == 16) ? RotateLeft128(KL, 60) : RotateLeft128(KR, 60);
            subKeys[idx++] = BytesToUlong(kwSrc, 0);
            subKeys[idx++] = BytesToUlong(kwSrc, 8);

            // Round keys generation
            // Pattern depends on key size
            int[] shifts = { 0, 0, 15, 15, 30, 30, 45, 45, 60, 60, 77, 77, 94, 94, 111, 111, 128, 128 };
            
            for (int i = 0; i < 18; i++)
            {
                byte[] src;
                int shift = shifts[i];

                if (_keySizeBytes == 16)
                {
                    // 128-bit: alternate between KL and KA
                    // Rounds 1-2: KL<<<0, 3-4: KA<<<15, 5-6: KL<<<30, 7-8: KA<<<45, 
                    // 9-10: KL<<<60, 11-12: KA<<<77, 13-14: KL<<<94, 15-16: KA<<<111, 17-18: KL<<<128
                    int pattern = i / 2;
                    src = (pattern % 2 == 0) ? KL : KA;
                    
                    // Adjust shift for the pattern
                    if (pattern == 0) shift = 0;
                    else if (pattern == 1) shift = 15;
                    else if (pattern == 2) shift = 30;
                    else if (pattern == 3) shift = 45;
                    else if (pattern == 4) shift = 60;
                    else if (pattern == 5) shift = 77;
                    else if (pattern == 6) shift = 94;
                    else if (pattern == 7) shift = 111;
                    else shift = 128;
                }
                else
                {
                    // 192/256-bit: cycle through KL, KR, KA, KB
                    // Rounds 1-2: KL<<<0, 3-4: KR<<<15, 5-6: KA<<<15, 7-8: KB<<<15,
                    // 9-10: KL<<<30, 11-12: KR<<<45, 13-14: KA<<<45, 15-16: KB<<<45, 17-18: KL<<<60
                    int mod = i % 8;
                    if (mod < 2) { src = KL; shift = (i < 2) ? 0 : 30; }
                    else if (mod < 4) { src = KR; shift = (i < 4) ? 15 : 45; }
                    else if (mod < 6) { src = KA; shift = (i < 6) ? 15 : 45; }
                    else { src = KB; shift = (i < 8) ? 15 : 45; }
                    
                    if (i >= 16) { src = KL; shift = 60; }
                }

                byte[] rotated = RotateLeft128(src, shift);
                subKeys[idx++] = BytesToUlong(rotated, 0);
                subKeys[idx++] = BytesToUlong(rotated, 8);
            }

            // FL keys: derived from KL (128-bit) or KR (192/256-bit) with rotations
            // 6 pairs needed (for rounds 6, 12, 18)
            byte[] flSrc = (_keySizeBytes == 16) ? KL : KR;
            int[] flShifts = { 0, 30, 60, 90, 120, 150 };
            
            for (int i = 0; i < 6; i++)
            {
                byte[] rotated = RotateLeft128(flSrc, flShifts[i]);
                subKeys[idx++] = BytesToUlong(rotated, 0);
                subKeys[idx++] = BytesToUlong(rotated, 8);
            }

            return subKeys;
        }

        private byte[] Sigma(byte[] input)
        {
            // Apply S-box layer
            byte[] sOut = new byte[16];
            sOut[0] = S1[input[0]];
            sOut[1] = S2[input[1]];
            sOut[2] = S3[input[2]];
            sOut[3] = S4[input[3]];
            sOut[4] = S2[input[4]];
            sOut[5] = S3[input[5]];
            sOut[6] = S4[input[6]];
            sOut[7] = S1[input[7]];
            sOut[8] = S3[input[8]];
            sOut[9] = S4[input[9]];
            sOut[10] = S1[input[10]];
            sOut[11] = S2[input[11]];
            sOut[12] = S4[input[12]];
            sOut[13] = S1[input[13]];
            sOut[14] = S2[input[14]];
            sOut[15] = S3[input[15]];

            // Apply P layer (two 64-bit P transforms)
            byte[] output = new byte[16];
            P64(sOut, 0, output, 0);
            P64(sOut, 8, output, 8);
            return output;
        }

        private void P64(byte[] input, int inOff, byte[] output, int outOff)
        {
            byte y1 = input[inOff];
            byte y2 = input[inOff + 1];
            byte y3 = input[inOff + 2];
            byte y4 = input[inOff + 3];
            byte y5 = input[inOff + 4];
            byte y6 = input[inOff + 5];
            byte y7 = input[inOff + 6];
            byte y8 = input[inOff + 7];

            output[outOff] = (byte)(y1 ^ y3 ^ y4 ^ y6 ^ y7 ^ y8);
            output[outOff + 1] = (byte)(y1 ^ y2 ^ y4 ^ y5 ^ y7 ^ y8);
            output[outOff + 2] = (byte)(y1 ^ y2 ^ y3 ^ y6 ^ y8);
            output[outOff + 3] = (byte)(y2 ^ y3 ^ y4 ^ y5 ^ y7);
            output[outOff + 4] = (byte)(y1 ^ y3 ^ y4 ^ y5 ^ y6 ^ y8);
            output[outOff + 5] = (byte)(y1 ^ y2 ^ y4 ^ y6 ^ y7);
            output[outOff + 6] = (byte)(y1 ^ y2 ^ y3 ^ y5 ^ y7 ^ y8);
            output[outOff + 7] = (byte)(y2 ^ y3 ^ y4 ^ y6 ^ y8);
        }

        private byte[] RotateLeft128(byte[] input, int shift)
        {
            if (shift == 0) return (byte[])input.Clone();
            shift %= 128;
            
            byte[] result = new byte[16];
            int byteShift = shift / 8;
            int bitShift = shift % 8;
            
            for (int i = 0; i < 16; i++)
            {
                int srcIdx1 = (i + byteShift) % 16;
                int srcIdx2 = (i + byteShift + 1) % 16;
                
                byte b1 = input[srcIdx1];
                byte b2 = input[srcIdx2];
                
                result[i] = (byte)((b1 << bitShift) | (b2 >> (8 - bitShift)));
            }
            return result;
        }

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
    }
}

using System;

namespace Crypto.Block.Rijndael
{
    /// <summary>
    /// Galois Field arithmetic for GF(2^8).
    /// </summary>
    public sealed class GaloisField
    {
        /// <summary>
        /// Returns the degree of a polynomial in GF(2^8).
        /// </summary>
        public int Degree(byte f) => Degree((uint)f);

        /// <summary>
        /// Adds two polynomials in GF(2^8).
        /// </summary>
        public byte Add(byte a, byte b) => (byte)(a ^ b);

        /// <summary>
        /// Multiplies two polynomials in GF(2^8) modulo mod.
        /// </summary>
        public byte MulMod(byte a, byte b, ushort mod)
        {
            return (byte)MulMod((uint)a, (uint)b, mod);
        }

        /// <summary>
        /// Returns the multiplicative inverse in GF(2^8) modulo mod.
        /// </summary>
        public byte Inv(byte f, ushort mod)
        {
            return (byte)Inv((uint)f, mod);
        }

        /// <summary>
        /// Checks if a degree-8 polynomial is irreducible in GF(2^8).
        /// </summary>
        public bool Irreducible(ushort f) => Irreducible((uint)f);

        private int Degree(uint f)
        {
            if (f == 0) return -1;
            int degree = 0;
            while ((f >>= 1) > 0) degree++;
            return degree;
        }

        private uint Mul(uint a, uint b)
        {
            uint p = 0;
            for (int i = 0; i < 32; i++)
            {
                if ((b & 1) == 1) p ^= a;
                b >>= 1;
                a <<= 1;
            }
            return p;
        }

        private uint MulMod(uint a, uint b, uint mod)
        {
            var divMod = DivMod(Mul(a, b), mod);
            return divMod.remainder;
        }

        private (uint quotient, uint remainder) DivMod(uint a, uint b)
        {
            uint q = 0, r = a;
            int degB = Degree(b);

            while (Degree(r) >= degB)
            {
                int lead = Degree(r) - degB;
                q ^= 1u << lead;
                r ^= b << lead;
            }

            return (q, r);
        }

        private (uint gcd, uint a, uint b) EGcd(uint a, uint b)
        {
            uint r0 = a, r = b;
            uint s0 = 1, s = 0;
            uint t0 = 0, t = 1;

            while (r != 0)
            {
                var divMod = DivMod(r0, r);
                uint quotient = divMod.quotient;

                uint temp = r0;
                r0 = r;
                r = temp ^ Mul(quotient, r);

                temp = s0;
                s0 = s;
                s = temp ^ Mul(quotient, s);

                temp = t0;
                t0 = t;
                t = temp ^ Mul(quotient, t);
            }

            return (r0, s0, t0);
        }

        private uint Inv(uint f, uint mod)
        {
            var result = EGcd(f, mod);
            if (result.gcd != 1)
                throw new ArgumentException("Inverse element does not exist");
            return result.a;
        }

        private bool Irreducible(uint f)
        {
            int n = Degree(f);
            if (n <= 0) return false;
            if (n == 1) return true;

            const uint x = 0b10;
            int k = n;

            for (int p = 2; p * p <= k; p++)
            {
                if (k % p != 0) continue;

                uint h = Pow2Mod(x, n / p, f) ^ x;
                var g = EGcd(f, h).gcd;
                if (g != 1) return false;

                while (k % p == 0) k /= p;
            }

            if (k > 1)
            {
                uint h = Pow2Mod(x, n / k, f) ^ x;
                var g = EGcd(f, h).gcd;
                if (g != 1) return false;
            }

            return Pow2Mod(x, n, f) == x;
        }

        private uint Pow2Mod(uint f, int exp, uint mod)
        {
            uint result = f;
            for (int i = 0; i < exp; i++)
                result = MulMod(result, result, mod);
            return result;
        }
    }
}

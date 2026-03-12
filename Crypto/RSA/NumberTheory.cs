using System;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// Number theory utility functions for RSA cryptography.
    /// </summary>
    public static class NumberTheory
    {
        /// <summary>
        /// Computes the greatest common divisor of two numbers using Euclidean algorithm.
        /// </summary>
        public static BigInteger Gcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        /// <summary>
        /// Extended Euclidean algorithm. Returns [gcd, x, y] such that a*x + b*y = gcd.
        /// </summary>
        public static BigInteger[] ExtendedGcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            if (b == 0)
            {
                return new BigInteger[] { a, 1, 0 };
            }
            BigInteger[] previous = ExtendedGcd(b, a % b);
            BigInteger x = previous[2];
            BigInteger y = previous[1] - (a / b) * previous[2];
            return new BigInteger[] { previous[0], x, y };
        }

        /// <summary>
        /// Computes (base^exponent) mod modulus using binary exponentiation.
        /// </summary>
        public static BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            if (modulus == 0)
            {
                throw new ArgumentException("Modulus cannot be zero");
            }
            baseValue = BigInteger.Abs(baseValue % modulus);
            BigInteger result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                {
                    result = (result * baseValue) % modulus;
                }
                baseValue = (baseValue * baseValue) % modulus;
                exponent >>= 1;
            }
            return result;
        }

        /// <summary>
        /// Computes the modular multiplicative inverse of a modulo m.
        /// </summary>
        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 0)
            {
                throw new ArithmeticException("Modulus must not be zero");
            }

            BigInteger[] gcdResult = ExtendedGcd(a, m);
            BigInteger gcd = gcdResult[0];
            BigInteger x = gcdResult[1];

            if (gcd != 1)
            {
                throw new ArithmeticException("Inverse does not exist: gcd(a, m) != 1");
            }

            BigInteger inverse = x % m;
            if (inverse.Sign < 0)
            {
                inverse += m;
            }

            return inverse;
        }

        /// <summary>
        /// Computes the Jacobi symbol (a/n).
        /// </summary>
        public static int JacobiSymbol(BigInteger a, BigInteger n)
        {
            if (n <= 0 || n % 2 == 0 || n == 1)
            {
                throw new ArgumentException("n must be positive odd integer > 1");
            }

            if (BigInteger.GreatestCommonDivisor(a, n) != 1)
            {
                return 0;
            }

            int r = 1;

            if (a < 0)
            {
                a = -a;
                if (n % 4 == 3)
                {
                    r = -r;
                }
            }

            while (a != 0)
            {
                int t = 0;
                while (a % 2 == 0)
                {
                    t++;
                    a /= 2;
                }

                if (t % 2 != 0)
                {
                    BigInteger bMod8 = n % 8;
                    if (bMod8 == 3 || bMod8 == 5)
                    {
                        r = -r;
                    }
                }

                if (a % 4 == 3 && n % 4 == 3)
                {
                    r = -r;
                }

                BigInteger temp = a;
                a = n % temp;
                n = temp;
            }

            return r;
        }

        /// <summary>
        /// Computes the Legendre symbol (a/p) where p is prime.
        /// </summary>
        public static int LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p < 2 || !IsPrime(p))
            {
                throw new ArgumentException("p must be a positive prime");
            }

            return JacobiSymbol(a, p);
        }

        /// <summary>
        /// Checks if a number is prime using trial division.
        /// For large numbers, use probabilistic tests instead.
        /// </summary>
        public static bool IsPrime(BigInteger n)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0 || n % 3 == 0) return false;
            for (BigInteger i = 5; i * i <= n; i += 6)
            {
                if (n % i == 0 || n % (i + 2) == 0) return false;
            }
            return true;
        }

        /// <summary>
        /// Integer square root using Newton's method.
        /// </summary>
        public static BigInteger? ISqrt(BigInteger n)
        {
            if (n.Sign < 0) return null;
            if (n == 0 || n == 1) return n;

            BigInteger x0 = BigInteger.One << ((n.GetBitLength() + 1) / 2);
            BigInteger x1 = (n / x0 + x0) / 2;

            while (x1 < x0)
            {
                x0 = x1;
                x1 = (n / x0 + x0) / 2;
            }
            return x0;
        }
    }
}

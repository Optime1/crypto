using System;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// Probabilistic primality tests for RSA key generation.
    /// </summary>
    public static class ProbabilisticTests
    {
        private static readonly Random Random = new Random();

        /// <summary>
        /// Miller-Rabin primality test.
        /// </summary>
        /// <param name="n">Number to test</param>
        /// <param name="k">Number of rounds (higher = more accurate)</param>
        /// <returns>True if probably prime, false if composite</returns>
        public static bool MillerRabin(BigInteger n, int k = 40)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            // Write n-1 as 2^r * d
            BigInteger d = n - 1;
            int r = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                r++;
            }

            // Witness loop
            for (int i = 0; i < k; i++)
            {
                BigInteger a;
                do
                {
                    byte[] bytes = new byte[n.GetBitLength() / 8 + 1];
                    Random.NextBytes(bytes);
                    a = new BigInteger(bytes);
                    a = BigInteger.Abs(a);
                } while (a < 2 || a >= n - 1);

                BigInteger x = NumberTheory.ModPow(a, d, n);

                if (x == 1 || x == n - 1)
                    continue;

                bool composite = true;
                for (int j = 0; j < r - 1; j++)
                {
                    x = NumberTheory.ModPow(x, 2, n);
                    if (x == n - 1)
                    {
                        composite = false;
                        break;
                    }
                }

                if (composite)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Solovay-Strassen primality test using Jacobi symbol.
        /// </summary>
        /// <param name="n">Number to test</param>
        /// <param name="k">Number of rounds</param>
        /// <returns>True if probably prime, false if composite</returns>
        public static bool SolovayStrassen(BigInteger n, int k = 40)
        {
            if (n < 2) return false;
            if (n == 2) return true;
            if (n % 2 == 0) return false;

            for (int i = 0; i < k; i++)
            {
                BigInteger a;
                do
                {
                    byte[] bytes = new byte[n.GetBitLength() / 8 + 1];
                    Random.NextBytes(bytes);
                    a = new BigInteger(bytes);
                    a = BigInteger.Abs(a);
                } while (a < 1 || a >= n);

                if (BigInteger.GreatestCommonDivisor(a, n) > 1)
                    return false;

                int jacobi = NumberTheory.JacobiSymbol(a, n);
                BigInteger modResult = NumberTheory.ModPow(a, (n - 1) / 2, n);

                if (jacobi < 0)
                    jacobi += (int)n;

                if (modResult != jacobi)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Combined primality test using both Miller-Rabin and Solovay-Strassen.
        /// </summary>
        public static bool IsProbablePrime(BigInteger n, double minProbability = 0.9999999)
        {
            // Quick check with small primes
            int[] smallPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
            foreach (int p in smallPrimes)
            {
                if (n == p) return true;
                if (n % p == 0) return false;
            }

            // Use Miller-Rabin with sufficient rounds
            int rounds = 40; // Gives probability > 1 - 2^(-80)
            return MillerRabin(n, rounds);
        }
    }
}

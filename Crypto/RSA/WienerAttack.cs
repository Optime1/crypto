using System;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// Wiener's attack on RSA with small private exponent.
    /// This attack can recover the private key d if d < N^(1/4)/3.
    /// </summary>
    public static class WienerAttack
    {
        /// <summary>
        /// Attempts to recover the private key d using Wiener's attack.
        /// </summary>
        /// <param name="e">Public exponent</param>
        /// <param name="n">Modulus</param>
        /// <returns>The recovered private key d, or null if attack fails</returns>
        public static BigInteger? Attack(BigInteger e, BigInteger n)
        {
            // Compute continued fraction expansion of e/n
            var convergents = GetConvergents(e, n);

            foreach (var convergent in convergents)
            {
                BigInteger k = convergent.Item1;
                BigInteger d = convergent.Item2;

                if (d <= 1) continue;

                // Check if this d is valid
                // We need: e*d ≡ 1 (mod phi(N))
                // So phi(N) should divide (e*d - 1)
                
                // Try to factor N using the candidate d
                BigInteger? phi = TryRecoverPhi(n, e, d);
                if (phi.HasValue)
                {
                    // Verify by attempting to factor N
                    Tuple<BigInteger, BigInteger>? factors = FactorFromPhi(n, phi.Value);
                    if (factors != null)
                    {
                        Console.WriteLine($"Wiener's attack successful!");
                        Console.WriteLine($"Recovered d: {d}");
                        Console.WriteLine($"Factors: p={factors.Item1}, q={factors.Item2}");
                        return d;
                    }
                }
            }

            Console.WriteLine("Wiener's attack failed - key is secure against this attack");
            return null;
        }

        /// <summary>
        /// Computes convergents of the continued fraction expansion of e/n.
        /// </summary>
        private static System.Collections.Generic.List<Tuple<BigInteger, BigInteger>> GetConvergents(BigInteger e, BigInteger n)
        {
            var convergents = new System.Collections.Generic.List<Tuple<BigInteger, BigInteger>>();
            
            BigInteger[] quotients = ContinuedFractionExpansion(e, n);
            
            // h_{-2} = 0, h_{-1} = 1 (numerators)
            // k_{-2} = 1, k_{-1} = 0 (denominators)
            BigInteger hPrev2 = 0;
            BigInteger hPrev1 = 1;
            BigInteger kPrev2 = 1;
            BigInteger kPrev1 = 0;

            for (int i = 0; i < quotients.Length; i++)
            {
                BigInteger a = quotients[i];
                
                BigInteger h = a * hPrev1 + hPrev2;
                BigInteger k = a * kPrev1 + kPrev2;

                // The convergent is h/k, but we want k/d where d is the denominator
                // In Wiener's attack, we look at convergents k/d of e/n
                if (k > 0)
                {
                    convergents.Add(new Tuple<BigInteger, BigInteger>(h, k));
                }

                hPrev2 = hPrev1;
                hPrev1 = h;
                kPrev2 = kPrev1;
                kPrev1 = k;
            }

            return convergents;
        }

        /// <summary>
        /// Computes the continued fraction expansion of a/b.
        /// </summary>
        private static BigInteger[] ContinuedFractionExpansion(BigInteger a, BigInteger b)
        {
            var quotients = new System.Collections.Generic.List<BigInteger>();
            
            while (b != 0)
            {
                quotients.Add(a / b);
                BigInteger temp = a % b;
                a = b;
                b = temp;
            }

            return quotients.ToArray();
        }

        /// <summary>
        /// Attempts to recover phi(N) from candidate d.
        /// </summary>
        private static BigInteger? TryRecoverPhi(BigInteger n, BigInteger e, BigInteger d)
        {
            // e*d - 1 = k*phi(N) for some integer k
            BigInteger edMinus1 = e * d - 1;
            
            if (edMinus1 <= 0) return null;

            // Try small values of k
            for (BigInteger k = 1; k <= 2 * e; k++)
            {
                if (edMinus1 % k == 0)
                {
                    BigInteger phi = edMinus1 / k;
                    
                    // Check if phi is reasonable (close to n)
                    if (phi < n && phi > n / 2)
                    {
                        return phi;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Attempts to factor N given phi(N).
        /// </summary>
        private static Tuple<BigInteger, BigInteger>? FactorFromPhi(BigInteger n, BigInteger phi)
        {
            // We know: n = p*q and phi = (p-1)*(q-1) = p*q - p - q + 1 = n - p - q + 1
            // So: p + q = n - phi + 1
            // And: (p - q)^2 = (p + q)^2 - 4*p*q = (p + q)^2 - 4*n
            
            BigInteger sum = n - phi + 1; // p + q
            BigInteger discriminant = sum * sum - 4 * n;
            
            if (discriminant < 0) return null;
            
            BigInteger? sqrtDisc = NumberTheory.ISqrt(discriminant);
            if (!sqrtDisc.HasValue) return null;
            
            // p = (sum + sqrt(disc)) / 2, q = (sum - sqrt(disc)) / 2
            if ((sum + sqrtDisc.Value) % 2 != 0) return null;
            
            BigInteger p = (sum + sqrtDisc.Value) / 2;
            BigInteger q = (sum - sqrtDisc.Value) / 2;
            
            // Verify
            if (p * q == n && p > 1 && q > 1)
            {
                return new Tuple<BigInteger, BigInteger>(p, q);
            }
            
            return null;
        }

        /// <summary>
        /// Checks if a key pair is vulnerable to Wiener's attack.
        /// </summary>
        public static bool IsVulnerable(BigInteger d, BigInteger n)
        {
            BigInteger? nSqrt = NumberTheory.ISqrt(n);
            if (!nSqrt.HasValue) return false;
            
            BigInteger? nFourthRoot = NumberTheory.ISqrt(nSqrt.Value);
            if (!nFourthRoot.HasValue) return false;
            
            BigInteger limit = nFourthRoot.Value / 3;
            return d < limit;
        }
    }
}

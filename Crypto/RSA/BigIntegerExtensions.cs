using System;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// Extension methods for BigInteger.
    /// </summary>
    public static class BigIntegerExtensions
    {
        /// <summary>
        /// Gets the number of bits required to represent the absolute value of the number.
        /// </summary>
        public static int GetBitLength(this BigInteger value)
        {
            if (value == 0) return 0;
            
            value = BigInteger.Abs(value);
            
            // Use bit manipulation to find the position of the highest set bit
            byte[] bytes = value.ToByteArray();
            int bitLength = (bytes.Length - 1) * 8;
            
            // Count bits in the most significant byte
            byte msb = bytes[bytes.Length - 1];
            while (msb > 0)
            {
                bitLength++;
                msb >>= 1;
            }
            
            // Adjust for sign bit that ToByteArray includes
            // For positive numbers, we may have an extra zero byte at the end
            // Check if the MSB has a leading zero that shouldn't be counted
            if (bitLength > 0 && bytes[bytes.Length - 1] < 128)
            {
                // The top bit of the MSB is 0, which means we might have counted correctly
                // But if there's a trailing zero byte, we need to adjust
            }
            
            return bitLength;
        }

        /// <summary>
        /// Gets the value of a specific bit.
        /// </summary>
        public static bool GetBit(this BigInteger value, int bitIndex)
        {
            return (value & (BigInteger.One << bitIndex)) != 0;
        }
    }
}

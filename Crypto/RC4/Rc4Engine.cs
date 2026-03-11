using System;

namespace Crypto.RC4
{
    /// <summary>
    /// RC4 stream cipher engine.
    /// </summary>
    public class Rc4Engine
    {
        private readonly byte[] _s = new byte[256];
        private int _x;
        private int _y;

        /// <summary>
        /// Initializes a new instance of the RC4 engine with the specified key.
        /// </summary>
        /// <param name="key">The encryption key (1-256 bytes).</param>
        public Rc4Engine(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length == 0 || key.Length > 256)
                throw new ArgumentException("Key length must be between 1 and 256 bytes", nameof(key));

            // Initialize S-box linearly
            for (int i = 0; i < 256; i++)
                _s[i] = (byte)i;

            // Shuffle the S-box based on the key
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) & 0xFF;
                Swap(_s, i, j);
            }
        }

        /// <summary>
        /// Encrypts or decrypts a byte array.
        /// RC4 is symmetric: XOR with keystream.
        /// This method updates the internal state (x, y, S).
        /// </summary>
        /// <param name="input">Input data to process.</param>
        /// <returns>Processed output data.</returns>
        public byte[] Process(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));

            byte[] output = new byte[input.Length];

            for (int k = 0; k < input.Length; k++)
            {
                _x = (_x + 1) & 0xFF;
                _y = (_y + _s[_x]) & 0xFF;

                Swap(_s, _x, _y);

                int t = (_s[_x] + _s[_y]) & 0xFF;
                byte keyStreamByte = _s[t];

                output[k] = (byte)(input[k] ^ keyStreamByte);
            }

            return output;
        }

        private static void Swap(byte[] arr, int i, int j)
        {
            byte temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
    }
}

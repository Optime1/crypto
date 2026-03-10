using System;

namespace dora.crypto.block.tripleDes
{
    public sealed class TripleDesKeySchedule : IKeySchedule
    {
        public byte[][] RoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            byte[][] subKeys = new byte[3][];

            if (key.Length == 16) // Option 2: K1, K2, K3=K1
            {
                subKeys[0] = new byte[8];
                subKeys[1] = new byte[8];
                subKeys[2] = new byte[8];

                Array.Copy(key, 0, subKeys[0], 0, 8);
                Array.Copy(key, 8, subKeys[1], 0, 8);
                Array.Copy(subKeys[0], 0, subKeys[2], 0, 8);
            }
            else if (key.Length == 24) // Option 1: K1, K2, K3
            {
                subKeys[0] = new byte[8];
                subKeys[1] = new byte[8];
                subKeys[2] = new byte[8];

                Array.Copy(key, 0, subKeys[0], 0, 8);
                Array.Copy(key, 8, subKeys[1], 0, 8);
                Array.Copy(key, 16, subKeys[2], 0, 8);
            }
            else
            {
                throw new ArgumentException("Triple DES requires 128-bit or 192-bit key");
            }

            return subKeys;
        }
    }
}

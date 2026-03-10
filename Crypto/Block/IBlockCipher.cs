namespace Crypto.Block;

public interface IBlockCipher
{
    int BlockSize();
    void Init(byte[] key);
    byte[] Encrypt(byte[] plaintext);
    byte[] Decrypt(byte[] ciphertext);
}

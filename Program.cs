using System;
using System.Security.Cryptography;
using Crypto.Block.DES;
using Crypto.Block.TripleDES;
using Crypto.Block.DEAL;
using Crypto.Block.Rijndael;
using Crypto.Block.Camellia;
using Crypto.RC4;
using Crypto.DH;

namespace CryptoDemo;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== Криптографическая демонстрация ===\n");

        // Тест DES
        TestDes();

        // Тест Triple DES
        TestTripleDes();

        // Тест DEAL
        TestDeal();

        // Тест Rijndael (AES)
        TestRijndael();

        // Тест Camellia
        TestCamellia();

        // Тест RC4
        TestRc4();

        // Тест Diffie-Hellman
        TestDiffieHellman();

        Console.WriteLine("\n=== Демонстрация завершена ===");
    }

    static void TestDes()
    {
        Console.WriteLine("--- DES (Data Encryption Standard) ---");
        
        var cipher = new DesBlockCipher();
        byte[] key = GenerateRandomBytes(8);
        byte[] plaintext = GenerateRandomBytes(8);

        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст (hex): {BitConverter.ToString(plaintext).Replace("-", "")}");

        cipher.Init(key);
        byte[] ciphertext = cipher.Encrypt(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        byte[] decrypted = cipher.Decrypt(ciphertext);
        Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decrypted).Replace("-", "")}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestTripleDes()
    {
        Console.WriteLine("--- Triple DES ---");
        
        var cipher = new TripleDesBlockCipher();
        byte[] key = GenerateRandomBytes(24); // 192 бита
        byte[] plaintext = GenerateRandomBytes(8);

        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст (hex): {BitConverter.ToString(plaintext).Replace("-", "")}");

        cipher.Init(key);
        byte[] ciphertext = cipher.Encrypt(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        byte[] decrypted = cipher.Decrypt(ciphertext);
        Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decrypted).Replace("-", "")}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestDeal()
    {
        Console.WriteLine("--- DEAL ---");
        
        byte[] desKey = GenerateRandomBytes(8);
        var cipher = new DealBlockCipher(desKey);
        byte[] key = GenerateRandomBytes(16); // 128 бит
        byte[] plaintext = GenerateRandomBytes(16);

        Console.WriteLine($"DES ключ (hex): {BitConverter.ToString(desKey).Replace("-", "")}");
        Console.WriteLine($"Ключ DEAL (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст (hex): {BitConverter.ToString(plaintext).Replace("-", "")}");

        cipher.Init(key);
        byte[] ciphertext = cipher.Encrypt(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        byte[] decrypted = cipher.Decrypt(ciphertext);
        Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decrypted).Replace("-", "")}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestRijndael()
    {
        Console.WriteLine("--- Rijndael (AES) ---");
        
        var parameters = RijndaelParameters.Aes256();
        var cipher = new RijndaelBlockCipher(parameters);
        byte[] key = GenerateRandomBytes(32); // 256 бит
        byte[] plaintext = GenerateRandomBytes(16); // 128 бит

        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст (hex): {BitConverter.ToString(plaintext).Replace("-", "")}");

        cipher.Init(key);
        byte[] ciphertext = cipher.Encrypt(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        byte[] decrypted = cipher.Decrypt(ciphertext);
        Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decrypted).Replace("-", "")}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestCamellia()
    {
        Console.WriteLine("--- Camellia ---");
        
        var cipher = new CamelliaBlockCipher(256); // 256-bit key
        byte[] key = GenerateRandomBytes(32); // 256 бит
        byte[] plaintext = GenerateRandomBytes(16); // 128 бит

        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст (hex): {BitConverter.ToString(plaintext).Replace("-", "")}");

        cipher.Init(key);
        byte[] ciphertext = cipher.Encrypt(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        byte[] decrypted = cipher.Decrypt(ciphertext);
        Console.WriteLine($"Расшифрованный текст (hex): {BitConverter.ToString(decrypted).Replace("-", "")}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestRc4()
    {
        Console.WriteLine("--- RC4 ---");
        
        byte[] key = GenerateRandomBytes(16);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, RC4!");

        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", "")}");
        Console.WriteLine($"Открытый текст: {System.Text.Encoding.UTF8.GetString(plaintext)}");

        var engine = new Rc4Engine(key);
        byte[] ciphertext = engine.Process(plaintext);
        Console.WriteLine($"Зашифрованный текст (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

        // Создаем новый экземпляр для дешифрования (или сбрасываем состояние)
        var engine2 = new Rc4Engine(key);
        byte[] decrypted = engine2.Process(ciphertext);
        Console.WriteLine($"Расшифрованный текст: {System.Text.Encoding.UTF8.GetString(decrypted)}");

        bool success = AreEqual(plaintext, decrypted);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}\n");
    }

    static void TestDiffieHellman()
    {
        Console.WriteLine("--- Протокол Диффи-Хеллмана ---");
        
        // Стандартные параметры (RFC 2409, Group 2)
        string pHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
                      "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
                      "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
        string gHex = "02";

        BigInteger p = BigInteger.Parse(pHex, System.Globalization.NumberStyles.HexNumber);
        BigInteger g = BigInteger.Parse(gHex, System.Globalization.NumberStyles.HexNumber);

        Console.WriteLine($"Модуль p (первые 16 символов): {pHex.Substring(0, 16)}...");
        Console.WriteLine($"Генератор g: {g}");

        // Алиса и Боб создают свои пары ключей
        var alice = new DiffieHellmanProtocol(p, g);
        var bob = new DiffieHellmanProtocol(p, g);

        Console.WriteLine($"\nПубличный ключ Алисы (первые 16 символов): {alice.GetPublicKey().ToString("X").Substring(0, 16)}...");
        Console.WriteLine($"Публичный ключ Боба (первые 16 символов): {bob.GetPublicKey().ToString("X").Substring(0, 16)}...");

        // Обмен секретами
        byte[] aliceSharedKey = alice.DeriveSymmetricKey(bob.GetPublicKey());
        byte[] bobSharedKey = bob.DeriveSymmetricKey(alice.GetPublicKey());

        Console.WriteLine($"\nОбщий секрет Алисы (hex): {BitConverter.ToString(aliceSharedKey).Replace("-", "")}");
        Console.WriteLine($"Общий секрет Боба (hex): {BitConverter.ToString(bobSharedKey).Replace("-", "")}");

        bool success = AreEqual(aliceSharedKey, bobSharedKey);
        Console.WriteLine($"Результат: {(success ? "УСПЕХ - Секреты совпадают!" : "ОШИБКА")}");
        
        if (success)
        {
            Console.WriteLine("Теперь Алиса и Боб могут использовать этот ключ для симметричного шифрования.\n");
        }
    }

    static byte[] GenerateRandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return bytes;
    }

    static bool AreEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}

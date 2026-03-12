using System;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;
using Crypto.RSA;

namespace CryptoDemo
{
    /// <summary>
    /// Demonstration program for RSA algorithm implementation.
    /// Shows key generation, encryption/decryption, Wiener's attack, and file operations.
    /// </summary>
    public class RsaDemo
    {
        public static async Task RunDemoAsync()
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("RSA Algorithm Implementation Demo");
            Console.WriteLine("===========================================\n");

            // 1. Generate secure RSA keys (protected against Wiener's attack)
            await GenerateSecureKeysDemo();

            // 2. Demonstrate basic encryption/decryption
            await BasicEncryptionDemo();

            // 3. Demonstrate Wiener's attack on vulnerable keys
            await WienerAttackDemo();

            // 4. Demonstrate file encryption/decryption
            await FileEncryptionDemo();

            // 5. Demonstrate multi-threaded file encryption
            await ParallelFileEncryptionDemo();

            Console.WriteLine("\n===========================================");
            Console.WriteLine("Demo completed successfully!");
            Console.WriteLine("===========================================");
        }

        private static async Task GenerateSecureKeysDemo()
        {
            Console.WriteLine("\n--- Secure Key Generation (Protected against Wiener's Attack) ---\n");

            var keyGen = new RsaService.KeyGenerationService(
                RsaService.PrimalityTest.MillerRabin,
                0.9999999,
                512 // Using smaller key size for demo speed
            );

            Console.WriteLine("Generating RSA key pair...");
            var keyPair = keyGen.GenerateKeys();

            Console.WriteLine($"\nPublic Key (N, E):");
            Console.WriteLine($"  N = {keyPair.N}");
            Console.WriteLine($"  E = {keyPair.E}");
            Console.WriteLine($"\nPrivate Key (D):");
            Console.WriteLine($"  D = {keyPair.D}");

            // Check if key is vulnerable to Wiener's attack
            bool isVulnerable = WienerAttack.IsVulnerable(keyPair.D, keyPair.N);
            Console.WriteLine($"\nVulnerable to Wiener's Attack: {(isVulnerable ? "YES (INSECURE!)" : "NO (SECURE)")}");

            // Try Wiener's attack (should fail on secure keys)
            Console.WriteLine("\nAttempting Wiener's attack...");
            var recoveredD = WienerAttack.Attack(keyPair.E, keyPair.N);
            
            if (recoveredD.HasValue && recoveredD.Value == keyPair.D)
            {
                Console.WriteLine("WARNING: Attack succeeded! Key is vulnerable!");
            }
            else
            {
                Console.WriteLine("Attack failed - key is secure against Wiener's attack.");
            }
        }

        private static async Task BasicEncryptionDemo()
        {
            Console.WriteLine("\n--- Basic Encryption/Decryption Demo ---\n");

            // Generate keys
            var keyGen = new RsaService.KeyGenerationService(
                RsaService.PrimalityTest.MillerRabin,
                0.9999999,
                512
            );
            var keyPair = keyGen.GenerateKeys();

            // Test message
            string originalMessage = "Hello, RSA!";
            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(originalMessage);

            Console.WriteLine($"Original message: \"{originalMessage}\"");
            Console.WriteLine($"Message bytes: {BitConverter.ToString(messageBytes)}");

            // Encrypt
            byte[] encrypted = RsaService.EncryptBytes(messageBytes, keyPair.E, keyPair.N);
            Console.WriteLine($"\nEncrypted: {BitConverter.ToString(encrypted)}");

            // Decrypt
            byte[] decrypted = RsaService.DecryptBytes(encrypted, keyPair.D, keyPair.N);
            string decryptedMessage = System.Text.Encoding.UTF8.GetString(decrypted);
            Console.WriteLine($"Decrypted: \"{decryptedMessage}\"");

            Console.WriteLine($"\nEncryption successful: {originalMessage == decryptedMessage}");
        }

        private static async Task WienerAttackDemo()
        {
            Console.WriteLine("\n--- Wiener's Attack Demonstration ---\n");

            Console.WriteLine("Creating a VULNERABLE key pair (small d for demonstration)...");
            Console.WriteLine("NOTE: This is intentionally insecure for educational purposes!\n");

            // Create small primes for demo
            BigInteger p = 61;
            BigInteger q = 53;
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            // Choose a SMALL d that is vulnerable to Wiener's attack
            // For n = 3233, N^(1/4)/3 ≈ 2.5, so d = 2 would be vulnerable
            // But we need gcd(e, phi) = 1, so let's use d = 17 which gives e = 2753
            BigInteger d = 17;
            BigInteger e = NumberTheory.ModInverse(d, phi);

            Console.WriteLine($"Vulnerable key pair:");
            Console.WriteLine($"  p = {p}, q = {q}");
            Console.WriteLine($"  n = {n}");
            Console.WriteLine($"  phi = {phi}");
            Console.WriteLine($"  e = {e} (public)");
            Console.WriteLine($"  d = {d} (private - SMALL!)");

            bool isVulnerable = WienerAttack.IsVulnerable(d, n);
            Console.WriteLine($"\nVulnerable to Wiener's Attack: {(isVulnerable ? "YES" : "NO")}");

            Console.WriteLine("\nAttempting Wiener's attack on vulnerable key...");
            var recoveredD = WienerAttack.Attack(e, n);

            if (recoveredD.HasValue)
            {
                Console.WriteLine($"\n*** ATTACK SUCCESSFUL ***");
                Console.WriteLine($"Recovered private key d = {recoveredD.Value}");
                Console.WriteLine($"Original private key d = {d}");
                Console.WriteLine($"Match: {recoveredD.Value == d}");
            }
            else
            {
                Console.WriteLine("Attack failed.");
            }
        }

        private static async Task FileEncryptionDemo()
        {
            Console.WriteLine("\n--- File Encryption/Decryption Demo ---\n");

            // Generate keys
            var keyGen = new RsaService.KeyGenerationService(
                RsaService.PrimalityTest.MillerRabin,
                0.9999999,
                1024
            );
            var keyPair = keyGen.GenerateKeys();

            var encryptionService = new RsaFileEncryptionService(keyPair);

            // Create test file
            string testContent = "This is a test file for RSA encryption.\n" +
                                 "It contains multiple lines of text.\n" +
                                 "The file will be encrypted using hybrid RSA-AES encryption.\n" +
                                 DateTime.Now.ToString();

            string inputFile = Path.Combine(Path.GetTempPath(), "test_rsa_input.txt");
            string encryptedFile = Path.Combine(Path.GetTempPath(), "test_rsa_encrypted.bin");
            string decryptedFile = Path.Combine(Path.GetTempPath(), "test_rsa_decrypted.txt");

            try
            {
                // Write test file
                File.WriteAllText(inputFile, testContent);
                Console.WriteLine($"Created test file: {inputFile}");
                Console.WriteLine($"Original content length: {testContent.Length} bytes");

                // Encrypt file (async)
                Console.WriteLine("\nEncrypting file...");
                await encryptionService.EncryptFileAsync(inputFile, encryptedFile);
                Console.WriteLine($"Encrypted file created: {encryptedFile}");
                Console.WriteLine($"Encrypted file size: {new FileInfo(encryptedFile).Length} bytes");

                // Decrypt file (async)
                Console.WriteLine("\nDecrypting file...");
                await encryptionService.DecryptFileAsync(encryptedFile, decryptedFile);
                Console.WriteLine($"Decrypted file created: {decryptedFile}");

                // Verify
                string decryptedContent = File.ReadAllText(decryptedFile);
                bool success = testContent == decryptedContent;
                Console.WriteLine($"\nDecryption successful: {success}");

                if (!success)
                {
                    Console.WriteLine("ERROR: Decrypted content does not match original!");
                }
            }
            finally
            {
                // Cleanup
                try
                {
                    if (File.Exists(inputFile)) File.Delete(inputFile);
                    if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                    if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                }
                catch { }
            }
        }

        private static async Task ParallelFileEncryptionDemo()
        {
            Console.WriteLine("\n--- Multi-threaded File Encryption Demo ---\n");

            // Generate keys
            var keyGen = new RsaService.KeyGenerationService(
                RsaService.PrimalityTest.MillerRabin,
                0.9999999,
                1024
            );
            var keyPair = keyGen.GenerateKeys();

            var encryptionService = new RsaFileEncryptionService(keyPair);

            // Create larger test file
            string inputFile = Path.Combine(Path.GetTempPath(), "test_rsa_large_input.bin");
            string encryptedFile = Path.Combine(Path.GetTempPath(), "test_rsa_large_encrypted.bin");
            string decryptedFile = Path.Combine(Path.GetTempPath(), "test_rsa_large_decrypted.bin");

            try
            {
                // Create 1MB test file
                int fileSize = 1024 * 1024; // 1 MB
                byte[] testData = new byte[fileSize];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(testData);
                }
                File.WriteAllBytes(inputFile, testData);
                Console.WriteLine($"Created test file: {inputFile} ({fileSize / 1024} KB)");

                // Encrypt file in parallel
                Console.WriteLine("\nEncrypting file with multi-threading (4 threads)...");
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                await encryptionService.EncryptFileParallelAsync(inputFile, encryptedFile, 4);
                stopwatch.Stop();
                Console.WriteLine($"Encrypted file created: {encryptedFile}");
                Console.WriteLine($"Encrypted file size: {new FileInfo(encryptedFile).Length} bytes");
                Console.WriteLine($"Encryption time: {stopwatch.ElapsedMilliseconds} ms");

                // Decrypt file in parallel
                Console.WriteLine("\nDecrypting file with multi-threading...");
                stopwatch.Restart();
                await encryptionService.DecryptFileParallelAsync(encryptedFile, decryptedFile, 4);
                stopwatch.Stop();
                Console.WriteLine($"Decrypted file created: {decryptedFile}");
                Console.WriteLine($"Decryption time: {stopwatch.ElapsedMilliseconds} ms");

                // Verify
                byte[] decryptedData = File.ReadAllBytes(decryptedFile);
                bool success = testData.Length == decryptedData.Length;
                for (int i = 0; i < testData.Length && success; i++)
                {
                    if (testData[i] != decryptedData[i]) success = false;
                }
                Console.WriteLine($"\nDecryption successful: {success}");

                if (!success)
                {
                    Console.WriteLine("ERROR: Decrypted content does not match original!");
                }
            }
            finally
            {
                // Cleanup
                try
                {
                    if (File.Exists(inputFile)) File.Delete(inputFile);
                    if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                    if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                }
                catch { }
            }
        }
    }
}

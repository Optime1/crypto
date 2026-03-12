using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// RSA file encryption service with async and multi-threaded support.
    /// Uses hybrid encryption: RSA for key exchange, AES for bulk data encryption.
    /// </summary>
    public class RsaFileEncryptionService
    {
        private readonly RsaService.KeyPair _keyPair;
        private const int ChunkSize = 1024; // Maximum bytes per RSA chunk
        private const int AesKeySize = 256; // AES-256

        public RsaFileEncryptionService(RsaService.KeyPair keyPair)
        {
            _keyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
        }

        /// <summary>
        /// Encrypts a file asynchronously using hybrid encryption (RSA + AES).
        /// </summary>
        public async Task EncryptFileAsync(string inputPath, string outputPath)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            await Task.Run(() => EncryptFile(inputPath, outputPath));
        }

        /// <summary>
        /// Decrypts a file asynchronously using hybrid encryption (RSA + AES).
        /// </summary>
        public async Task DecryptFileAsync(string inputPath, string outputPath)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            await Task.Run(() => DecryptFile(inputPath, outputPath));
        }

        /// <summary>
        /// Encrypts a file using hybrid encryption (RSA + AES).
        /// </summary>
        public void EncryptFile(string inputPath, string outputPath)
        {
            using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                // Generate random AES key and IV
                byte[] aesKey = new byte[AesKeySize / 8];
                byte[] iv = new byte[16];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(aesKey);
                    rng.GetBytes(iv);
                }

                // Encrypt AES key with RSA
                byte[] encryptedAesKey = RsaService.EncryptBytes(aesKey, _keyPair.E, _keyPair.N);

                // Write encrypted key length and key to output
                WriteInt32(outputStream, encryptedAesKey.Length);
                outputStream.Write(encryptedAesKey, 0, encryptedAesKey.Length);

                // Write IV
                outputStream.Write(iv, 0, iv.Length);

                // Write file size
                WriteInt64(outputStream, inputStream.Length);

                // Encrypt file content with AES in chunks
                using (var aes = System.Security.Cryptography.Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                    aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

                    using (var cryptoStream = new System.Security.Cryptography.CryptoStream(
                        outputStream, aes.CreateEncryptor(), System.Security.Cryptography.CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a file using hybrid encryption (RSA + AES).
        /// </summary>
        public void DecryptFile(string inputPath, string outputPath)
        {
            using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                // Read encrypted AES key
                int encryptedKeyLength = ReadInt32(inputStream);
                byte[] encryptedAesKey = new byte[encryptedKeyLength];
                if (inputStream.Read(encryptedAesKey, 0, encryptedKeyLength) != encryptedKeyLength)
                    throw new InvalidDataException("Invalid encrypted file format");

                // Decrypt AES key with RSA
                byte[] aesKey = RsaService.DecryptBytes(encryptedAesKey, _keyPair.D, _keyPair.N);

                // Read IV
                byte[] iv = new byte[16];
                if (inputStream.Read(iv, 0, iv.Length) != iv.Length)
                    throw new InvalidDataException("Invalid encrypted file format");

                // Read original file size
                long fileSize = ReadInt64(inputStream);

                // Decrypt file content with AES
                using (var aes = System.Security.Cryptography.Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                    aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

                    using (var cryptoStream = new System.Security.Cryptography.CryptoStream(
                        inputStream, aes.CreateDecryptor(), System.Security.Cryptography.CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts a file using pure RSA (for small files only).
        /// Not recommended for large files due to RSA limitations.
        /// </summary>
        public void EncryptFilePureRsa(string inputPath, string outputPath)
        {
            byte[] fileContent = File.ReadAllBytes(inputPath);
            
            int modulusByteLength = (_keyPair.N.GetBitLength() + 7) / 8;
            int maxChunkSize = modulusByteLength - 11; // PKCS#1 v1.5 padding overhead

            if (fileContent.Length > maxChunkSize * 1000)
            {
                throw new InvalidOperationException("File too large for pure RSA encryption. Use hybrid encryption.");
            }

            using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                // Write number of chunks
                int numChunks = (fileContent.Length + maxChunkSize - 1) / maxChunkSize;
                WriteInt32(outputStream, numChunks);

                // Encrypt each chunk
                for (int i = 0; i < fileContent.Length; i += maxChunkSize)
                {
                    int chunkSize = Math.Min(maxChunkSize, fileContent.Length - i);
                    byte[] chunk = new byte[chunkSize];
                    Array.Copy(fileContent, i, chunk, 0, chunkSize);

                    byte[] encryptedChunk = RsaService.EncryptBytes(chunk, _keyPair.E, _keyPair.N);
                    
                    // Write chunk length and encrypted data
                    WriteInt32(outputStream, encryptedChunk.Length);
                    outputStream.Write(encryptedChunk, 0, encryptedChunk.Length);
                }
            }
        }

        /// <summary>
        /// Decrypts a file using pure RSA.
        /// </summary>
        public void DecryptFilePureRsa(string inputPath, string outputPath)
        {
            using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new MemoryStream())
            {
                // Read number of chunks
                int numChunks = ReadInt32(inputStream);

                // Decrypt each chunk
                for (int i = 0; i < numChunks; i++)
                {
                    int chunkLength = ReadInt32(inputStream);
                    byte[] encryptedChunk = new byte[chunkLength];
                    if (inputStream.Read(encryptedChunk, 0, chunkLength) != chunkLength)
                        throw new InvalidDataException("Invalid encrypted file format");

                    byte[] decryptedChunk = RsaService.DecryptBytes(encryptedChunk, _keyPair.D, _keyPair.N);
                    outputStream.Write(decryptedChunk, 0, decryptedChunk.Length);
                }

                File.WriteAllBytes(outputPath, outputStream.ToArray());
            }
        }

        /// <summary>
        /// Multi-threaded file encryption for large files.
        /// Divides the file into blocks and encrypts them in parallel.
        /// </summary>
        public async Task EncryptFileParallelAsync(string inputPath, string outputPath, int degreeOfParallelism = 4)
        {
            await Task.Run(() => EncryptFileParallel(inputPath, outputPath, degreeOfParallelism));
        }

        /// <summary>
        /// Multi-threaded file encryption for large files.
        /// </summary>
        public void EncryptFileParallel(string inputPath, string outputPath, int degreeOfParallelism = 4)
        {
            // Generate random AES key and IV
            byte[] aesKey = new byte[AesKeySize / 8];
            byte[] iv = new byte[16];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(aesKey);
                rng.GetBytes(iv);
            }

            // Encrypt AES key with RSA
            byte[] encryptedAesKey = RsaService.EncryptBytes(aesKey, _keyPair.E, _keyPair.N);

            // Read entire file into memory (for parallel processing)
            byte[] fileContent = File.ReadAllBytes(inputPath);
            long fileSize = fileContent.Length;

            // Divide file into blocks for parallel encryption
            int blockCount = degreeOfParallelism;
            long blockSize = (fileSize + blockCount - 1) / blockCount;

            var encryptedBlocks = new byte[blockCount][];
            var blockSizes = new int[blockCount];

            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = aesKey;
                aes.IV = iv;
                aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                aes.Padding = System.Security.Cryptography.PaddingMode.None; // Manual padding

                Parallel.For(0, blockCount, i =>
                {
                    long start = i * blockSize;
                    long end = Math.Min(start + blockSize, fileSize);
                    int size = (int)(end - start);

                    if (size == 0)
                    {
                        encryptedBlocks[i] = new byte[0];
                        blockSizes[i] = 0;
                        return;
                    }

                    byte[] block = new byte[size];
                    Array.Copy(fileContent, start, block, 0, size);

                    // Pad the last block if necessary
                    int paddedSize = ((size + 15) / 16) * 16;
                    byte[] paddedBlock = new byte[paddedSize];
                    Array.Copy(block, paddedBlock, size);
                    
                    // PKCS7 padding
                    byte paddingValue = (byte)(paddedSize - size);
                    for (int j = size; j < paddedSize; j++)
                    {
                        paddedBlock[j] = paddingValue;
                    }

                    using (var aesEncryptor = aes.CreateEncryptor())
                    {
                        encryptedBlocks[i] = aesEncryptor.TransformFinalBlock(paddedBlock, 0, paddedBlock.Length);
                    }
                    blockSizes[i] = encryptedBlocks[i].Length;
                });
            }

            // Write encrypted file
            using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                // Write metadata
                WriteInt32(outputStream, encryptedAesKey.Length);
                outputStream.Write(encryptedAesKey, 0, encryptedAesKey.Length);
                outputStream.Write(iv, 0, iv.Length);
                WriteInt64(outputStream, fileSize);
                WriteInt32(outputStream, blockCount);

                // Write block sizes
                foreach (int blockSize in blockSizes)
                {
                    WriteInt32(outputStream, blockSize);
                }

                // Write encrypted blocks
                foreach (byte[] block in encryptedBlocks)
                {
                    outputStream.Write(block, 0, block.Length);
                }
            }
        }

        /// <summary>
        /// Multi-threaded file decryption.
        /// </summary>
        public async Task DecryptFileParallelAsync(string inputPath, string outputPath, int degreeOfParallelism = 4)
        {
            await Task.Run(() => DecryptFileParallel(inputPath, outputPath, degreeOfParallelism));
        }

        /// <summary>
        /// Multi-threaded file decryption.
        /// </summary>
        public void DecryptFileParallel(string inputPath, string outputPath, int degreeOfParallelism = 4)
        {
            using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            {
                // Read metadata
                int encryptedKeyLength = ReadInt32(inputStream);
                byte[] encryptedAesKey = new byte[encryptedKeyLength];
                if (inputStream.Read(encryptedAesKey, 0, encryptedKeyLength) != encryptedKeyLength)
                    throw new InvalidDataException("Invalid encrypted file format");

                byte[] aesKey = RsaService.DecryptBytes(encryptedAesKey, _keyPair.D, _keyPair.N);

                byte[] iv = new byte[16];
                if (inputStream.Read(iv, 0, iv.Length) != iv.Length)
                    throw new InvalidDataException("Invalid encrypted file format");

                long fileSize = ReadInt64(inputStream);
                int blockCount = ReadInt32(inputStream);

                int[] blockSizes = new int[blockCount];
                for (int i = 0; i < blockCount; i++)
                {
                    blockSizes[i] = ReadInt32(inputStream);
                }

                // Read all encrypted blocks
                byte[][] encryptedBlocks = new byte[blockCount][];
                for (int i = 0; i < blockCount; i++)
                {
                    encryptedBlocks[i] = new byte[blockSizes[i]];
                    if (inputStream.Read(encryptedBlocks[i], 0, blockSizes[i]) != blockSizes[i])
                        throw new InvalidDataException("Invalid encrypted file format");
                }

                // Decrypt blocks in parallel
                byte[][] decryptedBlocks = new byte[blockCount][];

                using (var aes = System.Security.Cryptography.Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                    aes.Padding = System.Security.Cryptography.PaddingMode.None;

                    Parallel.For(0, blockCount, i =>
                    {
                        using (var aesDecryptor = aes.CreateDecryptor())
                        {
                            decryptedBlocks[i] = aesDecryptor.TransformFinalBlock(encryptedBlocks[i], 0, encryptedBlocks[i].Length);
                        }
                    });
                }

                // Combine decrypted blocks and remove padding
                using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                {
                    long totalWritten = 0;
                    for (int i = 0; i < blockCount; i++)
                    {
                        int writeSize = decryptedBlocks[i].Length;
                        
                        // Remove PKCS7 padding from the last block
                        if (i == blockCount - 1 && totalWritten + writeSize > fileSize)
                        {
                            int actualSize = (int)(fileSize - totalWritten);
                            outputStream.Write(decryptedBlocks[i], 0, actualSize);
                        }
                        else
                        {
                            outputStream.Write(decryptedBlocks[i], 0, writeSize);
                        }
                        
                        totalWritten += writeSize;
                    }
                }
            }
        }

        private static void WriteInt32(Stream stream, int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        private static int ReadInt32(Stream stream)
        {
            byte[] bytes = new byte[4];
            if (stream.Read(bytes, 0, 4) != 4)
                throw new InvalidDataException("Unexpected end of stream");
            return BitConverter.ToInt32(bytes, 0);
        }

        private static void WriteInt64(Stream stream, long value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        private static long ReadInt64(Stream stream)
        {
            byte[] bytes = new byte[8];
            if (stream.Read(bytes, 0, 8) != 8)
                throw new InvalidDataException("Unexpected end of stream");
            return BitConverter.ToInt64(bytes, 0);
        }
    }
}

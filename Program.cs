using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string original = "Dados Sensiveis do Banco Digital";

        byte[] key = GenerateRandomKey();
        byte[] iv = GenerateRandomIV();

        byte[] encrypted = EncryptStringToBytes_Aes(original, key, iv);
        Console.WriteLine("Dados criptografados: " + Convert.ToBase64String(encrypted));

        string decrypted = DecryptStringFromBytes_Aes(encrypted, key, iv);
        Console.WriteLine("Dados descriptografados: " + decrypted);
    }

    static byte[] GenerateRandomKey()
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.GenerateKey();
            return aesAlg.Key;
        }
    }

    static byte[] GenerateRandomIV()
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.GenerateIV();
            return aesAlg.IV;
        }
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] IV)
    {
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException(nameof(plainText));
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        byte[] encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException(nameof(cipherText));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        string plaintext = null;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }
}

using EncryptionDecryptionUsingSymmetricKey;

internal class Program
{
    private static void Main(string[] args)
    {
        var key = "b14ca5898a4e4133bbce2ea2315a1916";
        //var key = "P455W0rd";

        //Console.WriteLine("Please enter a secret key for the symmetric algorithm.");
        //var key = Console.ReadLine();

        Console.WriteLine("Please enter a string for encryption");
        var str = Console.ReadLine();
        var encryptedString = AesOperation.EncryptString(key, str);
        Console.WriteLine($"AesOperation encrypted string = {encryptedString}");

        var decryptedString = AesOperation.DecryptString(key, encryptedString);
        Console.WriteLine($"AesOperation decrypted string = {decryptedString}");

        var securityManagerEncryp = SecurityManager.Encrypt(str);
        Console.WriteLine($"SecurityManager encrypted string = {securityManagerEncryp}");

        var securityManagerDecryp = SecurityManager.Decrypt(securityManagerEncryp);
        Console.WriteLine($"SecurityManager decrypted string = {securityManagerDecryp}");

        var securityManagerEncryp1 = AESEncryption.Encrypt(str,key);
        Console.WriteLine($"AESEncryption encrypted string = {securityManagerEncryp1}");

        var securityManagerDecryp1 = AESEncryption.Decrypt(securityManagerEncryp1, key);
        Console.WriteLine($"AESEncryption decrypted string = {securityManagerDecryp1}");

        var securityManagerEncryp2 = AES.EncryptText(str, key);
        Console.WriteLine($"AES encrypted string = {securityManagerEncryp2}");

        var securityManagerDecryp2 = AES.DecryptText(securityManagerEncryp2, key);
        Console.WriteLine($"AES decrypted string = {securityManagerDecryp2}");

        var securityManagerEncryp3 = AES.PBKDF2_CreateHash(str);
        Console.WriteLine($"AES encrypted string = {securityManagerEncryp3}");

        var securityManagerDecryp3 = AES.PBKDF2_ValidatePassword(str, securityManagerEncryp3);
        Console.WriteLine($"AES decrypted string = {securityManagerDecryp3}");

        Console.ReadKey();
    }
}
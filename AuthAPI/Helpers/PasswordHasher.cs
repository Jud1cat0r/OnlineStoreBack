using System.Drawing;
using System.Security.Cryptography;

namespace AuthAPI.Helpers
{
    public class PasswordHasher
    {
        private static readonly int saltSize = 16;
        private static readonly int hashSize = 20;
        private static readonly int iterations = 10000;
        //шифрование пароля
        public static string HashPassword(string password)
        {
            byte[] salt = GenerateSalt();
            var key = new Rfc2898DeriveBytes(password, salt, iterations);
            var hash = key.GetBytes(hashSize);

            var hashBytes = new byte[saltSize + hashSize];
            Array.Copy(salt, 0, hashBytes, 0, saltSize);
            Array.Copy(hash, 0, hashBytes, saltSize, hashSize);

            var base64Hash = Convert.ToBase64String(hashBytes);
            return base64Hash;
        }
        //генерация salt
        private static byte[] GenerateSalt()
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var salt = new byte[saltSize];
                generator.GetBytes(salt);
                return salt;
            }
        }
        //проверка пароля
        public static bool VerifyPassword(string password, string base64Hash)
        {
            var hashBytes = Convert.FromBase64String(base64Hash);

            var salt = new byte[saltSize];
            Array.Copy(hashBytes, 0, salt, 0, saltSize);

            var key = new Rfc2898DeriveBytes(password, salt, iterations);
            byte[] hash = key.GetBytes(hashSize);

            for (int i = 0; i < hashSize; i++)
            {
                if (hashBytes[i + saltSize] != hash[i])
                    return false;
            }
            return true;
        }
    }
}

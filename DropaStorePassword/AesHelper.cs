using System.Security.Cryptography;
using System.Text;

namespace DropaStorePassword
{
    public static class AesHelper
    {
        private const string IV = "2wDwCbJtSVuTlXhL";
        //private const string KEYExt = "OZMd2MfM6YuoFNLXM50FpJdjX0R926GF";

        public static string Encrypt(this string data, string KEY)
        {
            KEY = KEY.Replace("-", "");
            byte[]? buffer = null;

            Aes aes = Aes.Create();
            aes.IV = Encoding.UTF8.GetBytes(IV);
            aes.Key = Encoding.UTF8.GetBytes(KEY);

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(data);
                    }
                }
                buffer = ms.ToArray();
            }
            return Convert.ToBase64String(buffer);
        }

        public static string Decrypt(this string data, string KEY)
        {
            if (data == null) return "";
            KEY = KEY.Replace("-", "");
            byte[] buffer = Convert.FromBase64String(data);
            string result = "";

            Aes aes = Aes.Create();
            aes.IV = Encoding.UTF8.GetBytes(IV);
            aes.Key = Encoding.UTF8.GetBytes(KEY);

            ICryptoTransform encryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream(buffer))
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        result = sr.ReadToEnd();
                    }
                }
            }

            return result;
        }
    }

    public static class Extensions
    {
        public static string GetIdClaim(this System.Security.Claims.ClaimsPrincipal _user)
        {
            var id = _user.Claims.FirstOrDefault(a => a.Type == "ID")?.Value;
            try
            {
                if (id == null)
                {
                    id = _user.Claims.FirstOrDefault(a => a.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
                }
                if (id == null)
                {
                    id = _user.Claims.FirstOrDefault(x => x.Type == "Id")?.Value;
                }
                if (id == null)
                {
                    var _id = _user.Claims.ToList()[0].Value;
                    if (_id != null) id = _id;
                }
                if (id == null)
                {
                    id = string.Empty;
                }
            }
            catch
            {
                id = string.Empty;
            }
            return id;
        }
    }
}

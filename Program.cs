using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
namespace YinxiangbijiConverter
{
    internal sealed class Program
    {
        private static byte[] AesDecrypt(byte[] data, byte[] iv, byte[] key)
        {
            var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.Key = key;
            return aes.DecryptCbc(data, iv);

        }

        private static int mDecryptCount;
        private static readonly byte[] HmacKey = Encoding.ASCII.GetBytes("{22C58AC3-F1C7-4D96-8B88-5E4BBF505817}");
        private static bool Equals(byte[] data1, byte[] data2)
        {
            int length = data1.Length;
            if (length != data2.Length)
                return false;
            for (int i = 0; i < length; i++)
                if (data1[i] != data2[i])
                    return false;
            return true;
        }
        
        private static Task<byte[]> GenerateKeyAsync(byte[] nonce, byte[] hmacKey)
        {
            return Task.Run(() =>
            {
                var key = new byte[16];
                for (int i = 0; i < 50000; i++)
                {
                    nonce = HMACSHA256.HashData(hmacKey, nonce);
                    for (int j = 0; j < 16; j++)
                        key[j] ^= nonce[j];
                }
                return key;
            });
        }

        private async static Task DecryptNoteAsync(XmlElement noteElement)
        {
            var title = (noteElement.GetElementsByTagName("title")[0] as XmlElement)?.InnerText;
            var content = noteElement.GetElementsByTagName("content")[0] as XmlElement;
            var contentEncoding = content?.GetAttribute("encoding");
            if (content == null || contentEncoding != "base64:aes") return;
            var data = Convert.FromBase64String(content.InnerText);
            using var br = new BinaryReader(new MemoryStream(data));
            var signature = Encoding.ASCII.GetString(br.ReadBytes(4));
            if (signature != "ENC0")
                throw new Exception("Signature verify failed");
            var nonce1 = new byte[20];
            br.Read(nonce1, 0, 16);
            nonce1[19] = 1;
            var nonce2 = new byte[20];
            br.Read(nonce2, 0, 16);
            nonce2[19] = 1;
            var iv = br.ReadBytes(16);
            var getKey1Task =  GenerateKeyAsync(nonce1, HmacKey);
            var getKey2Task =  GenerateKeyAsync(nonce2, HmacKey);
            var encryptedData = br.ReadBytes(data.Length - 4 - 16 * 5);
            var hash = br.ReadBytes(32);
            if (!Equals(HMACSHA256.HashData(await getKey2Task, new ReadOnlySpan<byte>(data, 0, data.Length - 32)), hash))
                throw new Exception("Hash verify failed");
            var decryptedData = AesDecrypt(encryptedData, iv, await getKey1Task);
            var decryptedText = Encoding.UTF8.GetString(new ReadOnlySpan<byte>(decryptedData, 0, decryptedData.Length - 1));
            content.RemoveAttribute("encoding");
            content.InnerXml = $"<![CDATA[{decryptedText}]]>";
            mDecryptCount++;
            Console.WriteLine($"Note {title} decrypted");
        }


        public async static Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                var program = Path.GetFileName(Environment.ProcessPath)!;
                Console.WriteLine($"Usage: {program} path");
                Console.WriteLine($"Example: {program} test.notes");
                return;
            }
            mDecryptCount = 0;
            string path =args[0];
            if (!File.Exists(path))
            {
                Console.WriteLine($"file \"{path}\" not exist");
                return;
            }
            var sw = Stopwatch.StartNew();
            var doc = new XmlDocument();
            Console.WriteLine("Loading " + path);
            doc.Load(File.OpenRead(path));
            var noteList = doc.DocumentElement?.GetElementsByTagName("note");
            if (noteList == null) return;
            int totalCount = noteList.Count;
            Console.WriteLine($"{totalCount} notes found");
            Console.WriteLine("Starting decryping");
            var taskList =new Task[totalCount];
            for(int i = 0; i < totalCount; i++)
            {
                var noteElement= (XmlElement)noteList[i]!;
                taskList[i]=DecryptNoteAsync(noteElement);
            }
            await Task.WhenAll(taskList);
            sw.Stop();
            Console.WriteLine($"{mDecryptCount} notes decrypted,{totalCount} notes in total,{sw.ElapsedMilliseconds}ms passed.");
            string savePath = Path.ChangeExtension(path, "enex");
            doc.Save(savePath);
            Console.WriteLine("File has been saved to " + savePath);
        }
    }
}

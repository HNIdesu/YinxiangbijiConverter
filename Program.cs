﻿using System.Collections.Concurrent;
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

        private static byte[] DecryptNote(byte[] data)
        {
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
            var hmacKey = Encoding.ASCII.GetBytes("{22C58AC3-F1C7-4D96-8B88-5E4BBF505817}");
            var key1 = new byte[16];
            var key2 = new byte[16];
            var nonce = nonce1;
            for (int i = 0; i < 50000; i++)
            {
                nonce = HMACSHA256.HashData(hmacKey, nonce);
                for (int j = 0; j < 16; j++)
                    key1[j] ^= nonce[j];
            }
            nonce = nonce2;
            for (int i = 0; i < 50000; i++)
            {
                nonce = HMACSHA256.HashData(hmacKey, nonce);
                for (int j = 0; j < 16; j++)
                    key2[j] ^= nonce[j];
            }
            var encryptedData = br.ReadBytes(data.Length - 4 - 16 * 5);
            var hash = br.ReadBytes(32);
            if (!Equals(HMACSHA256.HashData(key2, data.SkipLast(32).ToArray()), hash))
                throw new Exception("Hash verify failed");
            return AesDecrypt(encryptedData, iv, key1);
        }

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                var program = Path.GetFileName(Environment.ProcessPath)!;
                Console.WriteLine($"Usage: {program} path");
                Console.WriteLine($"Example: {program} test.notes");
                return;
            }
            string path =args[0];
            if (!File.Exists(path))
            {
                Console.WriteLine($"file \"{path}\" not exist");
                return;
            }
            var sw = Stopwatch.StartNew();
            var doc = new XmlDocument();
            Console.WriteLine("loading " + path);
            doc.Load(File.OpenRead(path));
            var noteList = doc.DocumentElement?.GetElementsByTagName("note");
            if (noteList == null) return;
            int totalCount = noteList.Count;
            Console.WriteLine($"{totalCount} notes found");
            var decryptResultDict = new ConcurrentDictionary<XmlElement, string>();
            Console.WriteLine("starting decryping");
            Parallel.For(0, totalCount, i =>
            {
                var note = noteList[i] as XmlElement;
                var title = (note?.GetElementsByTagName("title")[0] as XmlElement)?.InnerText;
                var content = note?.GetElementsByTagName("content")[0] as XmlElement;
                var contentEncoding = content?.GetAttribute("encoding");
                if (content == null) return;
                if (contentEncoding == "base64:aes")
                {
                    var contentData = Convert.FromBase64String(content.InnerText);
                    try
                    {
                        var decryptedData = DecryptNote(contentData);
                        var decryptedText = Encoding.UTF8.GetString(new ReadOnlySpan<byte>(decryptedData, 0, decryptedData.Length - 1));
                        decryptResultDict[content] = $"<![CDATA[{decryptedText}]]>";//Length - 1是为了移除最后一个空字符
                        Console.WriteLine($"note {title} decrypted");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                        
                }
            });
            sw.Stop();
            Console.WriteLine($"{decryptResultDict.Count} notes decrypted,{totalCount} notes in total,{sw.ElapsedMilliseconds}ms passed.");
            Console.WriteLine("saving notes ...");
            foreach (var pair in decryptResultDict)
            {
                var content = pair.Key;
                content.RemoveAttribute("encoding");
                content.InnerXml = pair.Value;
            }
            string savePath = Path.ChangeExtension(path, "enex");
            doc.Save(savePath);
            Console.WriteLine("file has been saved to " + savePath);
            
        }
    }
}

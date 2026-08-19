using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace PdfPasswordRecovery
{
    internal enum PasswordVaultStorageMode
    {
        PlaintextJson,
        Aes256
    }

    internal sealed class PasswordVaultStorage : IDisposable
    {
        private const string JsonFormat = "PdfPasswordRecovery.PasswordVault";
        private const int JsonSchemaVersion = 2;
        private const int AesContainerVersion = 1;
        private const int Pbkdf2Iterations = 600000;
        private const int SaltLength = 16;
        private const int IvLength = 16;
        private const int TagLength = 32;
        private const int KeyLength = 32;
        private const int MaximumFileBytes = 16 * 1024 * 1024;
        private const int MaximumRecords = 100000;

        private static readonly byte[] AesMagic = Encoding.ASCII.GetBytes("PDFVAES1");
        private static readonly byte[] LegacyMagic = Encoding.ASCII.GetBytes("PDFVAULT");
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private byte[] passwordBytes;
        private byte[] salt;
        private byte[] aesKey;
        private byte[] macKey;
        private bool disposed;

        public PasswordVaultStorageMode Mode { get; private set; }

        public PasswordVaultStorage(PasswordVaultStorageMode mode, string password)
        {
            Mode = mode;
            if (mode == PasswordVaultStorageMode.Aes256)
            {
                if (String.IsNullOrEmpty(password))
                    throw new ArgumentException("AES-256 密码库密码不能为空。", "password");
                try
                {
                    passwordBytes = StrictUtf8.GetBytes(password);
                }
                catch (EncoderFallbackException exception)
                {
                    throw new ArgumentException("AES-256 密码库密码包含无效字符。", "password", exception);
                }
            }
            else if (mode != PasswordVaultStorageMode.PlaintextJson)
            {
                throw new ArgumentOutOfRangeException("mode");
            }
        }

        public byte[] Encode(List<PasswordRecord> records)
        {
            ThrowIfDisposed();
            byte[] json = SerializeJson(records);
            try
            {
                if (Mode == PasswordVaultStorageMode.PlaintextJson) return (byte[])json.Clone();
                return Encrypt(json);
            }
            finally
            {
                ClearBytes(json);
            }
        }

        public List<PasswordRecord> Decode(byte[] fileBytes)
        {
            ThrowIfDisposed();
            if (fileBytes == null || fileBytes.Length == 0 || fileBytes.Length > MaximumFileBytes)
                throw new PasswordVaultException("密码库文件为空、无效或超过 16 MiB 上限。");

            if (StartsWith(fileBytes, LegacyMagic))
                throw new PasswordVaultException(
                    "这是旧版 Windows DPAPI 密码库。当前版本不会自动解密或覆盖它，请选择新的 JSON 或 AES-256 密码库文件。");

            if (Mode == PasswordVaultStorageMode.PlaintextJson)
            {
                if (StartsWith(fileBytes, AesMagic))
                    throw new PasswordVaultException("所选文件是 AES-256 密码库，请改用 AES-256 模式打开。");
                return DeserializeJson(fileBytes);
            }

            if (!StartsWith(fileBytes, AesMagic))
                throw new PasswordVaultException("所选文件不是 AES-256 密码库，请检查存储方式和文件路径。");

            byte[] json = Decrypt(fileBytes);
            try
            {
                return DeserializeJson(json);
            }
            finally
            {
                ClearBytes(json);
            }
        }

        private byte[] Encrypt(byte[] plaintext)
        {
            EnsureKeysForNewFile();
            byte[] iv = new byte[IvLength];
            byte[] ciphertext = null;
            byte[] authenticated = null;
            byte[] tag = null;
            try
            {
                FillRandom(iv);
                using (Aes algorithm = Aes.Create())
                {
                    algorithm.KeySize = 256;
                    algorithm.BlockSize = 128;
                    algorithm.Mode = CipherMode.CBC;
                    algorithm.Padding = PaddingMode.PKCS7;
                    algorithm.Key = aesKey;
                    algorithm.IV = iv;
                    using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
                        ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }

                if (ciphertext.Length <= 0 || ciphertext.Length > MaximumFileBytes ||
                    (ciphertext.Length % IvLength) != 0)
                    throw new PasswordVaultException("AES-256 密码库密文长度无效。");

                using (MemoryStream stream = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
                {
                    writer.Write(AesMagic);
                    writer.Write(AesContainerVersion);
                    writer.Write(Pbkdf2Iterations);
                    writer.Write(SaltLength);
                    writer.Write(IvLength);
                    writer.Write(ciphertext.Length);
                    writer.Write(salt);
                    writer.Write(iv);
                    writer.Write(ciphertext);
                    writer.Flush();
                    authenticated = stream.ToArray();
                }

                using (HMACSHA256 hmac = new HMACSHA256(macKey)) tag = hmac.ComputeHash(authenticated);
                if (authenticated.Length + tag.Length > MaximumFileBytes)
                    throw new PasswordVaultException("AES-256 密码库超过 16 MiB 上限。");

                byte[] result = new byte[authenticated.Length + tag.Length];
                Buffer.BlockCopy(authenticated, 0, result, 0, authenticated.Length);
                Buffer.BlockCopy(tag, 0, result, authenticated.Length, tag.Length);
                return result;
            }
            catch (CryptographicException exception)
            {
                throw new PasswordVaultException("AES-256 密码库加密失败。", exception);
            }
            finally
            {
                ClearBytes(iv);
                ClearBytes(ciphertext);
                ClearBytes(authenticated);
                ClearBytes(tag);
            }
        }

        private byte[] Decrypt(byte[] container)
        {
            byte[] parsedSalt = null;
            byte[] iv = null;
            byte[] ciphertext = null;
            byte[] expectedTag = null;
            byte[] actualTag = null;
            try
            {
                int authenticatedLength = container.Length - TagLength;
                if (authenticatedLength <= AesMagic.Length + 20)
                    throw new PasswordVaultException("AES-256 密码库文件已截断。");

                using (MemoryStream stream = new MemoryStream(container, false))
                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
                {
                    RequireMagic(ReadExact(reader, AesMagic.Length), AesMagic);
                    int version = reader.ReadInt32();
                    int iterations = reader.ReadInt32();
                    int saltLength = reader.ReadInt32();
                    int ivLength = reader.ReadInt32();
                    int ciphertextLength = reader.ReadInt32();
                    if (version != AesContainerVersion)
                        throw new PasswordVaultException("AES-256 密码库版本不受支持。");
                    if (iterations != Pbkdf2Iterations || saltLength != SaltLength || ivLength != IvLength)
                        throw new PasswordVaultException("AES-256 密码库密钥派生参数无效或不受支持。");
                    if (ciphertextLength <= 0 || ciphertextLength > MaximumFileBytes ||
                        (ciphertextLength % IvLength) != 0)
                        throw new PasswordVaultException("AES-256 密码库密文长度无效。");

                    long expectedLength = stream.Position + saltLength + ivLength + ciphertextLength + TagLength;
                    if (expectedLength != stream.Length)
                        throw new PasswordVaultException("AES-256 密码库长度无效或包含多余数据。");

                    parsedSalt = ReadExact(reader, saltLength);
                    iv = ReadExact(reader, ivLength);
                    ciphertext = ReadExact(reader, ciphertextLength);
                    expectedTag = ReadExact(reader, TagLength);
                }

                EnsureKeys(parsedSalt);
                using (HMACSHA256 hmac = new HMACSHA256(macKey))
                    actualTag = hmac.ComputeHash(container, 0, authenticatedLength);
                if (!FixedTimeEquals(actualTag, expectedTag))
                    throw new PasswordVaultException("AES-256 密码库密码错误或文件已损坏。");

                try
                {
                    using (Aes algorithm = Aes.Create())
                    {
                        algorithm.KeySize = 256;
                        algorithm.BlockSize = 128;
                        algorithm.Mode = CipherMode.CBC;
                        algorithm.Padding = PaddingMode.PKCS7;
                        algorithm.Key = aesKey;
                        algorithm.IV = iv;
                        using (ICryptoTransform decryptor = algorithm.CreateDecryptor())
                            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    }
                }
                catch (CryptographicException exception)
                {
                    throw new PasswordVaultException("AES-256 密码库密码错误或文件已损坏。", exception);
                }
            }
            catch (EndOfStreamException exception)
            {
                throw new PasswordVaultException("AES-256 密码库文件已截断。", exception);
            }
            catch (IOException exception)
            {
                throw new PasswordVaultException("读取 AES-256 密码库失败。", exception);
            }
            finally
            {
                ClearBytes(parsedSalt);
                ClearBytes(iv);
                ClearBytes(ciphertext);
                ClearBytes(expectedTag);
                ClearBytes(actualTag);
            }
        }

        private void EnsureKeysForNewFile()
        {
            if (aesKey != null) return;
            byte[] newSalt = new byte[SaltLength];
            FillRandom(newSalt);
            try { EnsureKeys(newSalt); }
            finally { ClearBytes(newSalt); }
        }

        private void EnsureKeys(byte[] requestedSalt)
        {
            if (requestedSalt == null || requestedSalt.Length != SaltLength)
                throw new PasswordVaultException("AES-256 密码库盐值无效。");

            if (aesKey != null)
            {
                if (!FixedTimeEquals(salt, requestedSalt))
                    throw new PasswordVaultException("AES-256 密码库在当前会话中已被替换，请重新打开。");
                return;
            }
            if (passwordBytes == null || passwordBytes.Length == 0)
                throw new PasswordVaultException("AES-256 密码库密码不可用，请重新打开。");

            byte[] material = null;
            try
            {
                using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(
                    passwordBytes, requestedSalt, Pbkdf2Iterations, HashAlgorithmName.SHA256))
                    material = derive.GetBytes(KeyLength * 2);

                aesKey = new byte[KeyLength];
                macKey = new byte[KeyLength];
                Buffer.BlockCopy(material, 0, aesKey, 0, KeyLength);
                Buffer.BlockCopy(material, KeyLength, macKey, 0, KeyLength);
                salt = (byte[])requestedSalt.Clone();
            }
            catch (CryptographicException exception)
            {
                throw new PasswordVaultException("无法从密码派生 AES-256 密钥。", exception);
            }
            finally
            {
                ClearBytes(material);
                ClearBytes(passwordBytes);
                passwordBytes = null;
            }
        }

        private static byte[] SerializeJson(List<PasswordRecord> records)
        {
            if (records == null) throw new PasswordVaultException("密码库记录集合无效。");
            if (records.Count > MaximumRecords) throw new PasswordVaultException("密码库记录数量超过上限。");

            VaultJsonDocument document = new VaultJsonDocument
            {
                Format = JsonFormat,
                Version = JsonSchemaVersion,
                Records = new List<VaultJsonRecord>(records.Count)
            };
            for (int i = 0; i < records.Count; i++)
            {
                PasswordRecord record = records[i];
                document.Records.Add(new VaultJsonRecord
                {
                    Id = record.Id,
                    PdfPath = record.FilePath,
                    Password = record.Password,
                    Match = record.Match == PasswordMatch.User ? "User" :
                        record.Match == PasswordMatch.Owner ? "Owner" : record.Match.ToString(),
                    PasswordEncodingCodePage = record.PasswordEncodingCodePage,
                    Note = record.Note,
                    CreatedUtcTicks = record.CreatedUtc.Ticks,
                    UpdatedUtcTicks = record.UpdatedUtc.Ticks,
                    DocumentFingerprint = record.DocumentFingerprint == null ? null :
                        (byte[])record.DocumentFingerprint.Clone()
                });
            }

            try
            {
                DataContractJsonSerializer serializer = CreateSerializer();
                using (MemoryStream stream = new MemoryStream())
                {
                    try
                    {
                        using (XmlDictionaryWriter writer = JsonReaderWriterFactory.CreateJsonWriter(
                            stream, Encoding.UTF8, false, true, "  "))
                        {
                            serializer.WriteObject(writer, document);
                            writer.Flush();
                            byte[] result = stream.ToArray();
                            if (result.Length == 0 || result.Length > MaximumFileBytes)
                                throw new PasswordVaultException("密码库 JSON 超过 16 MiB 上限。");
                            return result;
                        }
                    }
                    finally
                    {
                        ClearBytes(stream.GetBuffer());
                    }
                }
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new PasswordVaultException("序列化密码库 JSON 失败。", exception);
            }
        }

        private static List<PasswordRecord> DeserializeJson(byte[] json)
        {
            if (json == null || json.Length == 0 || json.Length > MaximumFileBytes)
                throw new PasswordVaultException("密码库 JSON 为空或超过 16 MiB 上限。");

            try
            {
                DataContractJsonSerializer serializer = CreateSerializer();
                XmlDictionaryReaderQuotas quotas = new XmlDictionaryReaderQuotas();
                quotas.MaxDepth = 16;
                quotas.MaxArrayLength = MaximumFileBytes;
                quotas.MaxBytesPerRead = 4096;
                quotas.MaxNameTableCharCount = 4096;
                quotas.MaxStringContentLength = MaximumFileBytes;
                VaultJsonDocument document;
                using (XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(json, quotas))
                    document = serializer.ReadObject(reader, true) as VaultJsonDocument;

                if (document == null || !String.Equals(document.Format, JsonFormat, StringComparison.Ordinal))
                    throw new PasswordVaultException("密码库 JSON 格式标识无效。");
                if (document.Version != JsonSchemaVersion)
                    throw new PasswordVaultException("密码库 JSON 版本不受支持。");
                if (document.Records == null || document.Records.Count > MaximumRecords)
                    throw new PasswordVaultException("密码库 JSON 记录集合无效。");

                List<PasswordRecord> records = new List<PasswordRecord>(document.Records.Count);
                for (int i = 0; i < document.Records.Count; i++)
                {
                    VaultJsonRecord source = document.Records[i];
                    if (source == null) throw new PasswordVaultException("密码库 JSON 包含空记录。");
                    PasswordMatch match;
                    if (String.Equals(source.Match, "User", StringComparison.Ordinal)) match = PasswordMatch.User;
                    else if (String.Equals(source.Match, "Owner", StringComparison.Ordinal)) match = PasswordMatch.Owner;
                    else throw new PasswordVaultException("密码库 JSON 的密码类型无效。");

                    records.Add(new PasswordRecord
                    {
                        Id = source.Id,
                        FilePath = source.PdfPath,
                        Password = source.Password,
                        Match = match,
                        PasswordEncodingCodePage = source.PasswordEncodingCodePage,
                        Note = source.Note,
                        CreatedUtc = ReadUtc(source.CreatedUtcTicks, "创建时间"),
                        UpdatedUtc = ReadUtc(source.UpdatedUtcTicks, "更新时间"),
                        DocumentFingerprint = source.DocumentFingerprint == null ? null :
                            (byte[])source.DocumentFingerprint.Clone()
                    });
                }
                return records;
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (SerializationException exception)
            {
                throw new PasswordVaultException("密码库 JSON 结构无效。", exception);
            }
            catch (XmlException exception)
            {
                throw new PasswordVaultException("密码库 JSON 不是有效的 UTF-8 JSON。", exception);
            }
            catch (Exception exception)
            {
                throw new PasswordVaultException("读取密码库 JSON 失败。", exception);
            }
        }

        private static DataContractJsonSerializer CreateSerializer()
        {
            return new DataContractJsonSerializer(typeof(VaultJsonDocument),
                new DataContractJsonSerializerSettings
                {
                    MaxItemsInObjectGraph = MaximumRecords * 12,
                    UseSimpleDictionaryFormat = true
                });
        }

        private static DateTime ReadUtc(long ticks, string fieldName)
        {
            try { return new DateTime(ticks, DateTimeKind.Utc); }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new PasswordVaultException("密码库 JSON 的" + fieldName + "无效。", exception);
            }
        }

        private static byte[] ReadExact(BinaryReader reader, int count)
        {
            byte[] value = reader.ReadBytes(count);
            if (value.Length != count)
            {
                ClearBytes(value);
                throw new EndOfStreamException();
            }
            return value;
        }

        private static void RequireMagic(byte[] actual, byte[] expected)
        {
            bool equal = FixedTimeEquals(actual, expected);
            ClearBytes(actual);
            if (!equal) throw new PasswordVaultException("AES-256 密码库文件头无效。");
        }

        private static bool StartsWith(byte[] value, byte[] prefix)
        {
            if (value == null || prefix == null || value.Length < prefix.Length) return false;
            int difference = 0;
            for (int i = 0; i < prefix.Length; i++) difference |= value[i] ^ prefix[i];
            return difference == 0;
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static void FillRandom(byte[] value)
        {
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(value);
        }

        private static void ClearBytes(byte[] value)
        {
            if (value != null) Array.Clear(value, 0, value.Length);
        }

        private void ThrowIfDisposed()
        {
            if (disposed) throw new ObjectDisposedException("PasswordVaultStorage");
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            ClearBytes(passwordBytes);
            ClearBytes(salt);
            ClearBytes(aesKey);
            ClearBytes(macKey);
            passwordBytes = null;
            salt = null;
            aesKey = null;
            macKey = null;
        }

        [DataContract]
        private sealed class VaultJsonDocument
        {
            [DataMember(Name = "format", Order = 0, IsRequired = true)]
            public string Format;

            [DataMember(Name = "version", Order = 1, IsRequired = true)]
            public int Version;

            [DataMember(Name = "records", Order = 2, IsRequired = true)]
            public List<VaultJsonRecord> Records;
        }

        [DataContract]
        private sealed class VaultJsonRecord
        {
            [DataMember(Name = "id", Order = 0, IsRequired = true)]
            public Guid Id;

            [DataMember(Name = "pdfPath", Order = 1, IsRequired = true)]
            public string PdfPath;

            [DataMember(Name = "password", Order = 2, IsRequired = true)]
            public string Password;

            [DataMember(Name = "match", Order = 3, IsRequired = true)]
            public string Match;

            [DataMember(Name = "passwordEncodingCodePage", Order = 4, IsRequired = true)]
            public int PasswordEncodingCodePage;

            [DataMember(Name = "note", Order = 5, IsRequired = true)]
            public string Note;

            [DataMember(Name = "createdUtcTicks", Order = 6, IsRequired = true)]
            public long CreatedUtcTicks;

            [DataMember(Name = "updatedUtcTicks", Order = 7, IsRequired = true)]
            public long UpdatedUtcTicks;

            [DataMember(Name = "documentFingerprint", Order = 8, IsRequired = true)]
            public byte[] DocumentFingerprint;
        }
    }
}

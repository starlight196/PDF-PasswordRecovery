using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace PdfPasswordRecovery
{
    internal sealed class PasswordRecord
    {
        public Guid Id;
        public string FilePath;
        public string Password;
        public PasswordMatch Match;
        public int PasswordEncodingCodePage;
        public string Note;
        public DateTime CreatedUtc;
        public DateTime UpdatedUtc;
        public byte[] DocumentFingerprint;
        internal DateTime ExpectedUpdatedUtc;

        public PasswordRecord Clone()
        {
            return new PasswordRecord
            {
                Id = Id,
                FilePath = FilePath,
                Password = Password,
                Match = Match,
                PasswordEncodingCodePage = PasswordEncodingCodePage,
                Note = Note,
                CreatedUtc = CreatedUtc,
                UpdatedUtc = UpdatedUtc,
                DocumentFingerprint = DocumentFingerprint == null ? null : (byte[])DocumentFingerprint.Clone(),
                ExpectedUpdatedUtc = ExpectedUpdatedUtc
            };
        }
    }

    internal sealed class PasswordVaultException : Exception
    {
        public PasswordVaultException(string message)
            : base(message)
        {
        }

        public PasswordVaultException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    internal sealed class PasswordVault
    {
        private const int ContainerVersion = 1;
        private const int PlaintextVersion = 1;
        private const int MaximumVaultBytes = 16 * 1024 * 1024;
        private const int MaximumRecords = 100000;
        private const int MaximumPathBytes = 32768;
        private const int MaximumPasswordBytes = 1024 * 1024;
        private const int MaximumNoteBytes = 64 * 1024;
        private const int FingerprintLength = 32;
        private const int MutexWaitMilliseconds = 15000;

        private static readonly byte[] ContainerMagic = new byte[]
        {
            (byte)'P', (byte)'D', (byte)'F', (byte)'V', (byte)'A', (byte)'U', (byte)'L', (byte)'T'
        };

        private static readonly byte[] PlaintextMagic = new byte[]
        {
            (byte)'P', (byte)'D', (byte)'F', (byte)'P', (byte)'W', (byte)'D', (byte)'0', (byte)'1'
        };

        private static readonly byte[] AdditionalEntropy = Encoding.ASCII.GetBytes(
            "PdfPasswordRecovery.PasswordVault.v1");

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private readonly string mutexName;
        private readonly Dictionary<Guid, DateTime> observedVersions = new Dictionary<Guid, DateTime>();

        public PasswordVault()
            : this(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PdfPasswordRecovery",
                "passwords.vault"))
        {
        }

        internal PasswordVault(string storagePath)
        {
            if (String.IsNullOrWhiteSpace(storagePath))
                throw new ArgumentException("密码库路径不能为空。", "storagePath");

            StoragePath = Path.GetFullPath(storagePath);
            mutexName = CreateMutexName(StoragePath);
        }

        public string StoragePath { get; private set; }

        public List<PasswordRecord> Load()
        {
            return WithMutex(delegate
            {
                bool storageExists;
                List<PasswordRecord> records = LoadUnlocked(out storageExists);
                RememberObservedVersions(records);
                return CloneRecords(records);
            });
        }

        public PasswordRecord Upsert(PasswordRecord record)
        {
            if (record == null) throw new ArgumentNullException("record");
            PasswordRecord input = record.Clone();

            return WithMutex(delegate
            {
                bool storageExists;
                List<PasswordRecord> records = LoadUnlocked(out storageExists);
                DateTime now = DateTime.UtcNow;
                int existingIndex;

                if (input.Id != Guid.Empty)
                {
                    existingIndex = FindRecordById(records, input.Id);
                    if (existingIndex < 0)
                        throw new PasswordVaultException("密码条目已被删除或不存在，请重新加载密码库。");
                    EnsureRecordIsCurrent(input, records[existingIndex]);
                }
                else
                {
                    existingIndex = -1;
                }

                EnsureDocumentTypeIsUnique(records, input, existingIndex);

                if (existingIndex >= 0)
                {
                    input.Id = records[existingIndex].Id;
                    input.CreatedUtc = records[existingIndex].CreatedUtc;
                    if (now <= records[existingIndex].UpdatedUtc)
                        now = records[existingIndex].UpdatedUtc.AddTicks(1);
                }
                else
                {
                    if (input.Id == Guid.Empty) input.Id = Guid.NewGuid();
                    input.CreatedUtc = NormalizeNewCreatedTime(input.CreatedUtc, now);
                }

                input.UpdatedUtc = now;
                input.ExpectedUpdatedUtc = now;
                if (input.Note == null) input.Note = String.Empty;
                ValidateRecord(input);

                if (existingIndex >= 0) records[existingIndex] = input.Clone();
                else records.Add(input.Clone());

                SaveUnlocked(records, storageExists);
                RememberObservedVersions(records);
                return input.Clone();
            });
        }

        public void Delete(Guid id)
        {
            if (id == Guid.Empty) throw new ArgumentException("密码记录标识不能为空。", "id");

            WithMutex(delegate
            {
                bool storageExists;
                List<PasswordRecord> records = LoadUnlocked(out storageExists);
                int index = FindRecordById(records, id);

                if (index >= 0)
                {
                    EnsureDeleteIsCurrent(records[index]);
                    records.RemoveAt(index);
                    SaveUnlocked(records, storageExists);
                    RememberObservedVersions(records);
                }
                return true;
            });
        }

        private List<PasswordRecord> LoadUnlocked(out bool storageExists)
        {
            storageExists = false;
            byte[] protectedBytes = null;
            byte[] plaintext = null;
            try
            {
                FileStream stream;
                try
                {
                    stream = new FileStream(
                        StoragePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
                }
                catch (FileNotFoundException)
                {
                    return new List<PasswordRecord>();
                }
                catch (DirectoryNotFoundException)
                {
                    return new List<PasswordRecord>();
                }

                storageExists = true;
                using (stream)
                {
                    if (stream.Length < ContainerMagic.Length + 8 || stream.Length > MaximumVaultBytes)
                        throw new PasswordVaultException("密码库文件长度无效或超过 16 MiB 上限。");

                    using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
                    {
                        RequireMagic(ReadExact(reader, ContainerMagic.Length), ContainerMagic, "密码库文件头无效。");
                        int version = reader.ReadInt32();
                        if (version != ContainerVersion)
                            throw new PasswordVaultException("密码库文件版本不受支持。");

                        int protectedLength = reader.ReadInt32();
                        long remaining = stream.Length - stream.Position;
                        if (protectedLength <= 0 || protectedLength > MaximumVaultBytes || remaining != protectedLength)
                            throw new PasswordVaultException("密码库加密数据长度无效。");
                        protectedBytes = ReadExact(reader, protectedLength);
                    }
                }

                try
                {
                    plaintext = ProtectedData.Unprotect(
                        protectedBytes, AdditionalEntropy, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException exception)
                {
                    throw new PasswordVaultException(
                        "无法解密密码库。文件可能已损坏，或不属于当前 Windows 用户。", exception);
                }

                if (plaintext == null || plaintext.Length == 0 || plaintext.Length > MaximumVaultBytes)
                    throw new PasswordVaultException("密码库明文长度无效或超过 16 MiB 上限。");

                return DeserializePlaintext(plaintext);
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new PasswordVaultException("没有权限读取密码库文件。", exception);
            }
            catch (EndOfStreamException exception)
            {
                throw new PasswordVaultException("密码库文件已截断。", exception);
            }
            catch (IOException exception)
            {
                throw new PasswordVaultException("读取密码库文件失败。", exception);
            }
            finally
            {
                ClearBytes(plaintext);
                ClearBytes(protectedBytes);
            }
        }

        private void SaveUnlocked(List<PasswordRecord> records, bool storageExistedAtLoad)
        {
            byte[] plaintext = null;
            byte[] protectedBytes = null;
            byte[] container = null;
            string temporaryPath = null;

            try
            {
                plaintext = SerializePlaintext(records);
                protectedBytes = ProtectedData.Protect(
                    plaintext, AdditionalEntropy, DataProtectionScope.CurrentUser);
                if (protectedBytes == null || protectedBytes.Length == 0 ||
                    protectedBytes.Length > MaximumVaultBytes)
                    throw new PasswordVaultException("密码库加密数据超过 16 MiB 上限。");

                container = BuildContainer(protectedBytes);
                if (container.Length > MaximumVaultBytes)
                    throw new PasswordVaultException("密码库文件超过 16 MiB 上限。");

                string directory = Path.GetDirectoryName(StoragePath);
                if (String.IsNullOrEmpty(directory))
                    throw new PasswordVaultException("密码库目录无效。");
                Directory.CreateDirectory(directory);

                temporaryPath = Path.Combine(
                    directory,
                    "." + Path.GetFileName(StoragePath) + "." + Guid.NewGuid().ToString("N") + ".tmp");

                using (FileStream stream = new FileStream(
                    temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    4096, FileOptions.WriteThrough))
                {
                    stream.Write(container, 0, container.Length);
                    stream.Flush(true);
                }

                if (storageExistedAtLoad)
                {
                    File.Replace(temporaryPath, StoragePath, null, true);
                }
                else
                {
                    File.Move(temporaryPath, StoragePath);
                }
                temporaryPath = null;
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (CryptographicException exception)
            {
                throw new PasswordVaultException("加密密码库失败。", exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new PasswordVaultException("没有权限写入密码库文件。", exception);
            }
            catch (IOException exception)
            {
                throw new PasswordVaultException("写入密码库文件失败；原密码库未被替换。", exception);
            }
            finally
            {
                if (!String.IsNullOrEmpty(temporaryPath))
                {
                    try { File.Delete(temporaryPath); }
                    catch { }
                }
                ClearBytes(container);
                ClearBytes(protectedBytes);
                ClearBytes(plaintext);
            }
        }

        private static byte[] SerializePlaintext(List<PasswordRecord> records)
        {
            if (records == null) throw new PasswordVaultException("密码库记录集合无效。");
            if (records.Count > MaximumRecords) throw new PasswordVaultException("密码库记录数量超过上限。");

            HashSet<Guid> identifiers = new HashSet<Guid>();
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
            {
                try
                {
                    writer.Write(PlaintextMagic);
                    writer.Write(PlaintextVersion);
                    writer.Write(records.Count);

                    for (int i = 0; i < records.Count; i++)
                    {
                        PasswordRecord record = records[i];
                        ValidateRecord(record);
                        if (!identifiers.Add(record.Id))
                            throw new PasswordVaultException("密码库包含重复的记录标识。");

                        writer.Write(record.Id.ToByteArray());
                        WriteString(writer, record.FilePath, MaximumPathBytes, "PDF 路径");
                        WriteString(writer, record.Password, MaximumPasswordBytes, "密码");
                        writer.Write((int)record.Match);
                        writer.Write(record.PasswordEncodingCodePage);
                        WriteString(writer, record.Note, MaximumNoteBytes, "备注");
                        writer.Write(record.CreatedUtc.Ticks);
                        writer.Write(record.UpdatedUtc.Ticks);
                        writer.Write(record.DocumentFingerprint);

                        if (stream.Length > MaximumVaultBytes)
                            throw new PasswordVaultException("密码库明文超过 16 MiB 上限。");
                    }

                    writer.Flush();
                    if (stream.Length > MaximumVaultBytes)
                        throw new PasswordVaultException("密码库明文超过 16 MiB 上限。");
                    return stream.ToArray();
                }
                finally
                {
                    byte[] buffer = stream.GetBuffer();
                    ClearBytes(buffer);
                }
            }
        }

        private static List<PasswordRecord> DeserializePlaintext(byte[] plaintext)
        {
            List<PasswordRecord> records = new List<PasswordRecord>();
            HashSet<Guid> identifiers = new HashSet<Guid>();

            try
            {
                using (MemoryStream stream = new MemoryStream(plaintext, false))
                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
                {
                    RequireMagic(ReadExact(reader, PlaintextMagic.Length), PlaintextMagic, "密码库明文文件头无效。");
                    int version = reader.ReadInt32();
                    if (version != PlaintextVersion)
                        throw new PasswordVaultException("密码库明文版本不受支持。");

                    int count = reader.ReadInt32();
                    if (count < 0 || count > MaximumRecords)
                        throw new PasswordVaultException("密码库记录数量无效。");

                    for (int i = 0; i < count; i++)
                    {
                        PasswordRecord record = new PasswordRecord
                        {
                            Id = new Guid(ReadExact(reader, 16)),
                            FilePath = ReadString(reader, MaximumPathBytes, "PDF 路径"),
                            Password = ReadString(reader, MaximumPasswordBytes, "密码"),
                            Match = (PasswordMatch)reader.ReadInt32(),
                            PasswordEncodingCodePage = reader.ReadInt32(),
                            Note = ReadString(reader, MaximumNoteBytes, "备注"),
                            CreatedUtc = ReadUtcDateTime(reader.ReadInt64(), "创建时间"),
                            UpdatedUtc = ReadUtcDateTime(reader.ReadInt64(), "更新时间"),
                            DocumentFingerprint = ReadExact(reader, FingerprintLength)
                        };

                        ValidateRecord(record);
                        record.ExpectedUpdatedUtc = record.UpdatedUtc;
                        if (!identifiers.Add(record.Id))
                            throw new PasswordVaultException("密码库包含重复的记录标识。");
                        records.Add(record);
                    }

                    if (stream.Position != stream.Length)
                        throw new PasswordVaultException("密码库明文包含多余数据。");
                }
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (EndOfStreamException exception)
            {
                throw new PasswordVaultException("密码库明文已截断。", exception);
            }
            catch (DecoderFallbackException)
            {
                throw new PasswordVaultException("密码库包含无效的 UTF-8 文本。");
            }
            catch (ArgumentException exception)
            {
                throw new PasswordVaultException("密码库包含无效字段。", exception);
            }

            return records;
        }

        private static byte[] BuildContainer(byte[] protectedBytes)
        {
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
            {
                writer.Write(ContainerMagic);
                writer.Write(ContainerVersion);
                writer.Write(protectedBytes.Length);
                writer.Write(protectedBytes);
                writer.Flush();
                return stream.ToArray();
            }
        }

        private static void ValidateRecord(PasswordRecord record)
        {
            if (record == null) throw new PasswordVaultException("密码库包含空记录。");
            if (record.Id == Guid.Empty) throw new PasswordVaultException("密码记录标识无效。");
            if (String.IsNullOrWhiteSpace(record.FilePath) || record.FilePath.IndexOf('\0') >= 0)
                throw new PasswordVaultException("密码记录的 PDF 路径无效。");
            if (record.Password == null)
                throw new PasswordVaultException("密码记录缺少密码字段。");
            if (record.Note == null)
                throw new PasswordVaultException("密码记录缺少备注字段。");
            if (record.Match != PasswordMatch.User && record.Match != PasswordMatch.Owner)
                throw new PasswordVaultException("密码记录的匹配类型无效。");
            if (record.DocumentFingerprint == null || record.DocumentFingerprint.Length != FingerprintLength)
                throw new PasswordVaultException("密码记录的文档指纹必须为 32 字节。");
            if (record.CreatedUtc.Kind != DateTimeKind.Utc || record.UpdatedUtc.Kind != DateTimeKind.Utc ||
                record.UpdatedUtc < record.CreatedUtc)
                throw new PasswordVaultException("密码记录的 UTC 时间字段无效。");

            GetUtf8ByteCount(record.FilePath, MaximumPathBytes, "PDF 路径");
            GetUtf8ByteCount(record.Password, MaximumPasswordBytes, "密码");
            GetUtf8ByteCount(record.Note, MaximumNoteBytes, "备注");

            try
            {
                Encoding.GetEncoding(
                    record.PasswordEncodingCodePage,
                    EncoderFallback.ExceptionFallback,
                    DecoderFallback.ExceptionFallback);
            }
            catch (ArgumentException)
            {
                throw new PasswordVaultException("密码记录的字符编码无效。");
            }
        }

        private static int FindRecordById(List<PasswordRecord> records, Guid id)
        {
            for (int i = 0; i < records.Count; i++)
            {
                if (records[i].Id == id) return i;
            }
            return -1;
        }

        private static void EnsureDocumentTypeIsUnique(
            List<PasswordRecord> records, PasswordRecord input, int recordBeingUpdated)
        {
            if (input.DocumentFingerprint != null && input.DocumentFingerprint.Length == FingerprintLength &&
                (input.Match == PasswordMatch.User || input.Match == PasswordMatch.Owner))
            {
                for (int i = 0; i < records.Count; i++)
                {
                    if (i == recordBeingUpdated) continue;
                    if (records[i].Match == input.Match &&
                        FixedTimeEquals(records[i].DocumentFingerprint, input.DocumentFingerprint))
                        throw new PasswordVaultException(
                            "该 PDF 的同类型密码条目已存在，请重新加载密码库后再操作。");
                }
            }
        }

        private void EnsureRecordIsCurrent(PasswordRecord input, PasswordRecord stored)
        {
            DateTime expected = input.ExpectedUpdatedUtc;
            if (expected == default(DateTime)) observedVersions.TryGetValue(input.Id, out expected);
            if (expected == default(DateTime))
                throw new PasswordVaultException("缺少密码条目的并发版本，请重新加载密码库后再保存。");
            if (expected != stored.UpdatedUtc)
                throw new PasswordVaultException("密码条目已被其他进程修改，请重新加载后再编辑。");
        }

        private void EnsureDeleteIsCurrent(PasswordRecord stored)
        {
            DateTime expected;
            if (observedVersions.TryGetValue(stored.Id, out expected) && expected != stored.UpdatedUtc)
                throw new PasswordVaultException("密码条目已被其他进程修改，请重新加载后再删除。");
        }

        private void RememberObservedVersions(List<PasswordRecord> records)
        {
            observedVersions.Clear();
            for (int i = 0; i < records.Count; i++)
                observedVersions[records[i].Id] = records[i].UpdatedUtc;
        }

        private static DateTime NormalizeNewCreatedTime(DateTime value, DateTime fallback)
        {
            if (value == default(DateTime)) return fallback;
            if (value.Kind == DateTimeKind.Utc) return value;
            if (value.Kind == DateTimeKind.Local) return value.ToUniversalTime();
            throw new PasswordVaultException("密码记录的创建时间必须为 UTC。");
        }

        private static DateTime ReadUtcDateTime(long ticks, string fieldName)
        {
            try
            {
                return new DateTime(ticks, DateTimeKind.Utc);
            }
            catch (ArgumentOutOfRangeException)
            {
                throw new PasswordVaultException("密码记录的" + fieldName + "无效。");
            }
        }

        private static void WriteString(BinaryWriter writer, string value, int maximumBytes, string fieldName)
        {
            int byteCount = GetUtf8ByteCount(value, maximumBytes, fieldName);
            byte[] bytes = null;
            try
            {
                bytes = StrictUtf8.GetBytes(value);
                writer.Write(byteCount);
                writer.Write(bytes);
            }
            catch (EncoderFallbackException)
            {
                throw new PasswordVaultException("密码记录的" + fieldName + "包含无效字符。");
            }
            finally
            {
                ClearBytes(bytes);
            }
        }

        private static string ReadString(BinaryReader reader, int maximumBytes, string fieldName)
        {
            int byteCount = reader.ReadInt32();
            if (byteCount < 0 || byteCount > maximumBytes)
                throw new PasswordVaultException("密码记录的" + fieldName + "长度无效。");
            byte[] bytes = ReadExact(reader, byteCount);
            try
            {
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw new PasswordVaultException("密码记录的" + fieldName + "不是有效 UTF-8 文本。");
            }
            finally
            {
                ClearBytes(bytes);
            }
        }

        private static int GetUtf8ByteCount(string value, int maximumBytes, string fieldName)
        {
            if (value == null) throw new PasswordVaultException("密码记录缺少" + fieldName + "字段。");
            int byteCount;
            try
            {
                byteCount = StrictUtf8.GetByteCount(value);
            }
            catch (EncoderFallbackException)
            {
                throw new PasswordVaultException("密码记录的" + fieldName + "包含无效字符。");
            }
            if (byteCount > maximumBytes)
                throw new PasswordVaultException("密码记录的" + fieldName + "超过长度上限。");
            return byteCount;
        }

        private static byte[] ReadExact(BinaryReader reader, int count)
        {
            byte[] bytes = reader.ReadBytes(count);
            if (bytes.Length != count)
            {
                ClearBytes(bytes);
                throw new EndOfStreamException();
            }
            return bytes;
        }

        private static void RequireMagic(byte[] actual, byte[] expected, string errorMessage)
        {
            try
            {
                if (!FixedTimeEquals(actual, expected)) throw new PasswordVaultException(errorMessage);
            }
            finally
            {
                ClearBytes(actual);
            }
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static List<PasswordRecord> CloneRecords(List<PasswordRecord> records)
        {
            List<PasswordRecord> result = new List<PasswordRecord>(records.Count);
            for (int i = 0; i < records.Count; i++) result.Add(records[i].Clone());
            return result;
        }

        private T WithMutex<T>(Func<T> action)
        {
            Mutex mutex = null;
            bool acquired = false;
            try
            {
                mutex = new Mutex(false, mutexName);
                try
                {
                    acquired = mutex.WaitOne(MutexWaitMilliseconds, false);
                }
                catch (AbandonedMutexException)
                {
                    acquired = true;
                }

                if (!acquired)
                    throw new PasswordVaultException("密码库正被其他进程使用，请稍后重试。");
                return action();
            }
            catch (PasswordVaultException)
            {
                throw;
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new PasswordVaultException("无法访问密码库进程锁。", exception);
            }
            catch (IOException exception)
            {
                throw new PasswordVaultException("密码库进程锁失败。", exception);
            }
            finally
            {
                if (acquired && mutex != null)
                {
                    try { mutex.ReleaseMutex(); }
                    catch (ApplicationException) { }
                }
                if (mutex != null) mutex.Dispose();
            }
        }

        private static string CreateMutexName(string storagePath)
        {
            byte[] pathBytes = null;
            byte[] hash = null;
            try
            {
                pathBytes = Encoding.UTF8.GetBytes(storagePath.ToUpperInvariant());
                using (SHA256 algorithm = SHA256.Create()) hash = algorithm.ComputeHash(pathBytes);
                StringBuilder name = new StringBuilder("Local\\PdfPasswordRecovery.PasswordVault.");
                for (int i = 0; i < 16; i++) name.Append(hash[i].ToString("X2"));
                return name.ToString();
            }
            finally
            {
                ClearBytes(hash);
                ClearBytes(pathBytes);
            }
        }

        private static void ClearBytes(byte[] bytes)
        {
            if (bytes != null) Array.Clear(bytes, 0, bytes.Length);
        }
    }
}

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

    internal sealed class PasswordVaultMutationResult
    {
        public PasswordRecord SavedRecord;
        public List<PasswordRecord> Records;
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
        : IDisposable
    {
        private const int MaximumVaultBytes = 16 * 1024 * 1024;
        private const int MaximumRecords = 100000;
        private const int MaximumPathBytes = 32768;
        private const int MaximumPasswordBytes = 1024 * 1024;
        private const int MaximumNoteBytes = 64 * 1024;
        private const int FingerprintLength = 32;
        private const int MutexWaitMilliseconds = 15000;

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private readonly string mutexName;
        private readonly Dictionary<Guid, DateTime> observedVersions = new Dictionary<Guid, DateTime>();
        private readonly PasswordVaultStorage storage;
        private bool disposed;

        public static string DefaultPlaintextStoragePath { get { return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PdfPasswordRecovery", "passwords.json"); } }

        public static string DefaultAes256StoragePath { get { return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PdfPasswordRecovery", "passwords.aesvault"); } }

        private PasswordVault(string storagePath, PasswordVaultStorageMode mode, string password)
        {
            if (String.IsNullOrWhiteSpace(storagePath))
                throw new ArgumentException("密码库路径不能为空。", "storagePath");

            StoragePath = Path.GetFullPath(storagePath);
            mutexName = CreateMutexName(StoragePath);
            storage = new PasswordVaultStorage(mode, password);
        }

        public string StoragePath { get; private set; }
        public PasswordVaultStorageMode StorageMode { get { return storage.Mode; } }

        public static PasswordVault OpenPlaintext()
        {
            return OpenPlaintext(DefaultPlaintextStoragePath);
        }

        public static PasswordVault OpenPlaintext(string storagePath)
        {
            return new PasswordVault(storagePath, PasswordVaultStorageMode.PlaintextJson, null);
        }

        public static PasswordVault OpenAes256(string password)
        {
            return OpenAes256(DefaultAes256StoragePath, password);
        }

        public static PasswordVault OpenAes256(string storagePath, string password)
        {
            return new PasswordVault(storagePath, PasswordVaultStorageMode.Aes256, password);
        }

        public List<PasswordRecord> Load()
        {
            ThrowIfDisposed();
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
            return UpsertWithSnapshot(record).SavedRecord;
        }

        internal PasswordVaultMutationResult UpsertWithSnapshot(PasswordRecord record)
        {
            ThrowIfDisposed();
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
                return new PasswordVaultMutationResult
                {
                    SavedRecord = input.Clone(),
                    Records = CloneRecords(records)
                };
            });
        }

        public void Delete(Guid id)
        {
            DeleteWithSnapshot(id);
        }

        internal PasswordVaultMutationResult DeleteWithSnapshot(Guid id)
        {
            ThrowIfDisposed();
            if (id == Guid.Empty) throw new ArgumentException("密码记录标识不能为空。", "id");

            return WithMutex(delegate
            {
                bool storageExists;
                List<PasswordRecord> records = LoadUnlocked(out storageExists);
                int index = FindRecordById(records, id);

                if (index >= 0)
                {
                    EnsureDeleteIsCurrent(records[index]);
                    records.RemoveAt(index);
                    SaveUnlocked(records, storageExists);
                }
                RememberObservedVersions(records);
                return new PasswordVaultMutationResult
                {
                    SavedRecord = null,
                    Records = CloneRecords(records)
                };
            });
        }

        private List<PasswordRecord> LoadUnlocked(out bool storageExists)
        {
            storageExists = false;
            byte[] fileBytes = null;
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
                    if (stream.Length <= 0 || stream.Length > MaximumVaultBytes)
                        throw new PasswordVaultException("密码库文件为空、无效或超过 16 MiB 上限。");
                    fileBytes = new byte[(int)stream.Length];
                    int offset = 0;
                    while (offset < fileBytes.Length)
                    {
                        int read = stream.Read(fileBytes, offset, fileBytes.Length - offset);
                        if (read <= 0) throw new EndOfStreamException();
                        offset += read;
                    }
                }

                List<PasswordRecord> records = storage.Decode(fileBytes);
                ValidateRecordSet(records);
                return records;
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
                ClearBytes(fileBytes);
            }
        }

        private void SaveUnlocked(List<PasswordRecord> records, bool storageExistedAtLoad)
        {
            byte[] fileBytes = null;
            string temporaryPath = null;

            try
            {
                ValidateRecordSet(records);
                fileBytes = storage.Encode(records);
                if (fileBytes == null || fileBytes.Length == 0 || fileBytes.Length > MaximumVaultBytes)
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
                    stream.Write(fileBytes, 0, fileBytes.Length);
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
                ClearBytes(fileBytes);
            }
        }

        private static void ValidateRecordSet(List<PasswordRecord> records)
        {
            if (records == null) throw new PasswordVaultException("密码库记录集合无效。");
            if (records.Count > MaximumRecords) throw new PasswordVaultException("密码库记录数量超过上限。");

            HashSet<Guid> identifiers = new HashSet<Guid>();
            HashSet<string> documentTypes = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < records.Count; i++)
            {
                PasswordRecord record = records[i];
                ValidateRecord(record);
                if (!identifiers.Add(record.Id))
                    throw new PasswordVaultException("密码库包含重复的记录标识。");
                string documentType = ((int)record.Match).ToString() + ":" +
                    Convert.ToBase64String(record.DocumentFingerprint);
                if (!documentTypes.Add(documentType))
                    throw new PasswordVaultException("密码库包含重复的 PDF 密码类型条目。");
                record.ExpectedUpdatedUtc = record.UpdatedUtc;
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

        private void ThrowIfDisposed()
        {
            if (disposed) throw new ObjectDisposedException("PasswordVault");
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            observedVersions.Clear();
            storage.Dispose();
        }

        private static void ClearBytes(byte[] bytes)
        {
            if (bytes != null) Array.Clear(bytes, 0, bytes.Length);
        }
    }
}

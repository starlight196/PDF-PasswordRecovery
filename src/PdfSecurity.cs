using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace PdfPasswordRecovery
{
    public enum PasswordMatch
    {
        None,
        User,
        Owner
    }

    public sealed class PdfSecurityInfo
    {
        internal byte[] OwnerEntry;
        internal byte[] UserEntry;
        internal byte[] FileIdentifier;

        public string FilePath { get; internal set; }
        public int Version { get; internal set; }
        public int Revision { get; internal set; }
        public int KeyLengthBits { get; internal set; }
        public int Permissions { get; internal set; }
        public bool EncryptMetadata { get; internal set; }
        public string CipherName { get; internal set; }

        public string DisplayName
        {
            get
            {
                return "Standard V" + Version.ToString(CultureInfo.InvariantCulture) +
                    " / R" + Revision.ToString(CultureInfo.InvariantCulture) +
                    " / " + CipherName + " / 支持";
            }
        }
    }

    public static class PdfSecurity
    {
        private static readonly byte[] PasswordPadding = new byte[]
        {
            0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
            0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
            0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
            0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
        };

        [ThreadStatic]
        private static CryptoWorkspace threadWorkspace;

        public static PdfSecurityInfo Load(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("PDF 路径不能为空。", "path");
            FileInfo file = new FileInfo(path);
            if (!file.Exists) throw new FileNotFoundException("找不到 PDF 文件。", path);
            if (file.Length > Int32.MaxValue) throw new NotSupportedException("暂不支持大于 2 GB 的 PDF。");

            byte[] data = File.ReadAllBytes(path);
            PdfValue trailer;
            Dictionary<ObjectReference, long> xref;
            ReadXrefChain(data, out trailer, out xref);

            PdfValue encryptValue = GetRequired(trailer, "Encrypt", "最终 trailer 缺少 /Encrypt；该 PDF 未加密。", false);
            PdfValue encryptDictionary = ResolveDictionary(data, encryptValue, xref, "加密字典");
            PdfValue fileIdArray = GetRequired(trailer, "ID", "最终 trailer 缺少 /ID，无法校验密码。", false);
            if (fileIdArray.Kind != PdfValueKind.Array || fileIdArray.Items.Count == 0 ||
                fileIdArray.Items[0].Kind != PdfValueKind.String)
                throw new InvalidDataException("PDF trailer 的 /ID 格式无效。");

            string filter = GetName(encryptDictionary, "Filter", true);
            if (!String.Equals(filter, "Standard", StringComparison.Ordinal))
                throw new NotSupportedException("仅支持 PDF Standard Security Handler。");

            int version = GetInteger(encryptDictionary, "V", 0, true);
            int revision = GetInteger(encryptDictionary, "R", 0, true);
            if (revision < 2 || revision > 4 || (version != 1 && version != 2 && version != 4))
                throw new NotSupportedException("当前支持 Standard Security R2-R4；此文件为 V" + version + " / R" + revision + "。");

            int keyLengthBits = revision == 2 ? 40 : GetInteger(encryptDictionary, "Length", 40, false);
            if (keyLengthBits < 40 || keyLengthBits > 128 || (keyLengthBits & 7) != 0)
                throw new InvalidDataException("PDF 加密密钥长度无效：" + keyLengthBits + " bit。");

            byte[] owner = GetString(encryptDictionary, "O", true);
            byte[] user = GetString(encryptDictionary, "U", true);
            if (owner.Length < 32 || user.Length < 32)
                throw new InvalidDataException("PDF 加密字典中的 /O 或 /U 长度不足 32 字节。");

            bool encryptMetadata = GetBoolean(encryptDictionary, "EncryptMetadata", true);
            return new PdfSecurityInfo
            {
                FilePath = file.FullName,
                Version = version,
                Revision = revision,
                KeyLengthBits = keyLengthBits,
                Permissions = GetInteger(encryptDictionary, "P", 0, true),
                EncryptMetadata = encryptMetadata,
                CipherName = DetermineCipherName(encryptDictionary, version, revision, keyLengthBits),
                OwnerEntry = CopyFirst(owner, 32),
                UserEntry = CopyFirst(user, 32),
                FileIdentifier = (byte[])fileIdArray.Items[0].Bytes.Clone()
            };
        }

        public static PasswordMatch VerifyPassword(PdfSecurityInfo info, byte[] passwordBytes)
        {
            if (passwordBytes == null) throw new ArgumentNullException("passwordBytes");
            return VerifyPassword(info, passwordBytes, passwordBytes.Length);
        }

        public static PasswordMatch VerifyPassword(PdfSecurityInfo info, byte[] passwordBytes, int count)
        {
            if (info == null) throw new ArgumentNullException("info");
            if (passwordBytes == null) throw new ArgumentNullException("passwordBytes");
            if (count < 0 || count > passwordBytes.Length) throw new ArgumentOutOfRangeException("count");

            CryptoWorkspace workspace = threadWorkspace;
            if (workspace == null)
            {
                workspace = new CryptoWorkspace();
                threadWorkspace = workspace;
            }

            PadPassword(passwordBytes, count, workspace.PaddedPassword);
            if (ValidatePaddedUserPassword(info, workspace.PaddedPassword, workspace))
                return PasswordMatch.User;

            DeriveUserPasswordFromOwnerCandidate(info, workspace.PaddedPassword, workspace);
            if (ValidatePaddedUserPassword(info, workspace.OwnerDecoded, workspace))
                return PasswordMatch.Owner;

            return PasswordMatch.None;
        }

        private static bool ValidatePaddedUserPassword(PdfSecurityInfo info, byte[] paddedPassword, CryptoWorkspace workspace)
        {
            int keyLength = info.KeyLengthBits / 8;
            DeriveFileEncryptionKey(info, paddedPassword, workspace, keyLength);

            if (info.Revision == 2)
            {
                Rc4.Transform(workspace.EncryptionKey, keyLength, PasswordPadding, 32, workspace.UserCandidate, workspace.SBox);
                return FixedTimeEquals(workspace.UserCandidate, info.UserEntry, 32);
            }

            workspace.Md5.Reset();
            workspace.Md5.Update(PasswordPadding, 0, PasswordPadding.Length);
            workspace.Md5.Update(info.FileIdentifier, 0, info.FileIdentifier.Length);
            workspace.Md5.Final(workspace.Digest);
            Rc4.Transform(workspace.EncryptionKey, keyLength, workspace.Digest, 16, workspace.UserCandidate, workspace.SBox);
            for (int iteration = 1; iteration <= 19; iteration++)
            {
                for (int i = 0; i < keyLength; i++) workspace.IterationKey[i] = (byte)(workspace.EncryptionKey[i] ^ iteration);
                Rc4.Transform(workspace.IterationKey, keyLength, workspace.UserCandidate, 16, workspace.UserCandidate, workspace.SBox);
            }
            return FixedTimeEquals(workspace.UserCandidate, info.UserEntry, 16);
        }

        private static void DeriveFileEncryptionKey(PdfSecurityInfo info, byte[] paddedPassword,
            CryptoWorkspace workspace, int keyLength)
        {
            workspace.Md5.Reset();
            workspace.Md5.Update(paddedPassword, 0, 32);
            workspace.Md5.Update(info.OwnerEntry, 0, 32);
            workspace.LittleEndianInt[0] = (byte)info.Permissions;
            workspace.LittleEndianInt[1] = (byte)(info.Permissions >> 8);
            workspace.LittleEndianInt[2] = (byte)(info.Permissions >> 16);
            workspace.LittleEndianInt[3] = (byte)(info.Permissions >> 24);
            workspace.Md5.Update(workspace.LittleEndianInt, 0, 4);
            workspace.Md5.Update(info.FileIdentifier, 0, info.FileIdentifier.Length);
            if (info.Revision >= 4 && !info.EncryptMetadata)
                workspace.Md5.Update(workspace.FourFF, 0, 4);
            workspace.Md5.Final(workspace.Digest);

            if (info.Revision >= 3)
            {
                for (int iteration = 0; iteration < 50; iteration++)
                {
                    workspace.Md5.Reset();
                    workspace.Md5.Update(workspace.Digest, 0, keyLength);
                    workspace.Md5.Final(workspace.Digest);
                }
            }
            Buffer.BlockCopy(workspace.Digest, 0, workspace.EncryptionKey, 0, keyLength);
        }

        private static void DeriveUserPasswordFromOwnerCandidate(PdfSecurityInfo info,
            byte[] paddedOwnerPassword, CryptoWorkspace workspace)
        {
            int keyLength = info.KeyLengthBits / 8;
            workspace.Md5.Reset();
            workspace.Md5.Update(paddedOwnerPassword, 0, 32);
            workspace.Md5.Final(workspace.Digest);
            if (info.Revision >= 3)
            {
                for (int iteration = 0; iteration < 50; iteration++)
                {
                    workspace.Md5.Reset();
                    workspace.Md5.Update(workspace.Digest, 0, keyLength);
                    workspace.Md5.Final(workspace.Digest);
                }
            }

            Buffer.BlockCopy(workspace.Digest, 0, workspace.OwnerKey, 0, keyLength);
            Buffer.BlockCopy(info.OwnerEntry, 0, workspace.OwnerDecoded, 0, 32);
            if (info.Revision == 2)
            {
                Rc4.Transform(workspace.OwnerKey, keyLength, workspace.OwnerDecoded, 32, workspace.OwnerDecoded, workspace.SBox);
                return;
            }

            for (int iteration = 19; iteration >= 0; iteration--)
            {
                for (int i = 0; i < keyLength; i++) workspace.IterationKey[i] = (byte)(workspace.OwnerKey[i] ^ iteration);
                Rc4.Transform(workspace.IterationKey, keyLength, workspace.OwnerDecoded, 32, workspace.OwnerDecoded, workspace.SBox);
            }
        }

        private static void PadPassword(byte[] password, int count, byte[] destination)
        {
            int copied = Math.Min(32, count);
            if (copied > 0) Buffer.BlockCopy(password, 0, destination, 0, copied);
            if (copied < 32) Buffer.BlockCopy(PasswordPadding, 0, destination, copied, 32 - copied);
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right, int count)
        {
            int difference = 0;
            for (int i = 0; i < count; i++) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static byte[] CopyFirst(byte[] source, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, 0, result, 0, count);
            return result;
        }

        private static string DetermineCipherName(PdfValue dictionary, int version, int revision, int keyLengthBits)
        {
            if (revision == 2) return "RC4-40";
            if (version == 2) return "RC4-" + keyLengthBits;
            if (version == 4)
            {
                string streamFilter = GetName(dictionary, "StmF", false);
                PdfValue cryptFilters;
                PdfValue selected;
                PdfValue method;
                if (!String.IsNullOrEmpty(streamFilter) && dictionary.Dictionary.TryGetValue("CF", out cryptFilters) &&
                    cryptFilters.Kind == PdfValueKind.Dictionary && cryptFilters.Dictionary.TryGetValue(streamFilter, out selected) &&
                    selected.Kind == PdfValueKind.Dictionary && selected.Dictionary.TryGetValue("CFM", out method) &&
                    method.Kind == PdfValueKind.Name)
                {
                    if (method.Text == "AESV2") return "AES-128";
                    if (method.Text == "V2") return "RC4-" + keyLengthBits;
                }
                return "AES/RC4-" + keyLengthBits;
            }
            return "Standard-" + keyLengthBits;
        }

        private static void ReadXrefChain(byte[] data, out PdfValue mergedTrailer,
            out Dictionary<ObjectReference, long> mergedEntries)
        {
            long offset = ReadStartXref(data);
            HashSet<long> visited = new HashSet<long>();
            HashSet<int> definedObjectNumbers = new HashSet<int>();
            mergedTrailer = PdfValue.CreateDictionary();
            mergedEntries = new Dictionary<ObjectReference, long>();
            bool first = true;

            while (offset >= 0)
            {
                if (offset >= data.Length || !visited.Add(offset))
                    throw new InvalidDataException("PDF xref 链无效或形成循环。");

                XrefSection section = ParseClassicXref(data, (int)offset);
                foreach (KeyValuePair<int, XrefEntry> item in section.Entries)
                {
                    if (!definedObjectNumbers.Add(item.Key) || !item.Value.InUse) continue;
                    mergedEntries.Add(
                        new ObjectReference(item.Key, item.Value.Generation),
                        item.Value.Offset);
                }
                foreach (KeyValuePair<string, PdfValue> item in section.Trailer.Dictionary)
                {
                    if (!mergedTrailer.Dictionary.ContainsKey(item.Key)) mergedTrailer.Dictionary.Add(item.Key, item.Value);
                }

                PdfValue xrefStream;
                if (section.Trailer.Dictionary.TryGetValue("XRefStm", out xrefStream))
                    throw new NotSupportedException("暂不支持混合 xref stream PDF。");

                PdfValue previous;
                if (!section.Trailer.Dictionary.TryGetValue("Prev", out previous)) break;
                if (previous.Kind != PdfValueKind.Integer || previous.Number < 0)
                    throw new InvalidDataException("PDF trailer 的 /Prev 无效。");
                offset = previous.Number;
                first = false;
            }

            if (first && mergedTrailer.Dictionary.Count == 0)
                throw new InvalidDataException("未找到有效的 PDF trailer。");
        }

        private static long ReadStartXref(byte[] data)
        {
            int marker = LastIndexOfAscii(data, "startxref");
            if (marker < 0) throw new InvalidDataException("PDF 缺少 startxref。");
            PdfReader reader = new PdfReader(data, marker + 9);
            string value = reader.ReadWord();
            long offset;
            if (!Int64.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out offset))
                throw new InvalidDataException("PDF startxref 偏移无效。");
            return offset;
        }

        private static XrefSection ParseClassicXref(byte[] data, int offset)
        {
            PdfReader reader = new PdfReader(data, offset);
            string marker = reader.ReadWord();
            if (!String.Equals(marker, "xref", StringComparison.Ordinal))
                throw new NotSupportedException("暂不支持 xref stream 或对象流；请先用 PDF 工具转为经典 xref 格式。");

            XrefSection result = new XrefSection();
            while (true)
            {
                string first = reader.ReadWord();
                if (String.Equals(first, "trailer", StringComparison.Ordinal)) break;

                int firstObject;
                int count;
                if (!Int32.TryParse(first, NumberStyles.None, CultureInfo.InvariantCulture, out firstObject) ||
                    !Int32.TryParse(reader.ReadWord(), NumberStyles.None, CultureInfo.InvariantCulture, out count) ||
                    firstObject < 0 || count < 0 || (long)firstObject + count > Int32.MaxValue)
                    throw new InvalidDataException("PDF xref 子段头无效。");

                for (int i = 0; i < count; i++)
                {
                    string offsetToken = reader.ReadWord();
                    string generationToken = reader.ReadWord();
                    string stateToken = reader.ReadWord();
                    long objectOffset;
                    int generation;
                    if (!Int64.TryParse(offsetToken, NumberStyles.None, CultureInfo.InvariantCulture, out objectOffset) ||
                        !Int32.TryParse(generationToken, NumberStyles.None, CultureInfo.InvariantCulture, out generation))
                        throw new InvalidDataException("PDF xref 表项无效。");
                    if (generation < 0 || (stateToken != "n" && stateToken != "f"))
                        throw new InvalidDataException("PDF xref 表项状态无效。");

                    result.Entries[firstObject + i] = new XrefEntry
                    {
                        Generation = generation,
                        Offset = objectOffset,
                        InUse = stateToken == "n"
                    };
                }
            }

            result.Trailer = reader.ReadValue();
            if (result.Trailer.Kind != PdfValueKind.Dictionary)
                throw new InvalidDataException("PDF trailer 不是字典。");
            return result;
        }

        private static PdfValue ResolveDictionary(byte[] data, PdfValue value,
            Dictionary<ObjectReference, long> xref, string description)
        {
            if (value.Kind == PdfValueKind.Dictionary) return value;
            if (value.Kind != PdfValueKind.Reference)
                throw new InvalidDataException(description + "不是字典或间接引用。");

            long offset;
            if (!xref.TryGetValue(value.Reference, out offset) || offset < 0 || offset >= data.Length)
                throw new InvalidDataException("无法从 xref 定位" + description + "对象。");
            PdfReader reader = new PdfReader(data, (int)offset);
            string objectNumber = reader.ReadWord();
            string generation = reader.ReadWord();
            string marker = reader.ReadWord();
            int parsedObject;
            int parsedGeneration;
            if (!Int32.TryParse(objectNumber, NumberStyles.None, CultureInfo.InvariantCulture, out parsedObject) ||
                !Int32.TryParse(generation, NumberStyles.None, CultureInfo.InvariantCulture, out parsedGeneration) ||
                marker != "obj" || parsedObject != value.Reference.ObjectNumber || parsedGeneration != value.Reference.Generation)
                throw new InvalidDataException(description + "对象头与 xref 不一致。");
            PdfValue resolved = reader.ReadValue();
            if (resolved.Kind != PdfValueKind.Dictionary)
                throw new InvalidDataException(description + "对象不是 PDF 字典。");
            return resolved;
        }

        private static PdfValue GetRequired(PdfValue dictionary, string key, string message, bool requireDictionary)
        {
            PdfValue value;
            if (dictionary.Kind != PdfValueKind.Dictionary || !dictionary.Dictionary.TryGetValue(key, out value))
                throw new InvalidDataException(message);
            return value;
        }

        private static int GetInteger(PdfValue dictionary, string key, int defaultValue, bool required)
        {
            PdfValue value;
            if (!dictionary.Dictionary.TryGetValue(key, out value))
            {
                if (required) throw new InvalidDataException("PDF 加密字典缺少 /" + key + "。");
                return defaultValue;
            }
            if (value.Kind != PdfValueKind.Integer || value.Number < Int32.MinValue || value.Number > Int32.MaxValue)
                throw new InvalidDataException("PDF 加密字典的 /" + key + " 不是有效整数。");
            return (int)value.Number;
        }

        private static string GetName(PdfValue dictionary, string key, bool required)
        {
            PdfValue value;
            if (!dictionary.Dictionary.TryGetValue(key, out value))
            {
                if (required) throw new InvalidDataException("PDF 加密字典缺少 /" + key + "。");
                return null;
            }
            if (value.Kind != PdfValueKind.Name)
                throw new InvalidDataException("PDF 加密字典的 /" + key + " 不是名称。");
            return value.Text;
        }

        private static byte[] GetString(PdfValue dictionary, string key, bool required)
        {
            PdfValue value;
            if (!dictionary.Dictionary.TryGetValue(key, out value))
            {
                if (required) throw new InvalidDataException("PDF 加密字典缺少 /" + key + "。");
                return null;
            }
            if (value.Kind != PdfValueKind.String)
                throw new InvalidDataException("PDF 加密字典的 /" + key + " 不是字符串。");
            return value.Bytes;
        }

        private static bool GetBoolean(PdfValue dictionary, string key, bool defaultValue)
        {
            PdfValue value;
            if (!dictionary.Dictionary.TryGetValue(key, out value)) return defaultValue;
            if (value.Kind == PdfValueKind.Boolean) return value.Boolean;
            if (value.Kind == PdfValueKind.Integer && (value.Number == 0 || value.Number == 1)) return value.Number != 0;
            throw new InvalidDataException("PDF 加密字典的 /" + key + " 不是布尔值。");
        }

        private static int LastIndexOfAscii(byte[] data, string text)
        {
            byte[] needle = Encoding.ASCII.GetBytes(text);
            for (int i = data.Length - needle.Length; i >= 0; i--)
            {
                int j = 0;
                while (j < needle.Length && data[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private sealed class CryptoWorkspace
        {
            public readonly byte[] PaddedPassword = new byte[32];
            public readonly byte[] OwnerDecoded = new byte[32];
            public readonly byte[] OwnerKey = new byte[16];
            public readonly byte[] EncryptionKey = new byte[16];
            public readonly byte[] IterationKey = new byte[16];
            public readonly byte[] UserCandidate = new byte[32];
            public readonly byte[] Digest = new byte[16];
            public readonly byte[] LittleEndianInt = new byte[4];
            public readonly byte[] FourFF = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
            public readonly byte[] SBox = new byte[256];
            public readonly Md5Context Md5 = new Md5Context();
        }

        private static class Rc4
        {
            public static void Transform(byte[] key, int keyLength, byte[] input, int count,
                byte[] output, byte[] state)
            {
                for (int i = 0; i < 256; i++) state[i] = (byte)i;
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + state[i] + key[i % keyLength]) & 255;
                    byte swap = state[i];
                    state[i] = state[j];
                    state[j] = swap;
                }
                int x = 0;
                j = 0;
                for (int index = 0; index < count; index++)
                {
                    x = (x + 1) & 255;
                    j = (j + state[x]) & 255;
                    byte swap = state[x];
                    state[x] = state[j];
                    state[j] = swap;
                    output[index] = (byte)(input[index] ^ state[(state[x] + state[j]) & 255]);
                }
            }
        }

        private sealed class Md5Context
        {
            private static readonly int[] Shift = new int[]
            {
                7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
            };

            private static readonly uint[] Constants = new uint[]
            {
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
            };

            private readonly byte[] buffer = new byte[64];
            private readonly uint[] words = new uint[16];
            private uint a;
            private uint b;
            private uint c;
            private uint d;
            private long totalBytes;
            private int buffered;

            public void Reset()
            {
                a = 0x67452301;
                b = 0xefcdab89;
                c = 0x98badcfe;
                d = 0x10325476;
                totalBytes = 0;
                buffered = 0;
            }

            public void Update(byte[] input, int offset, int count)
            {
                if (count <= 0) return;
                totalBytes += count;
                while (count > 0)
                {
                    int take = Math.Min(64 - buffered, count);
                    Buffer.BlockCopy(input, offset, buffer, buffered, take);
                    buffered += take;
                    offset += take;
                    count -= take;
                    if (buffered == 64)
                    {
                        Transform(buffer);
                        buffered = 0;
                    }
                }
            }

            public void Final(byte[] output)
            {
                ulong bitLength = unchecked((ulong)totalBytes * 8UL);
                buffer[buffered++] = 0x80;
                if (buffered > 56)
                {
                    Array.Clear(buffer, buffered, 64 - buffered);
                    Transform(buffer);
                    buffered = 0;
                }
                Array.Clear(buffer, buffered, 56 - buffered);
                for (int i = 0; i < 8; i++) buffer[56 + i] = (byte)(bitLength >> (8 * i));
                Transform(buffer);
                WriteUInt32(output, 0, a);
                WriteUInt32(output, 4, b);
                WriteUInt32(output, 8, c);
                WriteUInt32(output, 12, d);
                buffered = 0;
            }

            private void Transform(byte[] block)
            {
                unchecked
                {
                    for (int i = 0; i < 16; i++)
                    {
                        int offset = i * 4;
                        words[i] = (uint)(block[offset] | (block[offset + 1] << 8) |
                            (block[offset + 2] << 16) | (block[offset + 3] << 24));
                    }

                    uint aa = a;
                    uint bb = b;
                    uint cc = c;
                    uint dd = d;
                    for (int i = 0; i < 64; i++)
                    {
                        uint function;
                        int wordIndex;
                        if (i < 16)
                        {
                            function = (bb & cc) | ((~bb) & dd);
                            wordIndex = i;
                        }
                        else if (i < 32)
                        {
                            function = (dd & bb) | ((~dd) & cc);
                            wordIndex = (5 * i + 1) & 15;
                        }
                        else if (i < 48)
                        {
                            function = bb ^ cc ^ dd;
                            wordIndex = (3 * i + 5) & 15;
                        }
                        else
                        {
                            function = cc ^ (bb | (~dd));
                            wordIndex = (7 * i) & 15;
                        }

                        uint rotatedInput = aa + function + Constants[i] + words[wordIndex];
                        uint next = bb + RotateLeft(rotatedInput, Shift[i]);
                        aa = dd;
                        dd = cc;
                        cc = bb;
                        bb = next;
                    }
                    a += aa;
                    b += bb;
                    c += cc;
                    d += dd;
                }
            }

            private static uint RotateLeft(uint value, int count)
            {
                return (value << count) | (value >> (32 - count));
            }

            private static void WriteUInt32(byte[] output, int offset, uint value)
            {
                output[offset] = (byte)value;
                output[offset + 1] = (byte)(value >> 8);
                output[offset + 2] = (byte)(value >> 16);
                output[offset + 3] = (byte)(value >> 24);
            }
        }

        private sealed class XrefSection
        {
            public readonly Dictionary<int, XrefEntry> Entries = new Dictionary<int, XrefEntry>();
            public PdfValue Trailer;
        }

        private struct XrefEntry
        {
            public int Generation;
            public long Offset;
            public bool InUse;
        }

        private struct ObjectReference : IEquatable<ObjectReference>
        {
            public readonly int ObjectNumber;
            public readonly int Generation;

            public ObjectReference(int objectNumber, int generation)
            {
                ObjectNumber = objectNumber;
                Generation = generation;
            }

            public bool Equals(ObjectReference other)
            {
                return ObjectNumber == other.ObjectNumber && Generation == other.Generation;
            }

            public override bool Equals(object obj)
            {
                return obj is ObjectReference && Equals((ObjectReference)obj);
            }

            public override int GetHashCode()
            {
                unchecked { return (ObjectNumber * 397) ^ Generation; }
            }
        }

        private enum PdfValueKind
        {
            Null,
            Integer,
            Boolean,
            Name,
            String,
            Array,
            Dictionary,
            Reference,
            Keyword
        }

        private sealed class PdfValue
        {
            public PdfValueKind Kind;
            public long Number;
            public bool Boolean;
            public string Text;
            public byte[] Bytes;
            public List<PdfValue> Items;
            public Dictionary<string, PdfValue> Dictionary;
            public ObjectReference Reference;

            public static PdfValue CreateDictionary()
            {
                return new PdfValue
                {
                    Kind = PdfValueKind.Dictionary,
                    Dictionary = new Dictionary<string, PdfValue>(StringComparer.Ordinal)
                };
            }
        }

        private sealed class PdfReader
        {
            private readonly byte[] data;
            public int Position;

            public PdfReader(byte[] data, int position)
            {
                this.data = data;
                Position = position;
            }

            public string ReadWord()
            {
                SkipWhitespaceAndComments();
                if (Position >= data.Length) throw new EndOfStreamException("读取 PDF token 时意外到达文件末尾。");
                int start = Position;
                while (Position < data.Length && !IsWhitespace(data[Position]) && !IsDelimiter(data[Position])) Position++;
                if (Position == start)
                {
                    byte value = data[Position++];
                    if ((value == '<' || value == '>') && Position < data.Length && data[Position] == value)
                    {
                        Position++;
                        return value == '<' ? "<<" : ">>";
                    }
                    return ((char)value).ToString();
                }
                return Encoding.ASCII.GetString(data, start, Position - start);
            }

            public PdfValue ReadValue()
            {
                SkipWhitespaceAndComments();
                if (Position >= data.Length) throw new EndOfStreamException("读取 PDF 对象时意外到达文件末尾。");
                byte current = data[Position];
                if (current == '(') return ReadLiteralString();
                if (current == '[') return ReadArray();
                if (current == '/') return ReadName();
                if (current == '<')
                {
                    if (Position + 1 < data.Length && data[Position + 1] == '<') return ReadDictionary();
                    return ReadHexString();
                }

                string token = ReadWord();
                if (token == "true" || token == "false")
                    return new PdfValue { Kind = PdfValueKind.Boolean, Boolean = token == "true" };
                if (token == "null") return new PdfValue { Kind = PdfValueKind.Null };

                long number;
                if (Int64.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
                {
                    int afterFirst = Position;
                    try
                    {
                        string secondToken = ReadWord();
                        int generation;
                        if (Int32.TryParse(secondToken, NumberStyles.None, CultureInfo.InvariantCulture, out generation))
                        {
                            string referenceToken = ReadWord();
                            int objectNumber;
                            if (referenceToken == "R" && number >= 0 && number <= Int32.MaxValue)
                            {
                                objectNumber = (int)number;
                                return new PdfValue
                                {
                                    Kind = PdfValueKind.Reference,
                                    Reference = new ObjectReference(objectNumber, generation)
                                };
                            }
                        }
                    }
                    catch (EndOfStreamException) { }
                    Position = afterFirst;
                    return new PdfValue { Kind = PdfValueKind.Integer, Number = number };
                }
                return new PdfValue { Kind = PdfValueKind.Keyword, Text = token };
            }

            private PdfValue ReadDictionary()
            {
                Position += 2;
                PdfValue result = PdfValue.CreateDictionary();
                while (true)
                {
                    SkipWhitespaceAndComments();
                    if (Position + 1 >= data.Length) throw new EndOfStreamException("PDF 字典未闭合。");
                    if (data[Position] == '>' && data[Position + 1] == '>')
                    {
                        Position += 2;
                        return result;
                    }
                    PdfValue key = ReadName();
                    result.Dictionary[key.Text] = ReadValue();
                }
            }

            private PdfValue ReadArray()
            {
                Position++;
                PdfValue result = new PdfValue { Kind = PdfValueKind.Array, Items = new List<PdfValue>() };
                while (true)
                {
                    SkipWhitespaceAndComments();
                    if (Position >= data.Length) throw new EndOfStreamException("PDF 数组未闭合。");
                    if (data[Position] == ']')
                    {
                        Position++;
                        return result;
                    }
                    result.Items.Add(ReadValue());
                }
            }

            private PdfValue ReadName()
            {
                SkipWhitespaceAndComments();
                if (Position >= data.Length || data[Position] != '/') throw new InvalidDataException("PDF 字典键不是名称。");
                Position++;
                List<byte> bytes = new List<byte>();
                while (Position < data.Length && !IsWhitespace(data[Position]) && !IsDelimiter(data[Position]))
                {
                    if (data[Position] == '#' && Position + 2 < data.Length && IsHex(data[Position + 1]) && IsHex(data[Position + 2]))
                    {
                        bytes.Add((byte)((HexValue(data[Position + 1]) << 4) | HexValue(data[Position + 2])));
                        Position += 3;
                    }
                    else
                    {
                        bytes.Add(data[Position++]);
                    }
                }
                return new PdfValue { Kind = PdfValueKind.Name, Text = Encoding.GetEncoding(28591).GetString(bytes.ToArray()) };
            }

            private PdfValue ReadHexString()
            {
                Position++;
                List<byte> result = new List<byte>();
                int highNibble = -1;
                while (Position < data.Length)
                {
                    byte value = data[Position++];
                    if (value == '>')
                    {
                        if (highNibble >= 0) result.Add((byte)(highNibble << 4));
                        return new PdfValue { Kind = PdfValueKind.String, Bytes = result.ToArray() };
                    }
                    if (IsWhitespace(value)) continue;
                    if (!IsHex(value)) throw new InvalidDataException("PDF 十六进制字符串包含无效字符。");
                    int nibble = HexValue(value);
                    if (highNibble < 0) highNibble = nibble;
                    else
                    {
                        result.Add((byte)((highNibble << 4) | nibble));
                        highNibble = -1;
                    }
                }
                throw new EndOfStreamException("PDF 十六进制字符串未闭合。");
            }

            private PdfValue ReadLiteralString()
            {
                Position++;
                int depth = 1;
                List<byte> result = new List<byte>();
                while (Position < data.Length)
                {
                    byte value = data[Position++];
                    if (value == '\\')
                    {
                        if (Position >= data.Length) break;
                        byte escaped = data[Position++];
                        if (escaped == 'n') result.Add(0x0A);
                        else if (escaped == 'r') result.Add(0x0D);
                        else if (escaped == 't') result.Add(0x09);
                        else if (escaped == 'b') result.Add(0x08);
                        else if (escaped == 'f') result.Add(0x0C);
                        else if (escaped == '(' || escaped == ')' || escaped == '\\') result.Add(escaped);
                        else if (escaped == '\r' || escaped == '\n')
                        {
                            if (escaped == '\r' && Position < data.Length && data[Position] == '\n') Position++;
                        }
                        else if (escaped >= '0' && escaped <= '7')
                        {
                            int octal = escaped - '0';
                            int digits = 1;
                            while (digits < 3 && Position < data.Length && data[Position] >= '0' && data[Position] <= '7')
                            {
                                octal = octal * 8 + data[Position++] - '0';
                                digits++;
                            }
                            result.Add((byte)octal);
                        }
                        else result.Add(escaped);
                    }
                    else if (value == '(')
                    {
                        depth++;
                        result.Add(value);
                    }
                    else if (value == ')')
                    {
                        depth--;
                        if (depth == 0) return new PdfValue { Kind = PdfValueKind.String, Bytes = result.ToArray() };
                        result.Add(value);
                    }
                    else if (value == '\r')
                    {
                        if (Position < data.Length && data[Position] == '\n') Position++;
                        result.Add(0x0A);
                    }
                    else result.Add(value);
                }
                throw new EndOfStreamException("PDF literal string 未闭合。");
            }

            private void SkipWhitespaceAndComments()
            {
                while (Position < data.Length)
                {
                    if (IsWhitespace(data[Position]))
                    {
                        Position++;
                        continue;
                    }
                    if (data[Position] == '%')
                    {
                        while (Position < data.Length && data[Position] != '\r' && data[Position] != '\n') Position++;
                        continue;
                    }
                    break;
                }
            }

            private static bool IsWhitespace(byte value)
            {
                return value == 0 || value == 9 || value == 10 || value == 12 || value == 13 || value == 32;
            }

            private static bool IsDelimiter(byte value)
            {
                return value == '(' || value == ')' || value == '<' || value == '>' || value == '[' ||
                    value == ']' || value == '{' || value == '}' || value == '/' || value == '%';
            }

            private static bool IsHex(byte value)
            {
                return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'F') || (value >= 'a' && value <= 'f');
            }

            private static int HexValue(byte value)
            {
                if (value >= '0' && value <= '9') return value - '0';
                if (value >= 'A' && value <= 'F') return value - 'A' + 10;
                return value - 'a' + 10;
            }
        }
    }
}

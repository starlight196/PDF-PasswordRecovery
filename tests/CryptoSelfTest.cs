using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using PdfPasswordRecovery;

internal static class CryptoSelfTest
{
    private static int failures;

    public static int Main()
    {
        string tempDirectory = Path.Combine(
            Path.GetTempPath(),
            "PdfPasswordRecovery-CryptoSelfTest-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(tempDirectory);

        try
        {
            Run("Revision 2, literal O/U strings", delegate
            {
                string path = Path.Combine(tempDirectory, "r2.pdf");
                WriteFixture(
                    path,
                    1,
                    2,
                    40,
                    -44,
                    ToPdfOctalLiteral("C44DA2329927CC7C8FD110FC193362339817384B584574692669600A8890E253"),
                    ToPdfOctalLiteral("E6D718581000C82B96F05303B967C5027A4B6F193C0143D00FE9012725C10B35"),
                    "00112233445566778899AABBCCDDEEFF",
                    null);

                AssertPasswords(path, "user-r2", "owner-r2");
                AssertDictionaryAttack(tempDirectory, path, "user-r2");
                AssertPausedStop(tempDirectory, path);
                AssertActiveDispose(tempDirectory, path);
            });

            Run("Revision 2, empty user password", delegate
            {
                string path = Path.Combine(tempDirectory, "r2-empty-password.pdf");
                WriteFixture(
                    path,
                    1,
                    2,
                    40,
                    -44,
                    "<EF01EE06294DC63F3007DBD6B24772E750A94BF317740C16DBCB38657EBCA8B0>",
                    "<C32F424A71F014845F9110B9D428B3BAA9D1E5BD4BB9AFFA75F707A7188BC9EE>",
                    "102132435465768798A9BACBDCEDFE0F",
                    null);

                AssertPasswords(path, String.Empty, "owner-empty-r2");
                AssertDictionaryAttack(tempDirectory, path, String.Empty);
            });

            Run("Revision 3, hexadecimal O/U strings", delegate
            {
                string path = Path.Combine(tempDirectory, "r3.pdf");
                WriteFixture(
                    path,
                    2,
                    3,
                    128,
                    -1028,
                    "<964A125365D0823596223377A2662F68D5D287A95F697AF269D3D2707CE1561A>",
                    "<818B4CBCC1FCB96C93F5CAD5A76E857600000000000000000000000000000000>",
                    "11223344556677889900AABBCCDDEEFF",
                    null);

                AssertPasswords(path, "user-r3", "owner-r3");
            });

            Run("Revision 4, EncryptMetadata false", delegate
            {
                string path = Path.Combine(tempDirectory, "r4.pdf");
                WriteFixture(
                    path,
                    4,
                    4,
                    128,
                    -3904,
                    "<EBDB2C1602FB652C36B14BE72F8D803D4A99DE4CA839872FEAA49EB2BAC027AD>",
                    "<F3C0577B7869B766A3EE1661B2A07CCF00000000000000000000000000000000>",
                    "A1A2A3A4A5A6A7A8A9AAABACADAEAFB0",
                    false);

                AssertPasswords(path, "user-r4", "owner-r4");
            });

            Run("GB18030 detection after ASCII prefix", delegate
            {
                AssertDictionaryEncodingFallback(tempDirectory);
            });

            Run("Incremental xref free entry shadows older object", delegate
            {
                string path = Path.Combine(tempDirectory, "incremental-free-entry.pdf");
                const string fileId = "2031425364758697A8B9CADBECFD0E1F";
                WriteFixture(
                    path,
                    1,
                    2,
                    40,
                    -44,
                    ToPdfOctalLiteral("C44DA2329927CC7C8FD110FC193362339817384B584574692669600A8890E253"),
                    ToPdfOctalLiteral("E6D718581000C82B96F05303B967C5027A4B6F193C0143D00FE9012725C10B35"),
                    fileId,
                    null);
                AppendFreeEncryptionObjectUpdate(path, fileId);

                try
                {
                    PdfSecurity.Load(path);
                    throw new InvalidOperationException("an older freed encryption object was incorrectly reused");
                }
                catch (InvalidDataException)
                {
                    // The newest xref section marks the encryption object as free.
                }
            });

            Run("Encrypted password vault round trip", delegate
            {
                AssertPasswordVaultRoundTrip(tempDirectory);
            });

            Run("Password vault rejects tampering", delegate
            {
                AssertPasswordVaultRejectsTampering(tempDirectory);
            });

            Run("Password vault rejects stale and missing updates", delegate
            {
                AssertPasswordVaultConcurrency(tempDirectory);
            });

            Run("Password vault rejects duplicate document types", delegate
            {
                AssertPasswordVaultDuplicateProtection(tempDirectory);
            });

            Run("Password document fingerprint normalization", delegate
            {
                AssertPasswordDocumentFingerprint(tempDirectory);
            });
        }
        finally
        {
            try
            {
                Directory.Delete(tempDirectory, true);
            }
            catch
            {
                // A cleanup failure must not hide a crypto test result.
            }
        }

        Console.WriteLine(failures == 0 ? "All crypto self-tests passed." : failures + " crypto self-test(s) failed.");
        return failures == 0 ? 0 : 1;
    }

    private static void AssertPasswords(string path, string userPassword, string ownerPassword)
    {
        PdfSecurityInfo info = PdfSecurity.Load(path);

        AssertEqual(
            PasswordMatch.User,
            PdfSecurity.VerifyPassword(info, Encoding.ASCII.GetBytes(userPassword)),
            "user password");
        AssertEqual(
            PasswordMatch.Owner,
            PdfSecurity.VerifyPassword(info, Encoding.ASCII.GetBytes(ownerPassword)),
            "owner password");
        AssertEqual(
            PasswordMatch.None,
            PdfSecurity.VerifyPassword(info, Encoding.ASCII.GetBytes("definitely-wrong")),
            "wrong password");
    }

    private static void AssertDictionaryAttack(string directory, string pdfPath, string expectedPassword)
    {
        string dictionaryPath = Path.Combine(directory, "found-dictionary.txt");
        File.WriteAllLines(dictionaryPath, new string[] { "wrong-one", "wrong-two", expectedPassword }, new UTF8Encoding(false));
        DictionaryInfo dictionary = DictionaryInfo.Analyze(dictionaryPath, "自动检测");
        PdfSecurityInfo info = PdfSecurity.Load(pdfPath);

        using (DictionaryAttack attack = new DictionaryAttack())
        using (ManualResetEventSlim completed = new ManualResetEventSlim(false))
        {
            attack.Completed += delegate { completed.Set(); };
            attack.Start(info, dictionary, 2, new UTF8Encoding(false), false, false);
            if (!completed.Wait(TimeSpan.FromSeconds(10)))
                throw new TimeoutException("dictionary attack did not complete");

            AttackSnapshot snapshot = attack.GetSnapshot();
            if (snapshot.State != AttackState.Found || snapshot.FoundPassword != expectedPassword ||
                snapshot.Match != PasswordMatch.User)
                throw new InvalidOperationException("dictionary attack did not report the expected user password");
            if (snapshot.Attempts != 3)
                throw new InvalidOperationException("dictionary attack reported an inaccurate attempt count");
        }
    }

    private static void AssertPausedStop(string directory, string pdfPath)
    {
        string dictionaryPath = Path.Combine(directory, "stop-dictionary.txt");
        using (StreamWriter writer = new StreamWriter(dictionaryPath, false, new UTF8Encoding(false)))
        {
            for (int i = 0; i < 200000; i++) writer.WriteLine("wrong-" + i.ToString("D6", CultureInfo.InvariantCulture));
        }
        DictionaryInfo dictionary = DictionaryInfo.Analyze(dictionaryPath, "自动检测");
        PdfSecurityInfo info = PdfSecurity.Load(pdfPath);

        using (DictionaryAttack attack = new DictionaryAttack())
        using (ManualResetEventSlim completed = new ManualResetEventSlim(false))
        {
            attack.Completed += delegate { completed.Set(); };
            attack.Start(info, dictionary, 2, new UTF8Encoding(false), false, false);
            DateTime waitDeadline = DateTime.UtcNow.AddSeconds(5);
            while (attack.GetSnapshot().Attempts < 128 && DateTime.UtcNow < waitDeadline)
                Thread.Sleep(1);
            attack.TogglePause();
            Thread.Sleep(40);
            AttackSnapshot paused = attack.GetSnapshot();
            if (paused.State != AttackState.Paused)
                throw new InvalidOperationException("attack did not enter the paused state");

            Thread.Sleep(100);
            long settledAttempts = attack.GetSnapshot().Attempts;
            Thread.Sleep(100);
            if (attack.GetSnapshot().Attempts != settledAttempts)
                throw new InvalidOperationException("attempt count continued changing while paused");

            attack.Stop();
            if (!completed.Wait(TimeSpan.FromSeconds(10)))
                throw new TimeoutException("paused attack did not stop cleanly");
            if (attack.GetSnapshot().State != AttackState.Stopped)
                throw new InvalidOperationException("stopped attack reported an unexpected terminal state");
        }
    }

    private static void AssertActiveDispose(string directory, string pdfPath)
    {
        string dictionaryPath = Path.Combine(directory, "stop-dictionary.txt");
        DictionaryInfo dictionary = DictionaryInfo.Analyze(dictionaryPath, "自动检测");
        PdfSecurityInfo info = PdfSecurity.Load(pdfPath);
        DictionaryAttack attack = new DictionaryAttack();
        attack.Start(info, dictionary, 2, new UTF8Encoding(false), false, false);
        attack.Dispose();

        AttackState state = attack.GetSnapshot().State;
        if (state != AttackState.Stopped && state != AttackState.Exhausted)
            throw new InvalidOperationException("disposing an active attack did not wait for a terminal state");
    }

    private static void AssertDictionaryEncodingFallback(string directory)
    {
        string path = Path.Combine(directory, "gb18030-after-ascii-prefix.txt");
        Encoding gb18030 = Encoding.GetEncoding(
            "GB18030", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
        string content = new string('a', 70 * 1024) + Environment.NewLine + "中文密码" + Environment.NewLine;
        File.WriteAllText(path, content, gb18030);

        DictionaryInfo info = DictionaryInfo.Analyze(path, "自动检测");
        if (info.Encoding.CodePage != 54936)
            throw new InvalidOperationException("GB18030 dictionary was incorrectly detected as " + info.EncodingLabel);
        if (info.CandidateCount != 2)
            throw new InvalidOperationException("GB18030 dictionary line count was incorrect");
    }

    private static void AppendFreeEncryptionObjectUpdate(string path, string fileIdHex)
    {
        byte[] original = File.ReadAllBytes(path);
        string text = Encoding.ASCII.GetString(original);
        int marker = text.LastIndexOf("startxref", StringComparison.Ordinal);
        if (marker < 0) throw new InvalidDataException("fixture is missing startxref");

        int start = marker + "startxref".Length;
        while (start < text.Length && Char.IsWhiteSpace(text[start])) start++;
        int end = start;
        while (end < text.Length && Char.IsDigit(text[end])) end++;
        long previousXref = Int64.Parse(text.Substring(start, end - start), CultureInfo.InvariantCulture);

        using (FileStream output = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None))
        {
            long xrefOffset = output.Position;
            WriteAscii(output, "xref\n2 1\n0000000000 00001 f \n");
            WriteAscii(
                output,
                "trailer\n<< /Size 4 /Root 1 0 R /Encrypt 2 0 R /ID [<" + fileIdHex + "><" +
                fileIdHex + ">] /Prev " + previousXref.ToString(CultureInfo.InvariantCulture) + " >>\n");
            WriteAscii(output, "startxref\n" + xrefOffset.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n");
        }
    }

    private static void AssertPasswordVaultRoundTrip(string directory)
    {
        string path = Path.Combine(directory, "round-trip-passwords.vault");
        PasswordVault vault = new PasswordVault(path);
        PasswordRecord first = vault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "测试文档.pdf"),
            Password = "测试密码-123",
            Match = PasswordMatch.User,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = "合成测试记录",
            DocumentFingerprint = CreateFingerprint(1)
        });

        if (first.Id == Guid.Empty || first.CreatedUtc.Kind != DateTimeKind.Utc ||
            first.UpdatedUtc.Kind != DateTimeKind.Utc)
            throw new InvalidOperationException("password vault did not initialize record metadata");

        byte[] fileBytes = File.ReadAllBytes(path);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(first.Password);
        if (ContainsSequence(fileBytes, passwordBytes))
            throw new InvalidOperationException("password vault file contains the plaintext password");

        System.Collections.Generic.List<PasswordRecord> loaded = vault.Load();
        if (loaded.Count != 1 || loaded[0].Password != first.Password || loaded[0].Note != first.Note ||
            loaded[0].Match != PasswordMatch.User)
            throw new InvalidOperationException("password vault round trip changed record data");

        first.FilePath = Path.Combine(directory, "移动后的文档.pdf");
        first.Note = "已更新";
        PasswordRecord updated = vault.Upsert(first);
        if (updated.Id != first.Id || vault.Load().Count != 1)
            throw new InvalidOperationException("password vault update created a duplicate record");

        PasswordRecord emptyPassword = vault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "空密码.pdf"),
            Password = String.Empty,
            Match = PasswordMatch.Owner,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = String.Empty,
            DocumentFingerprint = CreateFingerprint(2)
        });
        loaded = vault.Load();
        if (loaded.Count != 2 || emptyPassword.Password.Length != 0)
            throw new InvalidOperationException("password vault did not preserve an empty password");

        vault.Delete(updated.Id);
        loaded = vault.Load();
        if (loaded.Count != 1 || loaded[0].Id != emptyPassword.Id)
            throw new InvalidOperationException("password vault delete removed the wrong record");
    }

    private static void AssertPasswordVaultRejectsTampering(string directory)
    {
        string path = Path.Combine(directory, "tampered-passwords.vault");
        PasswordVault vault = new PasswordVault(path);
        vault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "tamper.pdf"),
            Password = "synthetic-vault-password",
            Match = PasswordMatch.User,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = String.Empty,
            DocumentFingerprint = CreateFingerprint(3)
        });

        byte[] damaged = File.ReadAllBytes(path);
        damaged[damaged.Length - 1] ^= 0x40;
        File.WriteAllBytes(path, damaged);

        AssertVaultFailure(delegate { vault.Load(); }, "tampered vault load");
        AssertVaultFailure(delegate
        {
            vault.Upsert(new PasswordRecord
            {
                FilePath = Path.Combine(directory, "must-not-overwrite.pdf"),
                Password = "another-synthetic-password",
                Match = PasswordMatch.User,
                PasswordEncodingCodePage = Encoding.UTF8.CodePage,
                Note = String.Empty,
                DocumentFingerprint = CreateFingerprint(4)
            });
        }, "tampered vault update");

        byte[] afterFailure = File.ReadAllBytes(path);
        if (!ByteArraysEqual(damaged, afterFailure))
            throw new InvalidOperationException("failed vault update overwrote the damaged source file");
    }

    private static void AssertPasswordVaultConcurrency(string directory)
    {
        string path = Path.Combine(directory, "concurrent-passwords.vault");
        PasswordVault firstVault = new PasswordVault(path);
        PasswordRecord created = firstVault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "concurrent.pdf"),
            Password = "initial-password",
            Match = PasswordMatch.User,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = "initial",
            DocumentFingerprint = CreateFingerprint(5)
        });

        PasswordVault secondVault = new PasswordVault(path);
        PasswordRecord stale = firstVault.Load()[0];
        PasswordRecord current = secondVault.Load()[0];
        current.Note = "second writer";
        current.UpdatedUtc = DateTime.UtcNow;
        PasswordRecord secondWrite = secondVault.Upsert(current);

        stale.Note = "stale first writer";
        stale.UpdatedUtc = DateTime.UtcNow;
        AssertVaultFailure(delegate { firstVault.Upsert(stale); }, "stale vault update");

        PasswordRecord afterConflict = firstVault.Load()[0];
        if (afterConflict.Id != created.Id || afterConflict.Note != secondWrite.Note)
            throw new InvalidOperationException("stale update changed the current vault record");

        PasswordRecord missing = afterConflict.Clone();
        missing.Id = Guid.NewGuid();
        missing.Note = "must not be inserted";
        missing.UpdatedUtc = DateTime.UtcNow;
        AssertVaultFailure(delegate { firstVault.Upsert(missing); }, "missing-id vault update");

        System.Collections.Generic.List<PasswordRecord> finalRecords = firstVault.Load();
        if (finalRecords.Count != 1 || finalRecords[0].Id != created.Id ||
            finalRecords[0].Note != secondWrite.Note)
            throw new InvalidOperationException("missing-id update inserted or replaced a vault record");
    }

    private static void AssertVaultFailure(Action action, string caseName)
    {
        try
        {
            action();
        }
        catch (PasswordVaultException)
        {
            return;
        }
        throw new InvalidOperationException(caseName + " unexpectedly succeeded");
    }

    private static void AssertPasswordVaultDuplicateProtection(string directory)
    {
        string path = Path.Combine(directory, "duplicate-passwords.vault");
        PasswordVault vault = new PasswordVault(path);
        PasswordRecord first = vault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "first.pdf"),
            Password = "first-password",
            Match = PasswordMatch.User,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = String.Empty,
            DocumentFingerprint = CreateFingerprint(6)
        });

        AssertVaultFailure(delegate
        {
            vault.Upsert(new PasswordRecord
            {
                FilePath = Path.Combine(directory, "duplicate.pdf"),
                Password = "must-not-overwrite",
                Match = PasswordMatch.User,
                PasswordEncodingCodePage = Encoding.UTF8.CodePage,
                Note = String.Empty,
                DocumentFingerprint = CreateFingerprint(6)
            });
        }, "duplicate document/type insert");

        PasswordRecord second = vault.Upsert(new PasswordRecord
        {
            FilePath = Path.Combine(directory, "second.pdf"),
            Password = "second-password",
            Match = PasswordMatch.User,
            PasswordEncodingCodePage = Encoding.UTF8.CodePage,
            Note = String.Empty,
            DocumentFingerprint = CreateFingerprint(7)
        });
        second.DocumentFingerprint = CreateFingerprint(6);
        AssertVaultFailure(delegate { vault.Upsert(second); }, "duplicate document/type update");

        System.Collections.Generic.List<PasswordRecord> records = vault.Load();
        if (records.Count != 2 || records[0].Password == "must-not-overwrite" ||
            records[1].Password == "must-not-overwrite" || first.Id == second.Id)
            throw new InvalidOperationException("duplicate protection changed existing records");
    }

    private static byte[] CreateFingerprint(byte seed)
    {
        byte[] result = new byte[32];
        for (int i = 0; i < result.Length; i++) result[i] = (byte)(seed + i);
        return result;
    }

    private static void AssertPasswordDocumentFingerprint(string directory)
    {
        string path = Path.Combine(directory, "Folder", "Document.pdf");
        string equivalentPath = Path.Combine(directory, ".", "folder", "DOCUMENT.PDF");
        string differentPath = Path.Combine(directory, "Folder", "Other.pdf");
        byte[] first = PasswordDocumentFingerprint.FromPath(path);
        byte[] equivalent = PasswordDocumentFingerprint.FromPath(equivalentPath);
        byte[] different = PasswordDocumentFingerprint.FromPath(differentPath);

        if (!ByteArraysEqual(first, equivalent))
            throw new InvalidOperationException("equivalent Windows paths produced different fingerprints");
        if (ByteArraysEqual(first, different))
            throw new InvalidOperationException("different paths produced the same fingerprint");
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0) return true;
        for (int index = 0; index <= haystack.Length - needle.Length; index++)
        {
            int offset = 0;
            while (offset < needle.Length && haystack[index + offset] == needle[offset]) offset++;
            if (offset == needle.Length) return true;
        }
        return false;
    }

    private static bool ByteArraysEqual(byte[] left, byte[] right)
    {
        if (left.Length != right.Length) return false;
        int difference = 0;
        for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
        return difference == 0;
    }

    private static void AssertEqual(PasswordMatch expected, PasswordMatch actual, string caseName)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                caseName + ": expected " + expected + ", actual " + actual + ".");
        }
    }

    private static void Run(string name, Action test)
    {
        try
        {
            test();
            Console.WriteLine("[PASS] " + name);
        }
        catch (Exception exception)
        {
            failures++;
            Console.Error.WriteLine("[FAIL] " + name + ": " + exception.Message);
        }
    }

    private static void WriteFixture(
        string path,
        int version,
        int revision,
        int keyLengthBits,
        int permissions,
        string ownerToken,
        string userToken,
        string fileIdHex,
        bool? encryptMetadata)
    {
        using (MemoryStream output = new MemoryStream())
        {
            WriteAscii(output, "%PDF-1.4\n% crypto self-test fixture\n");

            long catalogOffset = output.Position;
            WriteAscii(output, "1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n");

            long encryptionOffset = output.Position;
            StringBuilder dictionary = new StringBuilder();
            dictionary.Append("2 0 obj\n<< /Filter /Standard");
            dictionary.Append(" /V ").Append(version.ToString(CultureInfo.InvariantCulture));
            dictionary.Append(" /R ").Append(revision.ToString(CultureInfo.InvariantCulture));
            dictionary.Append(" /Length ").Append(keyLengthBits.ToString(CultureInfo.InvariantCulture));
            dictionary.Append(" /P ").Append(permissions.ToString(CultureInfo.InvariantCulture));
            dictionary.Append("\n/O ").Append(ownerToken);
            dictionary.Append("\n/U ").Append(userToken);

            if (revision == 4)
            {
                dictionary.Append("\n/CF << /StdCF << /CFM /AESV2 /Length 16 /AuthEvent /DocOpen >> >>");
                dictionary.Append(" /StmF /StdCF /StrF /StdCF");
            }

            if (encryptMetadata.HasValue)
            {
                dictionary.Append("\n/EncryptMetadata ").Append(encryptMetadata.Value ? "true" : "false");
            }

            dictionary.Append("\n>>\nendobj\n");
            WriteAscii(output, dictionary.ToString());

            long pagesOffset = output.Position;
            WriteAscii(output, "3 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");

            long xrefOffset = output.Position;
            WriteAscii(output, "xref\n0 4\n");
            WriteAscii(output, "0000000000 65535 f \n");
            WriteAscii(output, FormatOffset(catalogOffset) + " 00000 n \n");
            WriteAscii(output, FormatOffset(encryptionOffset) + " 00000 n \n");
            WriteAscii(output, FormatOffset(pagesOffset) + " 00000 n \n");
            WriteAscii(output, "trailer\n");
            WriteAscii(
                output,
                "<< /Size 4 /Root 1 0 R /Encrypt 2 0 R /ID [<" + fileIdHex + "><" + fileIdHex + ">] >>\n");
            WriteAscii(output, "startxref\n" + xrefOffset.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n");

            File.WriteAllBytes(path, output.ToArray());
        }
    }

    private static string FormatOffset(long value)
    {
        return value.ToString("0000000000", CultureInfo.InvariantCulture);
    }

    private static void WriteAscii(Stream output, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        output.Write(bytes, 0, bytes.Length);
    }

    private static string ToPdfOctalLiteral(string hex)
    {
        if ((hex.Length & 1) != 0)
        {
            throw new ArgumentException("Hex text must have an even length.", "hex");
        }

        StringBuilder token = new StringBuilder(2 + (hex.Length / 2 * 4));
        token.Append('(');

        for (int index = 0; index < hex.Length; index += 2)
        {
            int value = int.Parse(hex.Substring(index, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            token.Append('\\');
            token.Append((char)('0' + ((value >> 6) & 7)));
            token.Append((char)('0' + ((value >> 3) & 7)));
            token.Append((char)('0' + (value & 7)));
        }

        token.Append(')');
        return token.ToString();
    }
}

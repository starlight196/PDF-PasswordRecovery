using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PdfPasswordRecovery
{
    internal static class PasswordDocumentFingerprint
    {
        private static readonly byte[] Domain = Encoding.ASCII.GetBytes(
            "PdfPasswordRecovery.PathFingerprint.v1\0");
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        public static byte[] FromPath(string path)
        {
            string normalized = NormalizePath(path).ToUpperInvariant();
            byte[] pathBytes = null;
            byte[] input = null;
            try
            {
                pathBytes = StrictUtf8.GetBytes(normalized);
                input = new byte[Domain.Length + pathBytes.Length];
                Buffer.BlockCopy(Domain, 0, input, 0, Domain.Length);
                Buffer.BlockCopy(pathBytes, 0, input, Domain.Length, pathBytes.Length);
                using (SHA256 algorithm = SHA256.Create())
                    return algorithm.ComputeHash(input);
            }
            finally
            {
                if (pathBytes != null) Array.Clear(pathBytes, 0, pathBytes.Length);
                if (input != null) Array.Clear(input, 0, input.Length);
            }
        }

        public static string NormalizePath(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException("PDF 路径不能为空。", "path");

            string fullPath = Path.GetFullPath(path.Trim());
            string root = Path.GetPathRoot(fullPath);
            if (!String.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
                fullPath = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return fullPath;
        }
    }
}

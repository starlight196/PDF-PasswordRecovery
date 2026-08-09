using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PdfPasswordRecovery
{
    internal enum AttackState
    {
        Ready,
        Running,
        Paused,
        Found,
        Exhausted,
        Stopped,
        Failed
    }

    internal sealed class AttackSnapshot
    {
        public AttackState State;
        public long Attempts;
        public long TotalCandidates;
        public double CandidatesPerSecond;
        public TimeSpan Elapsed;
        public string CurrentCandidate;
        public string FoundPassword;
        public PasswordMatch Match;
        public string ErrorMessage;
    }

    internal sealed class DictionaryInfo
    {
        public string Path;
        public Encoding Encoding;
        public long CandidateCount;
        public long ByteLength;
        public string EncodingLabel;

        public static DictionaryInfo Analyze(string path, string requestedEncoding)
        {
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
                throw new FileNotFoundException("找不到字典文件。", path);

            Encoding encoding = ResolveEncoding(path, requestedEncoding);
            long count;
            try
            {
                count = CountLines(path, encoding, out encoding);
            }
            catch (DecoderFallbackException)
            {
                bool automaticUtf8WithoutBom =
                    String.Equals(requestedEncoding, "自动检测", StringComparison.Ordinal) &&
                    encoding.CodePage == 65001 && encoding.GetPreamble().Length == 0;
                if (!automaticUtf8WithoutBom) throw;

                encoding = Encoding.GetEncoding(
                    "GB18030", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                count = CountLines(path, encoding, out encoding);
            }

            FileInfo file = new FileInfo(path);
            return new DictionaryInfo
            {
                Path = path,
                Encoding = encoding,
                CandidateCount = count,
                ByteLength = file.Length,
                EncodingLabel = FriendlyEncodingName(encoding)
            };
        }

        private static long CountLines(string path, Encoding requestedEncoding, out Encoding actualEncoding)
        {
            long count = 0;
            using (StreamReader reader = new StreamReader(path, requestedEncoding, true, 1024 * 1024))
            {
                while (reader.ReadLine() != null) count++;
                actualEncoding = reader.CurrentEncoding;
            }
            return count;
        }

        private static Encoding ResolveEncoding(string path, string requestedEncoding)
        {
            if (!String.Equals(requestedEncoding, "自动检测", StringComparison.Ordinal))
            {
                if (String.Equals(requestedEncoding, "UTF-8", StringComparison.Ordinal))
                    return new UTF8Encoding(false, true);
                if (String.Equals(requestedEncoding, "GB18030", StringComparison.Ordinal))
                    return Encoding.GetEncoding(
                        "GB18030", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                if (String.Equals(requestedEncoding, "UTF-16 LE", StringComparison.Ordinal))
                    return new UnicodeEncoding(false, true, true);
                if (String.Equals(requestedEncoding, "UTF-16 BE", StringComparison.Ordinal))
                    return new UnicodeEncoding(true, true, true);
            }

            byte[] sample = new byte[64 * 1024];
            int read;
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                read = stream.Read(sample, 0, sample.Length);

            if (read >= 3 && sample[0] == 0xEF && sample[1] == 0xBB && sample[2] == 0xBF)
                return new UTF8Encoding(true, true);
            if (read >= 2 && sample[0] == 0xFF && sample[1] == 0xFE)
                return new UnicodeEncoding(false, true, true);
            if (read >= 2 && sample[0] == 0xFE && sample[1] == 0xFF)
                return new UnicodeEncoding(true, true, true);

            try
            {
                new UTF8Encoding(false, true).GetString(sample, 0, read);
                return new UTF8Encoding(false, true);
            }
            catch (DecoderFallbackException)
            {
                return Encoding.GetEncoding(
                    "GB18030", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
            }
        }

        private static string FriendlyEncodingName(Encoding encoding)
        {
            if (encoding.CodePage == 65001) return "UTF-8";
            if (encoding.CodePage == 54936) return "GB18030";
            if (encoding.CodePage == 1200) return "UTF-16 LE";
            if (encoding.CodePage == 1201) return "UTF-16 BE";
            return encoding.WebName;
        }
    }

    internal sealed class DictionaryAttack : IDisposable
    {
        private const int BatchSize = 256;
        private readonly object sync = new object();
        private readonly ManualResetEventSlim pauseGate = new ManualResetEventSlim(true);
        private CancellationTokenSource cancellation;
        private Task coordinator;
        private Stopwatch stopwatch;
        private volatile AttackState state = AttackState.Ready;
        private long attempts;
        private long totalCandidates;
        private string currentCandidate = String.Empty;
        private string foundPassword;
        private PasswordMatch match;
        private string errorMessage;
        private long lastRateAttempts;
        private long lastRateTicks;
        private double displayedRate;
        private bool disposed;
        private int resourcesDisposed;

        public event EventHandler Completed;

        public bool IsActive
        {
            get { return state == AttackState.Running || state == AttackState.Paused; }
        }

        public void Start(PdfSecurityInfo security, DictionaryInfo dictionary, int workerCount,
            Encoding passwordEncoding, bool trimWhitespace, bool skipEmpty)
        {
            if (security == null) throw new ArgumentNullException("security");
            if (dictionary == null) throw new ArgumentNullException("dictionary");

            Task previousCoordinator;
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException("DictionaryAttack");
                if (IsActive) throw new InvalidOperationException("已有任务正在运行。");
                previousCoordinator = coordinator;
            }

            if (previousCoordinator != null && !previousCoordinator.IsCompleted)
            {
                if (Task.CurrentId.HasValue && Task.CurrentId.Value == previousCoordinator.Id)
                    throw new InvalidOperationException("不能在任务完成回调中立即启动新任务。");
                try { previousCoordinator.Wait(); }
                catch (AggregateException) { }
            }

            CancellationTokenSource previousCancellation;
            CancellationTokenSource source = new CancellationTokenSource();
            lock (sync)
            {
                if (disposed)
                {
                    source.Dispose();
                    throw new ObjectDisposedException("DictionaryAttack");
                }
                if (IsActive)
                {
                    source.Dispose();
                    throw new InvalidOperationException("已有任务正在运行。");
                }

                previousCancellation = cancellation;
                cancellation = source;
                pauseGate.Set();
                attempts = 0;
                totalCandidates = dictionary.CandidateCount;
                currentCandidate = String.Empty;
                foundPassword = null;
                match = PasswordMatch.None;
                errorMessage = null;
                displayedRate = 0;
                lastRateAttempts = 0;
                lastRateTicks = Stopwatch.GetTimestamp();
                stopwatch = Stopwatch.StartNew();
                state = AttackState.Running;

                coordinator = Task.Factory.StartNew(
                    delegate
                    {
                        RunAttack(security, dictionary, Math.Max(1, workerCount), passwordEncoding,
                            trimWhitespace, skipEmpty, source);
                    },
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
            }
            if (previousCancellation != null) previousCancellation.Dispose();
        }

        public void TogglePause()
        {
            lock (sync)
            {
                if (disposed) return;
                if (state == AttackState.Running)
                {
                    pauseGate.Reset();
                    state = AttackState.Paused;
                    if (stopwatch != null) stopwatch.Stop();
                }
                else if (state == AttackState.Paused)
                {
                    pauseGate.Set();
                    state = AttackState.Running;
                    if (stopwatch != null) stopwatch.Start();
                    lastRateAttempts = Interlocked.Read(ref attempts);
                    lastRateTicks = Stopwatch.GetTimestamp();
                    displayedRate = 0;
                }
            }
        }

        public void Stop()
        {
            CancellationTokenSource source = cancellation;
            if (source == null || !IsActive) return;
            pauseGate.Set();
            source.Cancel();
        }

        public AttackSnapshot GetSnapshot()
        {
            long count = Interlocked.Read(ref attempts);
            long now = Stopwatch.GetTimestamp();
            long tickDelta = now - lastRateTicks;
            if (state == AttackState.Running && tickDelta >= Stopwatch.Frequency / 4)
            {
                long countDelta = count - lastRateAttempts;
                double instant = countDelta * (double)Stopwatch.Frequency / tickDelta;
                displayedRate = displayedRate == 0 ? instant : displayedRate * 0.65 + instant * 0.35;
                lastRateAttempts = count;
                lastRateTicks = now;
            }

            lock (sync)
            {
                return new AttackSnapshot
                {
                    State = state,
                    Attempts = count,
                    TotalCandidates = totalCandidates,
                    CandidatesPerSecond = state == AttackState.Paused ? 0 : displayedRate,
                    Elapsed = stopwatch == null ? TimeSpan.Zero : stopwatch.Elapsed,
                    CurrentCandidate = currentCandidate,
                    FoundPassword = foundPassword,
                    Match = match,
                    ErrorMessage = errorMessage
                };
            }
        }

        private void RunAttack(PdfSecurityInfo security, DictionaryInfo dictionary, int workerCount,
            Encoding passwordEncoding, bool trimWhitespace, bool skipEmpty, CancellationTokenSource source)
        {
            CancellationToken token = source.Token;
            BlockingCollection<string[]> queue = new BlockingCollection<string[]>(workerCount * 4);
            Task producer = Task.Factory.StartNew(
                delegate { Produce(dictionary, queue, token); }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            List<Task> workers = new List<Task>();

            for (int index = 0; index < workerCount; index++)
            {
                Task worker = Task.Factory.StartNew(
                    delegate { Consume(security, queue, passwordEncoding, trimWhitespace, skipEmpty, source, token); },
                    CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                workers.Add(worker);
            }

            Exception failure = null;
            try
            {
                Task.WaitAll(workers.ToArray());
            }
            catch (AggregateException ex)
            {
                failure = FindNonCancellationFailure(ex);
                source.Cancel();
                pauseGate.Set();
            }
            catch (Exception ex)
            {
                failure = ex;
                source.Cancel();
                pauseGate.Set();
            }

            try
            {
                producer.Wait();
            }
            catch (AggregateException ex)
            {
                Exception producerFailure = FindNonCancellationFailure(ex);
                if (failure == null) failure = producerFailure;
            }
            catch (Exception ex)
            {
                if (!(ex is OperationCanceledException) && failure == null) failure = ex;
            }

            lock (sync)
            {
                if (foundPassword != null)
                    state = AttackState.Found;
                else if (failure != null)
                {
                    state = AttackState.Failed;
                    errorMessage = failure.Message;
                }
                else if (token.IsCancellationRequested)
                    state = AttackState.Stopped;
                else
                    state = AttackState.Exhausted;
            }

            queue.Dispose();
            if (stopwatch != null) stopwatch.Stop();
            EventHandler handler = Completed;
            if (handler != null) handler(this, EventArgs.Empty);
        }

        private static void Produce(DictionaryInfo dictionary, BlockingCollection<string[]> queue, CancellationToken token)
        {
            try
            {
                using (StreamReader reader = new StreamReader(dictionary.Path, dictionary.Encoding, true, 1024 * 1024))
                {
                    List<string> batch = new List<string>(BatchSize);
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        token.ThrowIfCancellationRequested();
                        batch.Add(line);
                        if (batch.Count == BatchSize)
                        {
                            queue.Add(batch.ToArray(), token);
                            batch.Clear();
                        }
                    }
                    if (batch.Count > 0) queue.Add(batch.ToArray(), token);
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                queue.CompleteAdding();
            }
        }

        private void Consume(PdfSecurityInfo security, BlockingCollection<string[]> queue,
            Encoding passwordEncoding, bool trimWhitespace, bool skipEmpty,
            CancellationTokenSource source, CancellationToken token)
        {
            byte[] passwordBuffer = new byte[256];
            try
            {
                foreach (string[] batch in queue.GetConsumingEnumerable(token))
                {
                    pauseGate.Wait(token);
                    for (int i = 0; i < batch.Length; i++)
                    {
                        token.ThrowIfCancellationRequested();
                        pauseGate.Wait(token);

                        string candidate = trimWhitespace ? batch[i].Trim() : batch[i];
                        if (skipEmpty && candidate.Length == 0) continue;
                        int requiredBytes = passwordEncoding.GetByteCount(candidate);
                        if (requiredBytes > passwordBuffer.Length)
                            passwordBuffer = new byte[Math.Max(requiredBytes, passwordBuffer.Length * 2)];
                        int byteCount = passwordEncoding.GetBytes(candidate, 0, candidate.Length, passwordBuffer, 0);
                        PasswordMatch result = PdfSecurity.VerifyPassword(security, passwordBuffer, byteCount);
                        long attemptNumber = Interlocked.Increment(ref attempts);

                        if ((attemptNumber & 63) == 0)
                        {
                            lock (sync) currentCandidate = candidate;
                        }

                        if (result != PasswordMatch.None)
                        {
                            lock (sync)
                            {
                                if (foundPassword == null)
                                {
                                    foundPassword = candidate;
                                    currentCandidate = candidate;
                                    match = result;
                                }
                            }
                            source.Cancel();
                            return;
                        }
                    }
                }
            }
            catch
            {
                source.Cancel();
                pauseGate.Set();
                throw;
            }
        }

        private static Exception FindNonCancellationFailure(AggregateException exception)
        {
            AggregateException flattened = exception.Flatten();
            for (int i = 0; i < flattened.InnerExceptions.Count; i++)
            {
                Exception candidate = flattened.InnerExceptions[i];
                if (!(candidate is OperationCanceledException)) return candidate;
            }
            return null;
        }

        public void Dispose()
        {
            Task runningCoordinator;
            CancellationTokenSource source;
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                runningCoordinator = coordinator;
                source = cancellation;
            }

            pauseGate.Set();
            if (source != null) source.Cancel();

            bool calledFromCoordinator = runningCoordinator != null && Task.CurrentId.HasValue &&
                Task.CurrentId.Value == runningCoordinator.Id;
            if (calledFromCoordinator)
            {
                runningCoordinator.ContinueWith(
                    delegate { DisposeResources(source); },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                return;
            }

            if (runningCoordinator != null)
            {
                try { runningCoordinator.Wait(); }
                catch (AggregateException) { }
            }
            DisposeResources(source);
        }

        private void DisposeResources(CancellationTokenSource source)
        {
            if (Interlocked.Exchange(ref resourcesDisposed, 1) != 0) return;
            pauseGate.Dispose();
            if (source != null) source.Dispose();
        }
    }
}

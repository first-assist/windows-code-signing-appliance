using System.Formats.Tar;
using System.Security.Cryptography;

namespace ArtifactSigning.Protocol;

public enum ClosedTarError
{
    None,
    Malformed,
    UnsupportedFormat,
    InvalidEntryType,
    UnexpectedEntry,
    DuplicateEntry,
    EntrySizeInvalid,
    AggregateSizeExceeded,
    EntryNotFullyConsumed,
    MissingEntry,
    TrailingData,
}

public sealed record ClosedTarEntryPolicy
{
    public ClosedTarEntryPolicy(string name, long minimumBytes, long maximumBytes)
    {
        if (!ClosedTarArchivePolicy.IsCanonicalEntryName(name))
        {
            throw new ArgumentException("Entry name is not canonical.", nameof(name));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(minimumBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumBytes, minimumBytes);

        Name = name;
        MinimumBytes = minimumBytes;
        MaximumBytes = maximumBytes;
    }

    public string Name { get; }

    public long MinimumBytes { get; }

    public long MaximumBytes { get; }
}

public sealed class ClosedTarArchivePolicy
{
    public const int MaximumEntries = ArtifactSigningRequestJsonParser.MaximumArtifacts + 2;
    public const long MaximumArchiveEntryBytes = 100L * 1024 * 1024;

    private readonly Dictionary<string, ClosedTarEntryPolicy> _entries;

    public ClosedTarArchivePolicy(
        IEnumerable<ClosedTarEntryPolicy> entries,
        long maximumTotalEntryBytes)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumTotalEntryBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maximumTotalEntryBytes,
            MaximumArchiveEntryBytes);

        _entries = new Dictionary<string, ClosedTarEntryPolicy>(StringComparer.Ordinal);
        foreach (ClosedTarEntryPolicy entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry);
            if (_entries.Count >= MaximumEntries)
            {
                throw new ArgumentException("Policy contains too many entries.", nameof(entries));
            }

            if (entry.MaximumBytes > maximumTotalEntryBytes)
            {
                throw new ArgumentException(
                    "Entry maximum exceeds the aggregate maximum.",
                    nameof(entries));
            }

            if (!_entries.TryAdd(entry.Name, entry))
            {
                throw new ArgumentException("Policy contains a duplicate entry.", nameof(entries));
            }
        }

        if (_entries.Count is 0)
        {
            throw new ArgumentException("Policy must contain at least one entry.", nameof(entries));
        }

        MaximumTotalEntryBytes = maximumTotalEntryBytes;
    }

    public long MaximumTotalEntryBytes { get; }

    public IReadOnlyCollection<ClosedTarEntryPolicy> Entries => _entries.Values;

    internal bool TryGetEntry(string name, out ClosedTarEntryPolicy? policy)
    {
        return _entries.TryGetValue(name, out policy);
    }

    internal static bool IsCanonicalEntryName(string value)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > 255
            || value[0] is '/'
            || value[^1] is '/' or '.' or ' ')
        {
            return false;
        }

        string[] segments = value.Split('/');
        return segments.All(segment =>
            segment.Length is > 0 and <= 100
            && segment is not "." and not ".."
            && segment[^1] is not '.' and not ' '
            && segment.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'));
    }
}

public sealed record ClosedTarEntryHeader(string Name, long Length);

public sealed record ClosedTarEntryResult(string Name, long Size, string Sha256);

public sealed record ClosedTarReadResult(
    IReadOnlyList<ClosedTarEntryResult> Entries,
    ClosedTarError Error)
{
    public bool IsSuccess => Error is ClosedTarError.None;
}

public static class ClosedTarArchive
{
    private static readonly IReadOnlyList<ClosedTarEntryResult> NoEntries =
        Array.Empty<ClosedTarEntryResult>();

    public static ClosedTarReadResult Read(Stream archive, ClosedTarArchivePolicy policy)
    {
        return Read(
            archive,
            policy,
            static (_, content) => content.CopyTo(Stream.Null));
    }

    public static ClosedTarReadResult Read(
        Stream archive,
        ClosedTarArchivePolicy policy,
        Action<ClosedTarEntryHeader, Stream> consumeEntry)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(consumeEntry);

        if (!archive.CanRead)
        {
            throw new ArgumentException("Archive stream must be readable.", nameof(archive));
        }

        HashSet<string> observedNames = new(StringComparer.Ordinal);
        List<ClosedTarEntryResult> results = new(policy.Entries.Count);
        long aggregateBytes = 0;

        using TarReader reader = new(archive, leaveOpen: true);

        while (true)
        {
            TarEntry? entry;
            try
            {
                entry = reader.GetNextEntry(copyData: false);
            }
            catch (InvalidDataException)
            {
                return Failure(ClosedTarError.Malformed);
            }
            catch (EndOfStreamException)
            {
                return Failure(ClosedTarError.Malformed);
            }

            if (entry is null)
            {
                break;
            }

            if (entry.Format is not TarEntryFormat.Ustar)
            {
                return Failure(ClosedTarError.UnsupportedFormat);
            }

            if (entry.EntryType is not TarEntryType.RegularFile)
            {
                return Failure(ClosedTarError.InvalidEntryType);
            }

            if (!policy.TryGetEntry(entry.Name, out ClosedTarEntryPolicy? entryPolicy))
            {
                return Failure(ClosedTarError.UnexpectedEntry);
            }

            ClosedTarEntryPolicy acceptedEntryPolicy = entryPolicy!;

            if (!observedNames.Add(entry.Name))
            {
                return Failure(ClosedTarError.DuplicateEntry);
            }

            long length = entry.Length;
            if (length < acceptedEntryPolicy.MinimumBytes
                || length > acceptedEntryPolicy.MaximumBytes)
            {
                return Failure(ClosedTarError.EntrySizeInvalid);
            }

            if (length > policy.MaximumTotalEntryBytes - aggregateBytes)
            {
                return Failure(ClosedTarError.AggregateSizeExceeded);
            }

            Stream? dataStream = entry.DataStream;
            if (dataStream is null)
            {
                return Failure(ClosedTarError.Malformed);
            }

            using HashingBoundedReadStream content = new(dataStream, length);
            consumeEntry(new ClosedTarEntryHeader(entry.Name, length), content);

            if (!content.IsFullyConsumed)
            {
                return Failure(ClosedTarError.EntryNotFullyConsumed);
            }

            results.Add(new ClosedTarEntryResult(entry.Name, length, content.CompleteHashHex()));
            aggregateBytes += length;
        }

        if (observedNames.Count != policy.Entries.Count)
        {
            return Failure(ClosedTarError.MissingEntry);
        }

        if (!HasOnlyBoundedZeroPadding(archive))
        {
            return Failure(ClosedTarError.TrailingData);
        }

        return new ClosedTarReadResult(results.AsReadOnly(), ClosedTarError.None);
    }

    private static bool HasOnlyBoundedZeroPadding(Stream archive)
    {
        Span<byte> buffer = stackalloc byte[512];
        int totalPaddingBytes = 0;

        while (true)
        {
            int bytesRead = archive.Read(buffer);
            if (bytesRead is 0)
            {
                return true;
            }

            totalPaddingBytes += bytesRead;
            if (totalPaddingBytes > 1024 || buffer[..bytesRead].ContainsAnyExcept((byte)0))
            {
                return false;
            }
        }
    }

    private static ClosedTarReadResult Failure(ClosedTarError error)
    {
        return new ClosedTarReadResult(NoEntries, error);
    }

    private sealed class HashingBoundedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long _remaining;
        private bool _hashCompleted;

        public HashingBoundedReadStream(Stream inner, long length)
        {
            _inner = inner;
            _remaining = length;
        }

        public bool IsFullyConsumed => _remaining is 0;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public string CompleteHashHex()
        {
            ObjectDisposedException.ThrowIf(_hashCompleted, this);
            if (!IsFullyConsumed)
            {
                throw new InvalidOperationException("Entry content has not been fully consumed.");
            }

            _hashCompleted = true;
            return Convert.ToHexStringLower(_hash.GetHashAndReset());
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);

            if (buffer.Length - offset < count)
            {
                throw new ArgumentException("Offset and count exceed the buffer.", nameof(count));
            }

            if (_remaining is 0)
            {
                return 0;
            }

            int boundedCount = (int)Math.Min(count, _remaining);
            int bytesRead = _inner.Read(buffer, offset, boundedCount);
            if (bytesRead > 0)
            {
                _hash.AppendData(buffer, offset, bytesRead);
                _remaining -= bytesRead;
            }

            return bytesRead;
        }

        public override int Read(Span<byte> buffer)
        {
            if (_remaining is 0)
            {
                return 0;
            }

            int boundedCount = (int)Math.Min(buffer.Length, _remaining);
            int bytesRead = _inner.Read(buffer[..boundedCount]);
            if (bytesRead > 0)
            {
                _hash.AppendData(buffer[..bytesRead]);
                _remaining -= bytesRead;
            }

            return bytesRead;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

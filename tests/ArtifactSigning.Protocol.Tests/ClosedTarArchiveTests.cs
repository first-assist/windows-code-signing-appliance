using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ClosedTarArchiveTests
{
    private static readonly ClosedTarArchivePolicy Policy = new(
        [
            new ClosedTarEntryPolicy("request.json", 1, 64 * 1024),
            new ClosedTarEntryPolicy("request.p7s", 1, 256 * 1024),
        ],
        512 * 1024);

    [Fact]
    public void ReadAcceptsExactUstarInventoryAndHashesWhileStreaming()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));
        Dictionary<string, string> consumed = new(StringComparer.Ordinal);

        ClosedTarReadResult result = ClosedTarArchive.Read(
            archive,
            Policy,
            (header, content) =>
            {
                using StreamReader reader = new(
                    content,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true);
                consumed.Add(header.Name, reader.ReadToEnd());
            });

        Assert.True(result.IsSuccess);
        Assert.Equal(ClosedTarError.None, result.Error);
        Assert.Equal("request", consumed["request.json"]);
        Assert.Equal("signature", consumed["request.p7s"]);
        Assert.Collection(
            result.Entries,
            entry =>
            {
                Assert.Equal("request.json", entry.Name);
                Assert.Equal(7, entry.Size);
                Assert.Equal(
                    "1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047",
                    entry.Sha256);
            },
            entry =>
            {
                Assert.Equal("request.p7s", entry.Name);
                Assert.Equal(9, entry.Size);
                Assert.Equal(
                    "1a2fc26dc7ea5a2a4748b7cb2b1ef193d96ab2c99f93092f69e63075b28d1278",
                    entry.Sha256);
            });
    }

    [Fact]
    public void ReadRejectsMissingEntry()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.MissingEntry);
    }

    [Fact]
    public void ReadRejectsUnexpectedTraversalEntry()
    {
        using MemoryStream archive = CreateArchive(
            ("../request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.UnexpectedEntry);
    }

    [Fact]
    public void ReadRejectsAlternateDataStreamEntry()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json:stream", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.UnexpectedEntry);
    }

    [Fact]
    public void ReadRejectsDuplicateEntry()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.json", "again"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.DuplicateEntry);
    }

    [Fact]
    public void ReadRejectsSymbolicLink()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.SymbolicLink),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.InvalidEntryType);
    }

    [Fact]
    public void ReadRejectsPaxFormat()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Pax, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Pax, TarEntryType.RegularFile));

        AssertError(archive, Policy, ClosedTarError.UnsupportedFormat);
    }

    [Fact]
    public void ReadRejectsEntryOverPolicyLimit()
    {
        ClosedTarArchivePolicy smallPolicy = new(
            [new ClosedTarEntryPolicy("request.json", 1, 3)],
            3);
        using MemoryStream archive = CreateArchive(
            ("request.json", "four"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, smallPolicy, ClosedTarError.EntrySizeInvalid);
    }

    [Fact]
    public void ReadRejectsAggregateOverPolicyLimit()
    {
        ClosedTarArchivePolicy aggregatePolicy = new(
            [
                new ClosedTarEntryPolicy("request.json", 1, 8),
                new ClosedTarEntryPolicy("request.p7s", 1, 8),
            ],
            10);
        using MemoryStream archive = CreateArchive(
            ("request.json", "123456"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "123456"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        AssertError(archive, aggregatePolicy, ClosedTarError.AggregateSizeExceeded);
    }

    [Fact]
    public void ReadRejectsConsumerThatDoesNotConsumeEntry()
    {
        using MemoryStream archive = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));

        ClosedTarReadResult result = ClosedTarArchive.Read(archive, Policy, static (_, _) => { });

        Assert.False(result.IsSuccess);
        Assert.Equal(ClosedTarError.EntryNotFullyConsumed, result.Error);
    }

    [Fact]
    public void ReadRejectsTruncatedEntryData()
    {
        using MemoryStream complete = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));
        byte[] bytes = complete.ToArray();
        using MemoryStream truncated = new(bytes, 0, 514, writable: false, publiclyVisible: false);

        AssertError(truncated, Policy, ClosedTarError.EntryNotFullyConsumed);
    }

    [Fact]
    public void ReadRejectsCompressedArchive()
    {
        using MemoryStream uncompressed = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));
        using MemoryStream compressed = new();
        using (GZipStream gzip = new(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            uncompressed.CopyTo(gzip);
        }

        compressed.Position = 0;

        AssertError(compressed, Policy, ClosedTarError.Malformed);
    }

    [Fact]
    public void ReadRejectsTrailingNonZeroData()
    {
        using MemoryStream complete = CreateArchive(
            ("request.json", "request"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile),
            ("request.p7s", "signature"u8.ToArray(), TarEntryFormat.Ustar, TarEntryType.RegularFile));
        using MemoryStream archive = new();
        complete.CopyTo(archive);
        archive.Write("junk"u8);
        archive.Position = 0;

        AssertError(archive, Policy, ClosedTarError.TrailingData);
    }

    [Theory]
    [InlineData("../request.json")]
    [InlineData("/request.json")]
    [InlineData("request.json:stream")]
    [InlineData("bundle\\request.json")]
    [InlineData("bundle//request.json")]
    [InlineData("bundle/./request.json")]
    public void PolicyRejectsUnsafeEntryName(string name)
    {
        Assert.Throws<ArgumentException>(() => new ClosedTarEntryPolicy(name, 1, 2));
    }

    private static MemoryStream CreateArchive(
        params (string Name, byte[] Content, TarEntryFormat Format, TarEntryType Type)[] entries)
    {
        MemoryStream archive = new();
        foreach (IGrouping<TarEntryFormat, (string Name, byte[] Content, TarEntryFormat Format, TarEntryType Type)>
            formatGroup in entries.GroupBy(entry => entry.Format))
        {
            using TarWriter writer = new(archive, formatGroup.Key, leaveOpen: true);
            foreach ((string name, byte[] content, TarEntryFormat format, TarEntryType type) in formatGroup)
            {
                TarEntry entry = format switch
                {
                    TarEntryFormat.Ustar => new UstarTarEntry(type, name),
                    TarEntryFormat.Pax => new PaxTarEntry(type, name),
                    _ => throw new InvalidOperationException("Unsupported test format."),
                };

                if (type is TarEntryType.RegularFile)
                {
                    entry.DataStream = new MemoryStream(content, writable: false);
                }
                else if (type is TarEntryType.SymbolicLink)
                {
                    entry.LinkName = "request.p7s";
                }

                writer.WriteEntry(entry);
            }
        }

        archive.Position = 0;
        return archive;
    }

    private static void AssertError(
        Stream archive,
        ClosedTarArchivePolicy policy,
        ClosedTarError expected)
    {
        ClosedTarReadResult result = ClosedTarArchive.Read(archive, policy);

        Assert.False(result.IsSuccess);
        Assert.Empty(result.Entries);
        Assert.Equal(expected, result.Error);
    }
}

using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ArtifactSigningReceiptTests
{
    private static readonly DateTimeOffset CompletedAt =
        new(2026, 7, 29, 12, 5, 0, TimeSpan.Zero);

    [Fact]
    public void SerializerProducesDeterministicCanonicalBytes()
    {
        ArtifactSigningReceiptV1 receipt = CreateReceipt();

        byte[] first =
            ArtifactSigningReceiptJsonSerializer.Serialize(receipt);
        byte[] second =
            ArtifactSigningReceiptJsonSerializer.Serialize(receipt);
        string json = Encoding.UTF8.GetString(first);

        Assert.Equal(first, second);
        Assert.EndsWith("\n", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", json, StringComparison.Ordinal);
        Assert.Contains(
            "\"Format\": \"ArtifactSigningReceiptV1\"",
            json,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"SigningAuditSequence\": 42",
            json,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ParserAcceptsOnlyCanonicalReceiptBytes()
    {
        byte[] canonical =
            ArtifactSigningReceiptJsonSerializer.Serialize(
                CreateReceipt());

        ReceiptJsonParseResult parsed =
            ArtifactSigningReceiptJsonParser.Parse(canonical);
        byte[] reordered = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(canonical).Replace(
                "\"Format\": \"ArtifactSigningReceiptV1\",\n  \"RequestId\"",
                "\"RequestId\"",
                StringComparison.Ordinal));

        Assert.True(parsed.IsSuccess);
        Assert.NotNull(parsed.Receipt);
        Assert.Equal(
            ReceiptJsonError.Invalid,
            ArtifactSigningReceiptJsonParser
                .Parse(reordered).Error);
    }

    [Fact]
    public void ReceiptRejectsAuthenticodeMappingOutsideResultInventory()
    {
        ReceiptArtifactV1 unsigned = new(
            "Agent",
            "agent.exe",
            10,
            Digest('a'));
        ReceiptArtifactV1 result = new(
            "Agent",
            "agent.exe",
            11,
            Digest('b'));
        ReceiptAuthenticodeArtifactV1 wrong = new(
            "Other",
            "other.exe",
            Digest('a'),
            Digest('b'),
            Thumbprint('A'),
            Thumbprint('B'),
            CompletedAt);

        Assert.Throws<ArgumentException>(
            () => CreateReceipt(
                [unsigned],
                [result],
                [wrong]));
    }

    [Fact]
    public void ReceiptDigestHasFixedDomainSeparatedVector()
    {
        Assert.Equal(
            "87b22d6524208cf2122b8b0d187c79f19f97264bdecaf5121ed0371e12706b47",
            SigningReceiptDigest.ComputeHex("{}"u8));
    }

    private static ArtifactSigningReceiptV1 CreateReceipt(
        IReadOnlyList<ReceiptArtifactV1>? unsigned = null,
        IReadOnlyList<ReceiptArtifactV1>? results = null,
        IReadOnlyList<ReceiptAuthenticodeArtifactV1>? authenticode = null)
    {
        ReceiptArtifactV1 unsignedArtifact = new(
            "Agent",
            "agent.exe",
            10,
            Digest('a'));
        ReceiptArtifactV1 resultArtifact = new(
            "Agent",
            "agent.exe",
            11,
            Digest('b'));
        ReceiptAuthenticodeArtifactV1 evidence = new(
            "Agent",
            "agent.exe",
            Digest('a'),
            Digest('b'),
            Thumbprint('A'),
            Thumbprint('B'),
            CompletedAt.AddMinutes(-1));
        return new ArtifactSigningReceiptV1(
            Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
            Digest('c'),
            "example-project",
            "ExampleBundleV1",
            1,
            "example/project",
            "0123456789abcdef0123456789abcdef01234567",
            "1.2.3",
            "ExampleSignerV1",
            "ExampleTimestampV1",
            Digest('d'),
            Digest('e'),
            Digest('f'),
            unsigned ?? [unsignedArtifact],
            results ?? [resultArtifact],
            authenticode ?? [evidence],
            "0.4.0",
            Digest('1'),
            42,
            CompletedAt);
    }

    private static string Digest(char character)
    {
        return new string(character, 64);
    }

    private static string Thumbprint(char character)
    {
        return new string(character, 40);
    }
}

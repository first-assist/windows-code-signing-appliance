using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class WorkerAuditAnchorTests
{
    private static readonly DateTimeOffset PublishedAt =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CanonicalRoundTripIsExact()
    {
        WorkerAuditAnchorV1 anchor = CreateAnchor();

        byte[] json = WorkerAuditAnchorJson.Serialize(anchor);
        WorkerAuditAnchorJsonParseResult parsed =
            WorkerAuditAnchorJson.Parse(json);

        Assert.True(parsed.IsSuccess);
        Assert.Equal(anchor, parsed.Anchor);
        Assert.Equal(
            json,
            WorkerAuditAnchorJson.Serialize(parsed.Anchor!));
    }

    [Theory]
    [InlineData(
        "{\"Format\":\"ArtifactSigningWorkerAuditAnchorV1\",\"WorkerSequence\":1,\"WorkerEventDigest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"WorkerVersion\":\"0.8.3\",\"WorkerReady\":true,\"TimestampDependencyReady\":true,\"PublishedAt\":\"2026-07-29T18:00:00Z\",\"ExpiresAt\":\"2026-07-29T18:02:00Z\",\"ReceiptSignerSpkiSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"Extra\":true}")]
    [InlineData(
        "{\"Format\":\"ArtifactSigningWorkerAuditAnchorV1\",\"WorkerSequence\":1,\"WorkerEventDigest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"WorkerVersion\":\"0.8.3\",\"WorkerReady\":true,\"WorkerReady\":true,\"TimestampDependencyReady\":true,\"PublishedAt\":\"2026-07-29T18:00:00Z\",\"ExpiresAt\":\"2026-07-29T18:02:00Z\",\"ReceiptSignerSpkiSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}")]
    [InlineData(
        "{\"WorkerSequence\":1,\"Format\":\"ArtifactSigningWorkerAuditAnchorV1\",\"WorkerEventDigest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"WorkerVersion\":\"0.8.3\",\"WorkerReady\":true,\"TimestampDependencyReady\":true,\"PublishedAt\":\"2026-07-29T18:00:00Z\",\"ExpiresAt\":\"2026-07-29T18:02:00Z\",\"ReceiptSignerSpkiSha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}")]
    public void RejectsUnknownDuplicateAndNoncanonicalJson(
        string json)
    {
        WorkerAuditAnchorJsonParseResult parsed =
            WorkerAuditAnchorJson.Parse(
                System.Text.Encoding.UTF8.GetBytes(json));

        Assert.False(parsed.IsSuccess);
        Assert.Equal(
            WorkerAuditAnchorJsonError.Invalid,
            parsed.Error);
    }

    [Fact]
    public void RejectsGenesisDigestForNonzeroHeadRules()
    {
        Assert.Throws<ArgumentException>(() =>
            new WorkerAuditAnchorV1(
                0,
                new string('a', 64),
                "0.8.3",
                workerReady: true,
                timestampDependencyReady: true,
                PublishedAt,
                PublishedAt.AddMinutes(2),
                new string('b', 64)));
    }

    private static WorkerAuditAnchorV1 CreateAnchor()
    {
        return new WorkerAuditAnchorV1(
            1,
            new string('a', 64),
            "0.8.3",
            workerReady: true,
            timestampDependencyReady: true,
            PublishedAt,
            PublishedAt.AddMinutes(2),
            new string('b', 64));
    }
}

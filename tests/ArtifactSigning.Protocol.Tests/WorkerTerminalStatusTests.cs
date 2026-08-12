using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class WorkerTerminalStatusTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RoundTripsClosedTerminalStatus()
    {
        WorkerTerminalStatusV1 expected = new(
            Guid.NewGuid(),
            new string('a', 64),
            RequestState.Signed,
            "SigningCompleted",
            new string('b', 64),
            Now);

        byte[] json =
            WorkerTerminalStatusJson.Serialize(expected);
        WorkerTerminalStatusJsonParseResult parsed =
            WorkerTerminalStatusJson.Parse(json);

        Assert.True(parsed.IsSuccess);
        Assert.Equal(expected, parsed.Status);
    }

    [Theory]
    [InlineData(
        "{\"Format\":\"ArtifactSigningWorkerTerminalStatusV1\",\"Format\":\"ArtifactSigningWorkerTerminalStatusV1\"}")]
    [InlineData(
        "{\"format\":\"ArtifactSigningWorkerTerminalStatusV1\"}")]
    [InlineData(
        "{\"Format\":\"ArtifactSigningWorkerTerminalStatusV1\",\"Unknown\":true}")]
    public void RejectsAmbiguousStatusJson(string json)
    {
        WorkerTerminalStatusJsonParseResult result =
            WorkerTerminalStatusJson.Parse(
                Encoding.UTF8.GetBytes(json));

        Assert.False(result.IsSuccess);
        Assert.Equal(
            WorkerTerminalStatusJsonError.Invalid,
            result.Error);
    }

    [Fact]
    public void NonSignedStateCannotClaimEvidence()
    {
        Assert.Throws<ArgumentException>(
            () => new WorkerTerminalStatusV1(
                Guid.NewGuid(),
                new string('a', 64),
                RequestState.Failed,
                "ApprovalRevalidationFailed",
                new string('b', 64),
                Now));
    }
}

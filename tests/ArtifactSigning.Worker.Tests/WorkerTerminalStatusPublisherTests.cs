using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerTerminalStatusPublisherTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 18, 5, 0, TimeSpan.Zero);

    [Fact]
    public void AtomicallyPublishesExactIdempotentStatus()
    {
        using WorkerStateTestEnvironment environment = new();
        Directory.CreateDirectory(
            environment.Layout.GatewayStatusRoot);
        WorkerTerminalStatusPublisher publisher = new(
            environment.Layout);
        WorkerJobRecord job = new(
            Guid.NewGuid(),
            new string('a', 64),
            RequestState.Signed,
            RowVersion: 3,
            WorkerResultCode.SigningCompleted,
            new string('b', 64),
            Now.AddMinutes(-1),
            Now);

        Assert.True(publisher.Publish(job));
        Assert.True(publisher.Publish(job));
        string path = Path.Combine(
            environment.Layout.GatewayStatusRoot,
            $"{job.RequestId:N}.json");
        WorkerTerminalStatusJsonParseResult parsed =
            WorkerTerminalStatusJson.Parse(
                File.ReadAllBytes(path));
        Assert.True(parsed.IsSuccess);
        Assert.Equal(job.RequestDigest, parsed.Status?.RequestDigest);
        Assert.Equal(job.EvidenceDigest, parsed.Status?.EvidenceDigest);
    }

    [Fact]
    public void ExistingDifferentStatusFailsClosed()
    {
        using WorkerStateTestEnvironment environment = new();
        Directory.CreateDirectory(
            environment.Layout.GatewayStatusRoot);
        WorkerTerminalStatusPublisher publisher = new(
            environment.Layout);
        WorkerJobRecord job = new(
            Guid.NewGuid(),
            new string('c', 64),
            RequestState.Failed,
            RowVersion: 2,
            WorkerResultCode.ApprovalRevalidationFailed,
            EvidenceDigest: null,
            Now.AddMinutes(-1),
            Now);
        string path = Path.Combine(
            environment.Layout.GatewayStatusRoot,
            $"{job.RequestId:N}.json");
        File.WriteAllBytes(path, [0x01]);

        Assert.False(publisher.Publish(job));
    }
}

using ArtifactSigning.Gateway;
using ArtifactSigning.Worker;
using Xunit;

namespace ArtifactSigning.Acceptance.Tests;

public sealed class ComponentVersionContractTests
{
    [Fact]
    public void GatewayAndWorkerReadinessVersionsRemainAligned()
    {
        Assert.Equal(
            WorkerAuditAnchorPublisher.WorkerVersion,
            GatewayReadinessProbe.RequiredWorkerVersion);
    }
}

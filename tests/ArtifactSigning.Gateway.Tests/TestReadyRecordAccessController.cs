namespace ArtifactSigning.Gateway.Tests;

internal sealed class TestReadyRecordAccessController(
    bool success = true) : IGatewayReadyRecordAccessController
{
    internal int CallCount { get; private set; }

    internal Guid? LastRequestId { get; private set; }

    public bool PrepareForWorker(GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(request);
        CallCount++;
        LastRequestId = request.RequestId;
        return success;
    }
}

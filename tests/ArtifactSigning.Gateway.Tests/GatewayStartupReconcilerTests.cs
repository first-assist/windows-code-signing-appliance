using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayStartupReconcilerTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 17, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task ClearsIncompleteIntakeAndRedispatchesApprovedReadyRecord()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        GatewayRequestRecord approved =
            CreateApprovedRequest(store);
        Directory.CreateDirectory(
            store.Layout.GetReadyRequestDirectory(
                approved.RequestId));
        string receiving =
            store.Layout.CreateReceivingDirectoryPath();
        Directory.CreateDirectory(receiving);
        File.WriteAllBytes(
            Path.Combine(receiving, "partial.tar"),
            [0x01]);
        RecordingNotifier notifier = new(success: true);
        TestReadyRecordAccessController readyRecordAccess = new();
        GatewayStartupReconciler reconciler = new(
            store,
            notifier,
            readyRecordAccess,
            new FixedTimeProvider(Now.AddSeconds(2)));

        GatewayStartupReconciliationOutcome result =
            await reconciler.ReconcileAsync(
                TestContext.Current.CancellationToken);

        Assert.Equal(
            GatewayStartupReconciliationOutcome.Ready,
            result);
        Assert.Equal(1, notifier.CallCount);
        Assert.Equal(1, readyRecordAccess.CallCount);
        Assert.Equal(
            approved.RequestId,
            readyRecordAccess.LastRequestId);
        Assert.Equal(
            RequestState.Signing,
            store.GetRequest(approved.RequestId)?.State);
        Assert.Empty(Directory.EnumerateFileSystemEntries(
            store.Layout.ReceivingRoot));
    }

    [Fact]
    public async Task WorkerUnavailabilityPreventsGatewayReadiness()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        GatewayRequestRecord approved =
            CreateApprovedRequest(store);
        Directory.CreateDirectory(
            store.Layout.GetReadyRequestDirectory(
                approved.RequestId));
        GatewayStartupReconciler reconciler = new(
            store,
            new RecordingNotifier(success: false),
            new TestReadyRecordAccessController(),
            new FixedTimeProvider(Now.AddSeconds(2)));

        GatewayStartupReconciliationOutcome result =
            await reconciler.ReconcileAsync(
                TestContext.Current.CancellationToken);

        Assert.Equal(
            GatewayStartupReconciliationOutcome.Unresolved,
            result);
        Assert.Equal(
            RequestState.Approved,
            store.GetRequest(approved.RequestId)?.State);
    }

    [Fact]
    public async Task ReadyRecordAccessFailurePreventsRedispatch()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        GatewayRequestRecord approved =
            CreateApprovedRequest(store);
        Directory.CreateDirectory(
            store.Layout.GetReadyRequestDirectory(
                approved.RequestId));
        RecordingNotifier notifier = new(success: true);
        GatewayStartupReconciler reconciler = new(
            store,
            notifier,
            new TestReadyRecordAccessController(success: false),
            new FixedTimeProvider(Now.AddSeconds(2)));

        GatewayStartupReconciliationOutcome result =
            await reconciler.ReconcileAsync(
                TestContext.Current.CancellationToken);

        Assert.Equal(
            GatewayStartupReconciliationOutcome.Unresolved,
            result);
        Assert.Equal(0, notifier.CallCount);
        Assert.Equal(
            RequestState.Approved,
            store.GetRequest(approved.RequestId)?.State);
    }

    private static GatewayRequestRecord CreateApprovedRequest(
        GatewayStateStore store)
    {
        ArtifactSigningRequestV1 request =
            GatewayStateStoreTests.CreateRequestForOtherTests();
        string requestDigest = new('8', 64);
        GatewayRequestRecord pending = store.AdmitPending(
                request,
                requestDigest,
                new string('a', 64),
                Now)
            .Request!;
        ArtifactSigningApprovalV1 approval = new(
            request.RequestId,
            requestDigest,
            ApprovalDecision.Approve,
            "Approved for startup test",
            Now,
            Now.AddMinutes(1),
            CanonicalNonce());
        return store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                pending.RowVersion,
                approval,
                new string('b', 64),
                new string('9', 64),
                requireDistinctSubmitterAndApprover: true,
                Now.AddSeconds(1))
            .Request!;
    }

    private static string CanonicalNonce()
    {
        return Convert.ToBase64String(
                Enumerable.Repeat((byte)0x7a, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed class RecordingNotifier(bool success) :
        IGatewayWorkerNotifier
    {
        internal int CallCount { get; private set; }

        public ValueTask<GatewayWorkerNotificationResult>
            NotifyAsync(
                Guid requestId,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(
                new GatewayWorkerNotificationResult(
                    success
                        ? GatewayWorkerNotificationError.None
                        : GatewayWorkerNotificationError
                            .WorkerUnavailable));
        }
    }

    private sealed class FixedTimeProvider(
        DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }
}

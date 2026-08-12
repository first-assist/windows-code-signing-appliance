using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerNotificationDispatcherTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 13, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task RequestIdOnlyNotificationResolvesDigestFromDurableState()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string digest = new('a', 64);
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, digest, Now);
        RecordingOperation operation = new();
        WorkerJobProcessor processor = CreateProcessor(store, operation);
        WorkerNotificationDispatcher dispatcher = new(store, processor);

        WorkerNotificationDispatchResult result =
            await dispatcher.DispatchAsync(
                requestId,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerNotificationDispatchOutcome.Processed,
            result.Outcome);
        Assert.Equal(
            WorkerProcessingOutcome.Completed,
            result.ProcessingResult?.Outcome);
        Assert.Equal(digest, operation.ObservedDigest);
        Assert.Equal(
            RequestState.Signed,
            store.GetJob(requestId)?.State);
    }

    [Fact]
    public async Task UnknownRequestIdDoesNotInvokeSigningOperation()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        RecordingOperation operation = new();
        WorkerNotificationDispatcher dispatcher = new(
            store,
            CreateProcessor(store, operation));

        WorkerNotificationDispatchResult result =
            await dispatcher.DispatchAsync(
                Guid.NewGuid(),
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerNotificationDispatchOutcome.NotApproved,
            result.Outcome);
        Assert.Equal(0, operation.CallCount);
    }

    [Fact]
    public void UnresolvedStartupReconciliationPreventsReadiness()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string digest = new('b', 64);
        _ = store.AdmitApproved(requestId, digest, Now);
        _ = store.TryBeginSigning(
            requestId,
            digest,
            1,
            Now.AddSeconds(1));
        WorkerJobProcessor processor = CreateProcessor(
            store,
            new RecordingOperation());
        WorkerNotificationDispatcher dispatcher = new(store, processor);
        WorkerServiceCoordinator coordinator = new(
            processor,
            dispatcher,
            new RejectingNotificationSource());

        Assert.Equal(
            WorkerServiceStartupOutcome.ReconciliationUnresolved,
            coordinator.ReconcileStartup());
    }

    private static WorkerJobProcessor CreateProcessor(
        WorkerStateStore store,
        RecordingOperation operation)
    {
        return new WorkerJobProcessor(
            store,
            new SuccessfulRevalidator(),
            operation,
            new TestOutputPublisher(store.Layout),
            new FixedTimeProvider(Now.AddMinutes(1)));
    }

    private sealed class TestOutputPublisher(
        WorkerDirectoryLayout layout) : IWorkerOutputPublisher
    {
        public bool TryPublish(WorkerJobRecord signingJob)
        {
            return layout.TryPublish(signingJob.RequestId);
        }
    }

    private sealed class SuccessfulRevalidator : IWorkerJobRevalidator
    {
        public ValueTask<WorkerRevalidationResult> RevalidateAsync(
            WorkerJobRecord job,
            string trustedWorkDirectory,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                WorkerRevalidationResult.Success);
        }
    }

    private sealed class RecordingOperation : IWorkerSigningOperation
    {
        internal int CallCount { get; private set; }

        internal string? ObservedDigest { get; private set; }

        public ValueTask<WorkerSigningOperationResult> ExecuteAsync(
            WorkerJobRecord signingJob,
            string trustedWorkDirectory,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            ObservedDigest = signingJob.RequestDigest;
            return ValueTask.FromResult(
                WorkerSigningOperationResult.Success(
                    new string('c', 64)));
        }
    }

    private sealed class RejectingNotificationSource :
        IWorkerNotificationSource
    {
        public ValueTask<WorkerNotificationReadResult> ReadAsync(
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(
                new WorkerNotificationReadResult(
                    WorkerNotificationReadOutcome.Rejected,
                    null));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) :
        TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}

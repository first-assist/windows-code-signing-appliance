using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerJobProcessorTests
{
    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 29, 11, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task PersistsSigningBeforeOperationAndPublishesBeforeCompletion()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('a');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingRevalidator revalidator = new(
            (_, _, _) => ValueTask.FromResult(
                WorkerRevalidationResult.Success));
        RecordingSigningOperation operation = new(
            async (job, workDirectory, cancellationToken) =>
            {
                Assert.Equal(RequestState.Signing, job.State);
                Assert.Equal(
                    RequestState.Signing,
                    environment.CreateStore().GetJob(requestId)?.State);
                await File.WriteAllTextAsync(
                        Path.Combine(workDirectory, "result.marker"),
                        "bounded-test-output",
                        cancellationToken)
                    .ConfigureAwait(true);
                return WorkerSigningOperationResult.Success(Digest('b'));
            });
        WorkerJobProcessor processor = CreateProcessor(
            store,
            revalidator,
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Completed, result.Outcome);
        Assert.Equal(RequestState.Signed, result.Job?.State);
        Assert.False(Directory.Exists(
            environment.Layout.GetWorkDirectory(requestId)));
        Assert.True(Directory.Exists(
            environment.Layout.GetOutputDirectory(requestId)));
        Assert.False(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
        Assert.Equal(1, revalidator.CallCount);
        Assert.Equal(1, operation.CallCount);
        store.VerifyIntegrity();
    }

    [Fact]
    public async Task RevalidationFailureNeverCrossesKeyBoundary()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('c');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingRevalidator revalidator = new(
            (_, _, _) => ValueTask.FromResult(
                new WorkerRevalidationResult(
                    WorkerRevalidationError.ApprovalInvalid)));
        RecordingSigningOperation operation = new(
            (_, _, _) => throw new InvalidOperationException());
        WorkerJobProcessor processor = CreateProcessor(
            store,
            revalidator,
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerProcessingOutcome.FailedBeforeSigning,
            result.Outcome);
        Assert.Equal(RequestState.Failed, result.Job?.State);
        Assert.Equal(0, operation.CallCount);
        Assert.True(environment.Layout.HasDirectWorkDirectory(requestId));
    }

    [Fact]
    public async Task AuditAnchorFailureAfterClaimNeverCrossesKeyBoundary()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('7');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(
            requestId,
            requestDigest,
            InitialTime);
        RecordingSigningOperation operation =
            RecordingSigningOperation.Success();
        WorkerJobProcessor processor = new(
            store,
            RecordingRevalidator.Success(),
            operation,
            new RecordingOutputPublisher(
                job => store.Layout.TryPublish(job.RequestId)),
            new FixedTimeProvider(
                InitialTime.AddMinutes(1)),
            auditAnchorPublisher:
                new FailingAuditAnchorPublisher());

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerProcessingOutcome.ReconciliationRequired,
            result.Outcome);
        Assert.Equal(
            RequestState.Signing,
            store.GetJob(requestId)?.State);
        Assert.Equal(0, operation.CallCount);
    }

    [Fact]
    public async Task SigningFailureMovesCompleteDirectoryToQuarantine()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('d');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingSigningOperation operation = new(
            async (_, workDirectory, cancellationToken) =>
            {
                await File.WriteAllTextAsync(
                        Path.Combine(workDirectory, "partial.marker"),
                        "partial",
                        cancellationToken)
                    .ConfigureAwait(true);
                return WorkerSigningOperationResult.Failed(
                    WorkerSigningFailure.SignToolRejected);
            });
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(RequestState.Quarantined, result.Job?.State);
        Assert.Equal(
            WorkerResultCode.SigningToolInvocationFailed,
            result.Job?.ResultCode);
        Assert.False(Directory.Exists(
            environment.Layout.GetWorkDirectory(requestId)));
        Assert.True(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
        Assert.True(File.Exists(Path.Combine(
            environment.Layout.GetQuarantineDirectory(requestId),
            "partial.marker")));
    }

    [Fact]
    public async Task OutputAccessFailureQuarantinesMovedResult()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('8');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingOutputPublisher publisher = new(job =>
        {
            Assert.True(store.Layout.TryPublish(job.RequestId));
            return false;
        });
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            RecordingSigningOperation.Success(),
            publisher);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(
            WorkerResultCode.OutputPublicationFailed,
            result.Job?.ResultCode);
        Assert.Equal(1, publisher.CallCount);
        Assert.False(Directory.Exists(
            environment.Layout.GetOutputDirectory(requestId)));
        Assert.True(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
        store.VerifyIntegrity();
    }

    [Theory]
    [InlineData(
        WorkerSigningFailure.ReadyRecordInvalid,
        WorkerResultCode.SigningReadyRecordInvalid)]
    [InlineData(
        WorkerSigningFailure.AuthorizationInvalid,
        WorkerResultCode.SigningAuthorizationInvalid)]
    [InlineData(
        WorkerSigningFailure.ArtifactPrecheckFailed,
        WorkerResultCode.SigningArtifactPrecheckFailed)]
    [InlineData(
        WorkerSigningFailure.SignToolRejected,
        WorkerResultCode.SigningToolInvocationFailed)]
    [InlineData(
        WorkerSigningFailure.SignatureVerificationFailed,
        WorkerResultCode.SigningSignatureVerificationFailed)]
    [InlineData(
        WorkerSigningFailure.ProfileFinalizationFailed,
        WorkerResultCode.SigningProfileFinalizationFailed)]
    [InlineData(
        WorkerSigningFailure.FinalizedValidationFailed,
        WorkerResultCode.SigningFinalizedValidationFailed)]
    [InlineData(
        WorkerSigningFailure.ReceiptSigningFailed,
        WorkerResultCode.SigningReceiptSigningFailed)]
    [InlineData(
        WorkerSigningFailure.OutputPreparationFailed,
        WorkerResultCode.SigningOutputPreparationFailed)]
    public async Task SigningFailurePersistsOnlyItsFixedCategory(
        WorkerSigningFailure failure,
        WorkerResultCode expected)
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('9');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingSigningOperation operation = new(
            (_, _, _) => ValueTask.FromResult(
                WorkerSigningOperationResult.Failed(failure)));
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(expected, result.Job?.ResultCode);
        Assert.Equal(expected, store.GetJob(requestId)?.ResultCode);
        store.VerifyIntegrity();
    }

    [Fact]
    public async Task CancellationAfterClaimIsQuarantined()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('4');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        using CancellationTokenSource cancellation = new();
        RecordingSigningOperation operation = new(
            async (_, _, _) =>
            {
                await cancellation.CancelAsync().ConfigureAwait(true);
                return await ValueTask.FromCanceled<WorkerSigningOperationResult>(
                        cancellation.Token)
                    .ConfigureAwait(true);
            });
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                cancellation.Token);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(WorkerResultCode.SigningCancelled, result.Job?.ResultCode);
        Assert.True(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
    }

    [Fact]
    public async Task CancellationBeforeClaimLeavesApprovedJobExecutableOnlyOnce()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('5');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        using CancellationTokenSource cancellation = new();
        await cancellation.CancelAsync().ConfigureAwait(true);
        RecordingRevalidator revalidator = new(
            (_, _, _) =>
                ValueTask.FromCanceled<WorkerRevalidationResult>(
                    cancellation.Token));
        RecordingSigningOperation operation =
            RecordingSigningOperation.Success();
        WorkerJobProcessor processor = CreateProcessor(
            store,
            revalidator,
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                cancellation.Token);

        Assert.Equal(
            WorkerProcessingOutcome.CancelledBeforeSigning,
            result.Outcome);
        Assert.Equal(RequestState.Approved, store.GetJob(requestId)?.State);
        Assert.Equal(0, operation.CallCount);
    }

    [Fact]
    public async Task InvalidOperationResultAfterClaimIsQuarantined()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('6');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        RecordingSigningOperation operation = new(
            (_, _, _) =>
                ValueTask.FromResult<WorkerSigningOperationResult>(null!));
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            operation);

        WorkerProcessingResult result =
            await processor.ProcessApprovedAsync(
                requestId,
                requestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(RequestState.Quarantined, result.Job?.State);
    }

    [Fact]
    public void StartupReconciliationQuarantinesWorkWithoutRetry()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('e');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        _ = store.TryBeginSigning(
            requestId,
            requestDigest,
            1,
            InitialTime.AddSeconds(1));
        RecordingSigningOperation operation = new(
            (_, _, _) => throw new InvalidOperationException());
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            operation);

        WorkerReconciliationResult result =
            Assert.Single(processor.ReconcileStartup());

        Assert.Equal(
            WorkerReconciliationOutcome.Quarantined,
            result.Outcome);
        Assert.Equal(RequestState.Quarantined, result.Job?.State);
        Assert.Equal(WorkerResultCode.RestartAmbiguity, result.Job?.ResultCode);
        Assert.Equal(0, operation.CallCount);
        Assert.True(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
    }

    [Fact]
    public void StartupReconciliationQuarantinesPublishedButUncommittedOutput()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('f');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        _ = store.TryBeginSigning(
            requestId,
            requestDigest,
            1,
            InitialTime.AddSeconds(1));
        Assert.True(environment.Layout.TryPublish(requestId));
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            RecordingSigningOperation.Success());

        WorkerReconciliationResult result =
            Assert.Single(processor.ReconcileStartup());

        Assert.Equal(
            WorkerReconciliationOutcome.Quarantined,
            result.Outcome);
        Assert.False(Directory.Exists(
            environment.Layout.GetOutputDirectory(requestId)));
        Assert.True(Directory.Exists(
            environment.Layout.GetQuarantineDirectory(requestId)));
    }

    [Fact]
    public async Task StartupSignedOutputAccessFailureRemainsUnresolved()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('6');
        environment.CreateWorkDirectory(requestId);
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        WorkerProcessingResult completed =
            await CreateProcessor(
                    store,
                    RecordingRevalidator.Success(),
                    RecordingSigningOperation.Success())
                .ProcessApprovedAsync(
                    requestId,
                    requestDigest,
                    TestContext.Current.CancellationToken);
        RecordingOutputPublisher publisher = new(_ => false);
        WorkerJobProcessor restarting = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            RecordingSigningOperation.Success(),
            publisher);

        WorkerReconciliationResult result =
            Assert.Single(restarting.ReconcileStartup());

        Assert.Equal(WorkerProcessingOutcome.Completed, completed.Outcome);
        Assert.Equal(
            WorkerReconciliationOutcome.Unresolved,
            result.Outcome);
        Assert.Equal(RequestState.Signed, result.Job?.State);
        Assert.Equal(1, publisher.CallCount);
        store.VerifyIntegrity();
    }

    [Fact]
    public void MissingAmbiguousDirectoryRemainsSigningAndBlocksNewClaims()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid firstId = Guid.NewGuid();
        Guid secondId = Guid.NewGuid();
        _ = store.AdmitApproved(firstId, Digest('1'), InitialTime);
        _ = store.TryBeginSigning(
            firstId,
            Digest('1'),
            1,
            InitialTime.AddSeconds(1));
        _ = store.AdmitApproved(
            secondId,
            Digest('2'),
            InitialTime.AddSeconds(2));
        WorkerJobProcessor processor = CreateProcessor(
            store,
            RecordingRevalidator.Success(),
            RecordingSigningOperation.Success());

        WorkerReconciliationResult reconciliation =
            Assert.Single(processor.ReconcileStartup());
        WorkerMutationResult secondClaim = store.TryBeginSigning(
            secondId,
            Digest('2'),
            1,
            InitialTime.AddSeconds(3));

        Assert.Equal(
            WorkerReconciliationOutcome.Unresolved,
            reconciliation.Outcome);
        Assert.Equal(RequestState.Signing, store.GetJob(firstId)?.State);
        Assert.Equal(WorkerMutationOutcome.SigningBusy, secondClaim.Outcome);
    }

    private static WorkerJobProcessor CreateProcessor(
        WorkerStateStore store,
        IWorkerJobRevalidator revalidator,
        IWorkerSigningOperation operation,
        IWorkerOutputPublisher? outputPublisher = null)
    {
        return new WorkerJobProcessor(
            store,
            revalidator,
            operation,
            outputPublisher ?? new RecordingOutputPublisher(
                job => store.Layout.TryPublish(job.RequestId)),
            new FixedTimeProvider(InitialTime.AddMinutes(1)));
    }

    private static string Digest(char character)
    {
        return new string(character, 64);
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }

    private sealed class RecordingRevalidator(
        Func<
            WorkerJobRecord,
            string,
            CancellationToken,
            ValueTask<WorkerRevalidationResult>> callback)
        : IWorkerJobRevalidator
    {
        internal int CallCount { get; private set; }

        public ValueTask<WorkerRevalidationResult> RevalidateAsync(
            WorkerJobRecord job,
            string trustedWorkDirectory,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return callback(job, trustedWorkDirectory, cancellationToken);
        }

        internal static RecordingRevalidator Success()
        {
            return new RecordingRevalidator(
                (_, _, _) => ValueTask.FromResult(
                    WorkerRevalidationResult.Success));
        }
    }

    private sealed class RecordingSigningOperation(
        Func<
            WorkerJobRecord,
            string,
            CancellationToken,
            ValueTask<WorkerSigningOperationResult>> callback)
        : IWorkerSigningOperation
    {
        internal int CallCount { get; private set; }

        public ValueTask<WorkerSigningOperationResult> ExecuteAsync(
            WorkerJobRecord signingJob,
            string trustedWorkDirectory,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return callback(
                signingJob,
                trustedWorkDirectory,
                cancellationToken);
        }

        internal static RecordingSigningOperation Success()
        {
            return new RecordingSigningOperation(
                (_, _, _) => ValueTask.FromResult(
                    WorkerSigningOperationResult.Success(Digest('3'))));
        }
    }

    private sealed class RecordingOutputPublisher(
        Func<WorkerJobRecord, bool> callback) : IWorkerOutputPublisher
    {
        internal int CallCount { get; private set; }

        public bool TryPublish(WorkerJobRecord signingJob)
        {
            CallCount++;
            return callback(signingJob);
        }
    }

    private sealed class FailingAuditAnchorPublisher :
        IWorkerAuditAnchorPublisher
    {
        public bool Publish(bool workerReady)
        {
            return false;
        }
    }
}

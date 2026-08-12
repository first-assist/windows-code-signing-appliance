using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerStateStoreTests
{
    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 29, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void PersistsAuditedCompareAndSwapLifecycle()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('1');
        string evidenceDigest = Digest('a');

        WorkerMutationResult admitted = store.AdmitApproved(
            requestId,
            requestDigest,
            InitialTime);
        Assert.Equal(WorkerMutationOutcome.Applied, admitted.Outcome);
        Assert.Equal(RequestState.Approved, admitted.Job?.State);
        Assert.Equal(1, admitted.Job?.RowVersion);

        WorkerMutationResult claimed = store.TryBeginSigning(
            requestId,
            requestDigest,
            1,
            InitialTime.AddSeconds(1));
        Assert.Equal(WorkerMutationOutcome.Applied, claimed.Outcome);
        Assert.Equal(RequestState.Signing, claimed.Job?.State);
        Assert.Equal(2, claimed.Job?.RowVersion);

        WorkerMutationResult completed = store.TryCompleteSigned(
            requestId,
            requestDigest,
            2,
            evidenceDigest,
            InitialTime.AddSeconds(2));
        Assert.Equal(WorkerMutationOutcome.Applied, completed.Outcome);
        Assert.Equal(RequestState.Signed, completed.Job?.State);
        Assert.Equal(3, completed.Job?.RowVersion);
        Assert.Equal(evidenceDigest, completed.Job?.EvidenceDigest);

        WorkerStateStore reopened = environment.CreateStore();
        reopened.VerifyIntegrity();
        Assert.Equal(completed.Job, reopened.GetJob(requestId));
        Assert.Empty(reopened.GetSigningJobs());
    }

    [Fact]
    public void ApprovedAdmissionIsIdempotentButRejectsIdentityConflicts()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('2');

        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        WorkerMutationResult same = store.AdmitApproved(
            requestId,
            requestDigest,
            InitialTime.AddSeconds(1));
        WorkerMutationResult changedDigest = store.AdmitApproved(
            requestId,
            Digest('3'),
            InitialTime.AddSeconds(1));
        WorkerMutationResult changedId = store.AdmitApproved(
            Guid.NewGuid(),
            requestDigest,
            InitialTime.AddSeconds(1));

        Assert.Equal(WorkerMutationOutcome.AlreadyApplied, same.Outcome);
        Assert.Equal(WorkerMutationOutcome.Conflict, changedDigest.Outcome);
        Assert.Equal(WorkerMutationOutcome.Conflict, changedId.Outcome);
        Assert.Equal(1, store.GetJob(requestId)?.RowVersion);
        store.VerifyIntegrity();
    }

    [Fact]
    public void StaleClaimsCannotRepeatKeyBoundaryTransition()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('4');
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);

        WorkerMutationResult first = store.TryBeginSigning(
            requestId,
            requestDigest,
            1,
            InitialTime.AddSeconds(1));
        WorkerMutationResult repeated = store.TryBeginSigning(
            requestId,
            requestDigest,
            1,
            InitialTime.AddSeconds(2));

        Assert.Equal(WorkerMutationOutcome.Applied, first.Outcome);
        Assert.Equal(WorkerMutationOutcome.AlreadyApplied, repeated.Outcome);
        Assert.Equal(2, store.GetJob(requestId)?.RowVersion);
        store.VerifyIntegrity();
    }

    [Fact]
    public void DurableSigningLeaseAllowsOnlyOneClaim()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid firstId = Guid.NewGuid();
        Guid secondId = Guid.NewGuid();
        _ = store.AdmitApproved(firstId, Digest('5'), InitialTime);
        _ = store.AdmitApproved(
            secondId,
            Digest('6'),
            InitialTime.AddSeconds(1));

        WorkerMutationResult first = store.TryBeginSigning(
            firstId,
            Digest('5'),
            1,
            InitialTime.AddSeconds(2));
        WorkerMutationResult second = store.TryBeginSigning(
            secondId,
            Digest('6'),
            1,
            InitialTime.AddSeconds(3));

        Assert.Equal(WorkerMutationOutcome.Applied, first.Outcome);
        Assert.Equal(WorkerMutationOutcome.SigningBusy, second.Outcome);
        Assert.Equal(RequestState.Approved, store.GetJob(secondId)?.State);
        Assert.Single(store.GetSigningJobs());
    }

    [Fact]
    public async Task ConcurrentStoresSerializeClaimsThroughDurableLease()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore firstStore = environment.CreateStore();
        WorkerStateStore secondStore = environment.CreateStore();
        Guid firstId = Guid.NewGuid();
        Guid secondId = Guid.NewGuid();
        _ = firstStore.AdmitApproved(firstId, Digest('a'), InitialTime);
        _ = firstStore.AdmitApproved(
            secondId,
            Digest('b'),
            InitialTime.AddSeconds(1));
        TaskCompletionSource gate = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        Task<WorkerMutationResult> firstClaim = Task.Run(
            async () =>
            {
                await gate.Task.ConfigureAwait(true);
                return firstStore.TryBeginSigning(
                    firstId,
                    Digest('a'),
                    1,
                    InitialTime.AddSeconds(2));
            },
            TestContext.Current.CancellationToken);
        Task<WorkerMutationResult> secondClaim = Task.Run(
            async () =>
            {
                await gate.Task.ConfigureAwait(true);
                return secondStore.TryBeginSigning(
                    secondId,
                    Digest('b'),
                    1,
                    InitialTime.AddSeconds(2));
            },
            TestContext.Current.CancellationToken);

        gate.SetResult();
        WorkerMutationResult[] results = await Task.WhenAll(
            firstClaim,
            secondClaim).ConfigureAwait(true);

        Assert.Single(
            results,
            result => result.Outcome is WorkerMutationOutcome.Applied);
        Assert.Single(
            results,
            result => result.Outcome is WorkerMutationOutcome.SigningBusy);
        Assert.Single(firstStore.GetSigningJobs());
        firstStore.VerifyIntegrity();
    }

    [Fact]
    public void AuditEventTamperingFailsClosedOnRestart()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        _ = store.AdmitApproved(
            Guid.NewGuid(),
            Digest('7'),
            InitialTime);
        environment.ExecuteSql(
            """
            UPDATE WorkerEvents
            SET ResultCode = 'SigningCompleted'
            WHERE Sequence = 1
            """);

        InvalidDataException exception = Assert.Throws<InvalidDataException>(
            environment.CreateStore);

        Assert.Equal(
            "Worker durable state integrity verification failed.",
            exception.Message);
    }

    [Fact]
    public void AuditHeadTamperingRollsBackAStateMutation()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string requestDigest = Digest('8');
        _ = store.AdmitApproved(requestId, requestDigest, InitialTime);
        environment.ExecuteSql(
            """
            UPDATE WorkerAuditHead
            SET EventDigest =
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            WHERE Id = 1
            """);

        _ = Assert.Throws<InvalidDataException>(
            () => store.TryBeginSigning(
                requestId,
                requestDigest,
                1,
                InitialTime.AddSeconds(1)));
        environment.ExecuteSql(
            """
            UPDATE WorkerAuditHead
            SET EventDigest = (
                SELECT EventDigest
                FROM WorkerEvents
                WHERE Sequence = 1
            )
            WHERE Id = 1
            """);

        WorkerStateStore reopened = environment.CreateStore();
        Assert.Equal(RequestState.Approved, reopened.GetJob(requestId)?.State);
        Assert.Equal(1, reopened.GetJob(requestId)?.RowVersion);
    }

    [Fact]
    public void JobStateDriftFailsClosedOnRestart()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        _ = store.AdmitApproved(
            Guid.NewGuid(),
            Digest('9'),
            InitialTime);
        environment.ExecuteSql(
            """
            UPDATE WorkerJobs
            SET ResultCode = 'ApprovalRevalidationFailed'
            """);

        _ = Assert.Throws<InvalidDataException>(environment.CreateStore);
    }

    [Fact]
    public void UnknownSchemaVersionFailsClosed()
    {
        using WorkerStateTestEnvironment environment = new();
        _ = environment.CreateStore();
        environment.ExecuteSql(
            """
            UPDATE SchemaMigrations
            SET Version = 2
            WHERE Version = 1
            """);

        _ = Assert.Throws<InvalidDataException>(environment.CreateStore);
    }

    private static string Digest(char character)
    {
        return new string(character, 64);
    }
}

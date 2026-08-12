using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayStateStoreTests
{
    private static int _nonceCounter;

    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 29, 14, 0, 0, TimeSpan.Zero);

    private static readonly string SubmitterSpki = Digest('a');
    private static readonly string ApproverSpki = Digest('b');

    internal static ArtifactSigningRequestV1
        CreateRequestForOtherTests()
    {
        return CreateRequest();
    }

    [Fact]
    public void AdmissionPersistsRequestArtifactsAndAuditAtomically()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();

        GatewayMutationResult result = store.AdmitPending(
            request,
            Digest('1'),
            SubmitterSpki,
            InitialTime.AddSeconds(1));

        Assert.Equal(
            GatewayMutationOutcome.Applied,
            result.Outcome);
        Assert.Equal(
            RequestState.PendingApproval,
            result.Request?.State);
        Assert.Equal(1, result.Request?.RowVersion);
        Assert.Equal(
            request.Artifacts.OrderBy(
                item => item.Role,
                StringComparer.Ordinal),
            store.GetRequestArtifacts(request.RequestId));
        environment.CreateStore().VerifyIntegrity();
    }

    [Fact]
    public void SameRequestIdAndDigestIsIdempotent()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        _ = store.AdmitPending(
            request,
            Digest('2'),
            SubmitterSpki,
            InitialTime.AddSeconds(1));

        GatewayMutationResult result = store.AdmitPending(
            request,
            Digest('2'),
            SubmitterSpki,
            InitialTime.AddSeconds(2));

        Assert.Equal(
            GatewayMutationOutcome.AlreadyApplied,
            result.Outcome);
        Assert.Equal(1, result.Request?.RowVersion);
    }

    [Fact]
    public void NonterminalCapacityIsAtomicButExactRetryRemainsIdempotent()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1? first = null;
        for (int index = 0;
             index < GatewayStateStore.MaximumNonterminalRequests;
             index++)
        {
            ArtifactSigningRequestV1 request = CreateRequest();
            first ??= request;
            GatewayMutationResult admitted = store.AdmitPending(
                request,
                Digest((char)('a' + index)),
                SubmitterSpki,
                InitialTime.AddSeconds(index + 1));
            Assert.Equal(
                GatewayMutationOutcome.Applied,
                admitted.Outcome);
        }

        GatewayMutationResult overflow = store.AdmitPending(
            CreateRequest(),
            Digest('f'),
            SubmitterSpki,
            InitialTime.AddSeconds(10));
        GatewayMutationResult retry = store.AdmitPending(
            first!,
            Digest('a'),
            SubmitterSpki,
            InitialTime.AddSeconds(11));

        Assert.Equal(
            GatewayMutationOutcome.CapacityExceeded,
            overflow.Outcome);
        Assert.Equal(
            GatewayMutationOutcome.AlreadyApplied,
            retry.Outcome);
        Assert.Equal(
            GatewayStateStore.MaximumNonterminalRequests,
            store.CountNonterminalRequests());
    }

    [Fact]
    public void ReusedRequestIdentityNonceOrDigestConflicts()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 first = CreateRequest();
        _ = store.AdmitPending(
            first,
            Digest('3'),
            SubmitterSpki,
            InitialTime.AddSeconds(1));
        ArtifactSigningRequestV1 reusedNonce = CreateRequest(
            Guid.NewGuid(),
            first.Nonce);

        GatewayMutationResult sameId = store.AdmitPending(
            first with { ReleaseVersion = "2.0.0" },
            Digest('4'),
            SubmitterSpki,
            InitialTime.AddSeconds(2));
        GatewayMutationResult sameNonce = store.AdmitPending(
            reusedNonce,
            Digest('5'),
            SubmitterSpki,
            InitialTime.AddSeconds(2));
        GatewayMutationResult sameDigest = store.AdmitPending(
            CreateRequest(),
            Digest('3'),
            SubmitterSpki,
            InitialTime.AddSeconds(2));

        Assert.Equal(
            GatewayMutationOutcome.Conflict,
            sameId.Outcome);
        Assert.Equal(
            GatewayMutationOutcome.NonceReplay,
            sameNonce.Outcome);
        Assert.Equal(
            GatewayMutationOutcome.Conflict,
            sameDigest.Outcome);
    }

    [Fact]
    public void ApprovalNonceAndStateAdvanceInOneTransaction()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        const char requestDigestCharacter = '6';
        string requestDigest = Digest(requestDigestCharacter);
        GatewayRequestRecord admitted = store.AdmitPending(
                request,
                requestDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;
        ArtifactSigningApprovalV1 approval = CreateApproval(
            request.RequestId,
            requestDigest,
            ApprovalDecision.Approve);

        GatewayApprovalMutationResult result =
            store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                admitted.RowVersion,
                approval,
                ApproverSpki,
                Digest('7'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2));

        Assert.Equal(
            GatewayMutationOutcome.Applied,
            result.Outcome);
        Assert.Equal(
            RequestState.Approved,
            result.Request?.State);
        Assert.Equal(2, result.Request?.RowVersion);
        Assert.Equal(approval.Nonce, result.Approval?.Nonce);
        Assert.Equal(
            ApproverSpki,
            store.GetApproval(request.RequestId)
                ?.ApproverSpkiSha256);
        store.VerifyIntegrity();
    }

    [Fact]
    public void ExactApprovalRetryIsIdempotent()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('8');
        GatewayRequestRecord admitted = store.AdmitPending(
                request,
                requestDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;
        ArtifactSigningApprovalV1 approval = CreateApproval(
            request.RequestId,
            requestDigest,
            ApprovalDecision.Approve);
        _ = store.TryRecordApproval(
            request.RequestId,
            requestDigest,
            admitted.RowVersion,
            approval,
            ApproverSpki,
            Digest('9'),
            requireDistinctSubmitterAndApprover: true,
            InitialTime.AddMinutes(2));

        GatewayApprovalMutationResult retry =
            store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                admitted.RowVersion,
                approval,
                ApproverSpki,
                Digest('9'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2));

        Assert.Equal(
            GatewayMutationOutcome.AlreadyApplied,
            retry.Outcome);
        Assert.Equal(
            RequestState.Approved,
            retry.Request?.State);
    }

    [Fact]
    public void ReusedApprovalNonceAcrossRequestsIsRejected()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 first = CreateRequest();
        ArtifactSigningRequestV1 second = CreateRequest();
        string firstDigest = Digest('c');
        string secondDigest = Digest('d');
        GatewayRequestRecord firstRecord = store.AdmitPending(
                first,
                firstDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;
        GatewayRequestRecord secondRecord = store.AdmitPending(
                second,
                secondDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(2))
            .Request!;
        ArtifactSigningApprovalV1 firstApproval = CreateApproval(
            first.RequestId,
            firstDigest,
            ApprovalDecision.Approve);
        _ = store.TryRecordApproval(
            first.RequestId,
            firstDigest,
            firstRecord.RowVersion,
            firstApproval,
            ApproverSpki,
            Digest('e'),
            requireDistinctSubmitterAndApprover: true,
            InitialTime.AddMinutes(2));
        ArtifactSigningApprovalV1 replay =
            CreateApproval(
                second.RequestId,
                secondDigest,
                ApprovalDecision.Approve) with
            {
                Nonce = firstApproval.Nonce,
            };

        GatewayApprovalMutationResult result =
            store.TryRecordApproval(
                second.RequestId,
                secondDigest,
                secondRecord.RowVersion,
                replay,
                ApproverSpki,
                Digest('f'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2));

        Assert.Equal(
            GatewayMutationOutcome.NonceReplay,
            result.Outcome);
        Assert.Equal(
            RequestState.PendingApproval,
            store.GetRequest(second.RequestId)?.State);
    }

    [Fact]
    public void ProductionDualControlRejectsSubmitterApproval()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('1');
        GatewayRequestRecord admitted = store.AdmitPending(
                request,
                requestDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;

        GatewayApprovalMutationResult result =
            store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                admitted.RowVersion,
                CreateApproval(
                    request.RequestId,
                    requestDigest,
                    ApprovalDecision.Approve),
                SubmitterSpki,
                Digest('2'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2));

        Assert.Equal(
            GatewayMutationOutcome.DualControlViolation,
            result.Outcome);
        Assert.Null(store.GetApproval(request.RequestId));
    }

    [Fact]
    public void RejectionIsTerminalAndAudited()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('3');
        GatewayRequestRecord admitted = store.AdmitPending(
                request,
                requestDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;

        GatewayApprovalMutationResult result =
            store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                admitted.RowVersion,
                CreateApproval(
                    request.RequestId,
                    requestDigest,
                    ApprovalDecision.Reject),
                ApproverSpki,
                Digest('4'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2));

        Assert.Equal(RequestState.Rejected, result.Request?.State);
        Assert.True(
            RequestStateTransitions.IsTerminal(
                result.Request!.State));
        store.VerifyIntegrity();
    }

    [Fact]
    public void CancelAndExpiryUseCompareAndSwap()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 cancelRequest = CreateRequest();
        ArtifactSigningRequestV1 expiryRequest = CreateRequest();
        GatewayRequestRecord cancelRecord = store.AdmitPending(
                cancelRequest,
                Digest('5'),
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;
        GatewayRequestRecord expiryRecord = store.AdmitPending(
                expiryRequest,
                Digest('6'),
                SubmitterSpki,
                InitialTime.AddSeconds(2))
            .Request!;

        GatewayMutationResult cancelled = store.TryCancel(
            cancelRequest.RequestId,
            Digest('5'),
            cancelRecord.RowVersion,
            InitialTime.AddMinutes(2));
        GatewayMutationResult stale = store.TryCancel(
            expiryRequest.RequestId,
            Digest('6'),
            expiryRecord.RowVersion + 1,
            InitialTime.AddMinutes(2));
        GatewayMutationResult expired = store.TryExpire(
            expiryRequest.RequestId,
            Digest('6'),
            expiryRecord.RowVersion,
            InitialTime.AddMinutes(2));

        Assert.Equal(RequestState.Cancelled, cancelled.Request?.State);
        Assert.Equal(
            GatewayMutationOutcome.StateMismatch,
            stale.Outcome);
        Assert.Equal(RequestState.Expired, expired.Request?.State);
        store.VerifyIntegrity();
    }

    [Fact]
    public void AuditOrSchemaTamperFailsClosed()
    {
        using GatewayStateTestEnvironment auditEnvironment = new();
        GatewayStateStore auditStore =
            auditEnvironment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        _ = auditStore.AdmitPending(
            request,
            Digest('7'),
            SubmitterSpki,
            InitialTime.AddSeconds(1));
        auditEnvironment.ExecuteSql(
            """
            UPDATE GatewayEvents
            SET EventDigest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            WHERE Sequence = 1
            """);
        Assert.Throws<InvalidDataException>(
            auditStore.VerifyIntegrity);

        using GatewayStateTestEnvironment schemaEnvironment = new();
        GatewayStateStore schemaStore =
            schemaEnvironment.CreateStore();
        schemaEnvironment.ExecuteSql(
            "ALTER TABLE Requests ADD COLUMN Drift TEXT NULL;");
        Assert.Throws<InvalidDataException>(
            schemaStore.VerifyIntegrity);
    }

    [Fact]
    public void ClientCertificateObservationPinsCertificateToSpki()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        string certificateDigest = Digest('a');

        GatewayIdentityObservationResult first =
            store.ObserveClientIdentity(
                certificateDigest,
                SubmitterSpki,
                InitialTime);
        GatewayIdentityObservationResult second =
            store.ObserveClientIdentity(
                certificateDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1));
        GatewayIdentityObservationResult mismatch =
            store.ObserveClientIdentity(
                certificateDigest,
                ApproverSpki,
                InitialTime.AddSeconds(2));

        Assert.Equal(
            GatewayIdentityObservationOutcome.Recorded,
            first.Outcome);
        Assert.Equal(
            GatewayIdentityObservationOutcome.Updated,
            second.Outcome);
        Assert.Equal(2, second.Observation.ObservationCount);
        Assert.Equal(
            GatewayIdentityObservationOutcome.IdentityMismatch,
            mismatch.Outcome);
        Assert.Equal(
            SubmitterSpki,
            mismatch.Observation.SubjectPublicKeyInfoSha256);
        store.VerifyIntegrity();
    }

    [Fact]
    public void NoncanonicalNonceAndUnsafeApprovalReasonAreRejected()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 invalidRequest =
            CreateRequest() with
            {
                Nonce = new string('A', 42) + "B",
            };
        Assert.Throws<ArgumentException>(
            () => store.AdmitPending(
                invalidRequest,
                Digest('b'),
                SubmitterSpki,
                InitialTime.AddSeconds(1)));

        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('c');
        GatewayRequestRecord admitted = store.AdmitPending(
                request,
                requestDigest,
                SubmitterSpki,
                InitialTime.AddSeconds(1))
            .Request!;
        ArtifactSigningApprovalV1 invalidApproval =
            CreateApproval(
                request.RequestId,
                requestDigest,
                ApprovalDecision.Approve) with
            {
                Reason = "unsafe\nreason",
            };

        Assert.Throws<ArgumentException>(
            () => store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                admitted.RowVersion,
                invalidApproval,
                ApproverSpki,
                Digest('d'),
                requireDistinctSubmitterAndApprover: true,
                InitialTime.AddMinutes(2)));
    }

    private static ArtifactSigningRequestV1 CreateRequest(
        Guid? requestId = null,
        string? nonce = null)
    {
        return new ArtifactSigningRequestV1(
            requestId ?? Guid.NewGuid(),
            "synthetic-project",
            "SyntheticProfileV1",
            1,
            "example/synthetic",
            new string('1', 40),
            "1.0.0",
            InitialTime,
            InitialTime.AddMinutes(15),
            nonce ?? NextNonce(),
            "SyntheticSignerV1",
            "SyntheticTimestampV1",
            [
                new RequestArtifactV1(
                    "Manifest",
                    "manifest.json",
                    1,
                    Digest('8')),
                new RequestArtifactV1(
                    "Agent",
                    "agent.exe",
                    2,
                    Digest('9')),
            ]);
    }

    private static ArtifactSigningApprovalV1 CreateApproval(
        Guid requestId,
        string requestDigest,
        ApprovalDecision decision)
    {
        return new ArtifactSigningApprovalV1(
            requestId,
            requestDigest,
            decision,
            "Synthetic release accepted",
            InitialTime.AddMinutes(1),
            InitialTime.AddMinutes(5),
            NextNonce());
    }

    private static string Digest(char character)
    {
        return new string(character, 64);
    }

    private static string CanonicalNonce(int value)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(
                        checked((byte)value),
                        32)
                    .ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string NextNonce()
    {
        int value = Interlocked.Increment(ref _nonceCounter);
        return CanonicalNonce(value % 254 + 1);
    }
}

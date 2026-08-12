using System.Security.Cryptography;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public enum GatewayApprovalError
{
    None,
    TransportIdentityMismatch,
    RequestNotFound,
    RequestNotPending,
    SignatureInvalid,
    ApprovalInvalid,
    DualControlViolation,
    Conflict,
    StorageFailed,
}

public sealed record GatewayApprovalResult(
    GatewayApprovalError Error,
    GatewayRequestRecord? Request,
    bool WorkerNotificationRequired)
{
    public bool IsSuccess =>
        Error is GatewayApprovalError.None
        && Request is not null;
}

public sealed class GatewayApproverPolicy
{
    public GatewayApproverPolicy(
        string projectId,
        string profileId,
        int profileVersion,
        CmsTrustPolicy trustPolicy,
        bool requireDistinctSubmitterAndApprover)
    {
        ArgumentNullException.ThrowIfNull(projectId);
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            profileVersion);
        if (!GatewayContractRules.IsSafeIdentifier(projectId)
            || !GatewayContractRules.IsSafeIdentifier(profileId))
        {
            throw new ArgumentException(
                "Approver policy identity is invalid.");
        }

        ProjectId = projectId;
        ProfileId = profileId;
        ProfileVersion = profileVersion;
        TrustPolicy = trustPolicy;
        RequireDistinctSubmitterAndApprover =
            requireDistinctSubmitterAndApprover;
    }

    public string ProjectId { get; }

    public string ProfileId { get; }

    public int ProfileVersion { get; }

    public CmsTrustPolicy TrustPolicy { get; }

    public bool RequireDistinctSubmitterAndApprover { get; }
}

public sealed class GatewayApprovalProcessor
{
    public const string ApprovalSignatureFileName = "approval.p7s";

    private readonly GatewayStateStore _stateStore;
    private readonly IGatewayReadyRecordAccessController
        _readyRecordAccess;
    private readonly TimeProvider _timeProvider;

    public GatewayApprovalProcessor(
        GatewayStateStore stateStore,
        IGatewayReadyRecordAccessController readyRecordAccess,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(readyRecordAccess);
        _stateStore = stateStore;
        _readyRecordAccess = readyRecordAccess;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public GatewayApprovalResult Process(
        Guid requestId,
        ReadOnlyMemory<byte> approvalSignature,
        GatewayApproverPolicy approverPolicy,
        string authenticatedSpkiSha256)
    {
        if (requestId == Guid.Empty)
        {
            return Failure(GatewayApprovalError.RequestNotFound);
        }

        ArgumentNullException.ThrowIfNull(approverPolicy);
        GatewayContractRules.ValidateSpki(
            authenticatedSpkiSha256,
            nameof(authenticatedSpkiSha256));
        if (!string.Equals(
                authenticatedSpkiSha256,
                approverPolicy.TrustPolicy
                    .ExpectedSignerSpkiSha256,
                StringComparison.Ordinal))
        {
            return Failure(
                GatewayApprovalError.TransportIdentityMismatch);
        }

        if (approvalSignature.IsEmpty
            || approvalSignature.Length
                > DetachedCmsSignatureVerifier.MaximumSignatureBytes)
        {
            return Failure(GatewayApprovalError.SignatureInvalid);
        }

        try
        {
            GatewayRequestRecord? current =
                _stateStore.GetRequest(requestId);
            if (current is null)
            {
                return Failure(
                    GatewayApprovalError.RequestNotFound);
            }

            if (!MatchesPolicy(current, approverPolicy))
            {
                return Failure(GatewayApprovalError.Conflict);
            }

            string cmsDigest = Convert.ToHexStringLower(
                SHA256.HashData(approvalSignature.Span));
            GatewayApprovalRecord? existing =
                _stateStore.GetApproval(requestId);
            if (existing is not null)
            {
                return RecoverExactPublication(
                    current,
                    existing,
                    approvalSignature,
                    cmsDigest,
                    authenticatedSpkiSha256);
            }

            if (current.State is not RequestState.PendingApproval)
            {
                return Failure(
                    GatewayApprovalError.RequestNotPending,
                    current);
            }

            DateTimeOffset now = GetWholeSecondUtcNow();
            TrustedAttachedCmsVerificationResult verification =
                TrustedAttachedCmsSignatureVerifier.Verify(
                    approvalSignature,
                    approverPolicy.TrustPolicy,
                    now,
                    ArtifactSigningApprovalJsonParser
                        .MaximumApprovalJsonBytes);
            if (!verification.IsSuccess
                || verification.Signer is null
                || !string.Equals(
                    verification.Signer
                        .SubjectPublicKeyInfoSha256,
                    authenticatedSpkiSha256,
                    StringComparison.Ordinal))
            {
                return Failure(
                    GatewayApprovalError.SignatureInvalid);
            }

            ApprovalJsonParseResult parsed =
                ArtifactSigningApprovalJsonParser.Parse(
                    verification.GetContentBytes());
            if (!parsed.IsSuccess || parsed.Approval is null)
            {
                return Failure(
                    GatewayApprovalError.ApprovalInvalid);
            }

            GatewayApprovalMutationResult mutation =
                _stateStore.TryRecordApproval(
                    requestId,
                    current.RequestDigest,
                    current.RowVersion,
                    parsed.Approval,
                    authenticatedSpkiSha256,
                    cmsDigest,
                    approverPolicy
                        .RequireDistinctSubmitterAndApprover,
                    now);
            if (mutation.Request is null
                || mutation.Approval is null)
            {
                return Failure(
                    MapMutationError(mutation.Outcome),
                    mutation.Request);
            }

            if (mutation.Outcome is not (
                    GatewayMutationOutcome.Applied
                    or GatewayMutationOutcome.AlreadyApplied))
            {
                return Failure(
                    MapMutationError(mutation.Outcome),
                    mutation.Request);
            }

            return PublishDecision(
                mutation.Request,
                mutation.Approval,
                approvalSignature,
                cmsDigest,
                authenticatedSpkiSha256);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Failure(GatewayApprovalError.StorageFailed);
        }
    }

    private GatewayApprovalResult RecoverExactPublication(
        GatewayRequestRecord current,
        GatewayApprovalRecord existing,
        ReadOnlyMemory<byte> approvalSignature,
        string cmsDigest,
        string approverSpkiSha256)
    {
        if (!string.Equals(
                existing.RequestDigest,
                current.RequestDigest,
                StringComparison.Ordinal)
            || !string.Equals(
                existing.ApproverSpkiSha256,
                approverSpkiSha256,
                StringComparison.Ordinal)
            || !FixedTimeDigestEquals(
                existing.ApprovalCmsSha256,
                cmsDigest))
        {
            return Failure(GatewayApprovalError.Conflict, current);
        }

        return PublishDecision(
            current,
            existing,
            approvalSignature,
            cmsDigest,
            approverSpkiSha256);
    }

    private GatewayApprovalResult PublishDecision(
        GatewayRequestRecord request,
        GatewayApprovalRecord approval,
        ReadOnlyMemory<byte> approvalSignature,
        string cmsDigest,
        string approverSpkiSha256)
    {
        bool stateMatchesDecision =
            approval.Decision is ApprovalDecision.Approve
                ? request.State is RequestState.Approved
                    or RequestState.Signing
                    or RequestState.Signed
                : request.State is RequestState.Rejected;
        if (!stateMatchesDecision
            || !string.Equals(
                approval.RequestDigest,
                request.RequestDigest,
                StringComparison.Ordinal)
            || !string.Equals(
                approval.ApproverSpkiSha256,
                approverSpkiSha256,
                StringComparison.Ordinal)
            || !FixedTimeDigestEquals(
                approval.ApprovalCmsSha256,
                cmsDigest))
        {
            return Failure(GatewayApprovalError.Conflict, request);
        }

        string pending =
            _stateStore.Layout.GetPendingRequestDirectory(
                request.RequestId);
        if (approval.Decision is ApprovalDecision.Reject)
        {
            TryDeleteOwnedDirectory(pending);
            return Success(
                request,
                workerNotificationRequired: false);
        }

        string ready =
            _stateStore.Layout.GetReadyRequestDirectory(
                request.RequestId);
        if (Directory.Exists(ready))
        {
            return ReadyContainsExactApproval(
                    ready,
                    cmsDigest)
                && _readyRecordAccess.PrepareForWorker(request)
                ? Success(
                    request,
                    workerNotificationRequired:
                        request.State is not RequestState.Signed)
                : Failure(GatewayApprovalError.Conflict, request);
        }

        if (!Directory.Exists(pending))
        {
            return Failure(
                GatewayApprovalError.StorageFailed,
                request);
        }

        WriteExactApproval(
            pending,
            approvalSignature,
            cmsDigest);
        try
        {
            Directory.Move(pending, ready);
        }
        catch (IOException) when (
            Directory.Exists(ready)
            && ReadyContainsExactApproval(ready, cmsDigest))
        {
            TryDeleteOwnedDirectory(pending);
        }

        if (!_readyRecordAccess.PrepareForWorker(request))
        {
            return Failure(
                GatewayApprovalError.StorageFailed,
                request);
        }

        return Success(
            request,
            workerNotificationRequired:
                request.State is not RequestState.Signed);
    }

    private static void WriteExactApproval(
        string pendingDirectory,
        ReadOnlyMemory<byte> approvalSignature,
        string expectedDigest)
    {
        string approvalPath = Path.Combine(
            pendingDirectory,
            ApprovalSignatureFileName);
        if (File.Exists(approvalPath))
        {
            if (!FileHasDigest(approvalPath, expectedDigest))
            {
                throw new InvalidDataException(
                    "Stored approval differs from durable state.");
            }

            return;
        }

        string temporaryPath = Path.Combine(
            pendingDirectory,
            "approval.p7s.new");
        if (File.Exists(temporaryPath))
        {
            if (!FileHasDigest(temporaryPath, expectedDigest))
            {
                throw new InvalidDataException(
                    "Partial approval differs from durable state.");
            }
        }
        else
        {
            using FileStream output = new(
                temporaryPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 64 * 1024,
                    Options = FileOptions.WriteThrough,
                });
            output.Write(approvalSignature.Span);
            output.Flush(flushToDisk: true);
        }

        File.Move(temporaryPath, approvalPath);
    }

    private static bool ReadyContainsExactApproval(
        string readyDirectory,
        string expectedDigest)
    {
        try
        {
            return FileHasDigest(
                Path.Combine(
                    readyDirectory,
                    ApprovalSignatureFileName),
                expectedDigest);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool FileHasDigest(
        string path,
        string expectedDigest)
    {
        using FileStream input = GatewayDirectFile.OpenRead(path);
        if (input.Length is <= 0
            || input.Length
                > DetachedCmsSignatureVerifier.MaximumSignatureBytes)
        {
            return false;
        }

        string observed = Convert.ToHexStringLower(
            SHA256.HashData(input));
        return FixedTimeDigestEquals(
            observed,
            expectedDigest);
    }

    private static bool FixedTimeDigestEquals(
        string first,
        string second)
    {
        return first.Length is 64
            && second.Length is 64
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(first),
                Convert.FromHexString(second));
    }

    private static bool MatchesPolicy(
        GatewayRequestRecord request,
        GatewayApproverPolicy policy)
    {
        return string.Equals(
                request.ProjectId,
                policy.ProjectId,
                StringComparison.Ordinal)
            && string.Equals(
                request.ProfileId,
                policy.ProfileId,
                StringComparison.Ordinal)
            && request.ProfileVersion == policy.ProfileVersion;
    }

    private DateTimeOffset GetWholeSecondUtcNow()
    {
        DateTimeOffset now =
            _timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private static GatewayApprovalError MapMutationError(
        GatewayMutationOutcome outcome)
    {
        return outcome switch
        {
            GatewayMutationOutcome.DualControlViolation =>
                GatewayApprovalError.DualControlViolation,
            GatewayMutationOutcome.ApprovalInvalid =>
                GatewayApprovalError.ApprovalInvalid,
            GatewayMutationOutcome.StateMismatch =>
                GatewayApprovalError.RequestNotPending,
            GatewayMutationOutcome.Conflict
                or GatewayMutationOutcome.NonceReplay =>
                GatewayApprovalError.Conflict,
            _ => GatewayApprovalError.StorageFailed,
        };
    }

    private static void TryDeleteOwnedDirectory(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            FileAttributes attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.Directory)
                && !attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Durable terminal metadata remains authoritative.
        }
        catch (UnauthorizedAccessException)
        {
            // Durable terminal metadata remains authoritative.
        }
    }

    private static GatewayApprovalResult Success(
        GatewayRequestRecord request,
        bool workerNotificationRequired)
    {
        return new GatewayApprovalResult(
            GatewayApprovalError.None,
            request,
            workerNotificationRequired);
    }

    private static GatewayApprovalResult Failure(
        GatewayApprovalError error,
        GatewayRequestRecord? request = null)
    {
        return new GatewayApprovalResult(
            error,
            request,
            WorkerNotificationRequired: false);
    }
}

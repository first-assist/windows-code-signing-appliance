using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public enum WorkerResultCode
{
    ApprovedValidated,
    ApprovalRevalidationFailed,
    SigningStarted,
    SigningCompleted,
    SigningOperationFailed,
    SigningReadyRecordInvalid,
    SigningAuthorizationInvalid,
    SigningArtifactPrecheckFailed,
    SigningToolInvocationFailed,
    SigningSignatureVerificationFailed,
    SigningProfileFinalizationFailed,
    SigningFinalizedValidationFailed,
    SigningReceiptSigningFailed,
    SigningOutputPreparationFailed,
    SigningCancelled,
    OutputPublicationFailed,
    CompletionPersistenceFailed,
    RestartAmbiguity,
}

public enum WorkerMutationOutcome
{
    Applied,
    AlreadyApplied,
    Conflict,
    StateMismatch,
    SigningBusy,
}

public sealed record WorkerJobRecord(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    long RowVersion,
    WorkerResultCode ResultCode,
    string? EvidenceDigest,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record WorkerMutationResult(
    WorkerMutationOutcome Outcome,
    WorkerJobRecord? Job);

public enum WorkerRevalidationError
{
    None,
    RequestInvalid,
    ApprovalInvalid,
    AuthorizationInvalid,
    ProfileInvalid,
    RequestExpired,
}

public sealed record WorkerRevalidationResult(WorkerRevalidationError Error)
{
    public bool IsSuccess => Error is WorkerRevalidationError.None;

    public static WorkerRevalidationResult Success { get; } =
        new(WorkerRevalidationError.None);
}

public enum WorkerSigningFailure
{
    ReadyRecordInvalid,
    AuthorizationInvalid,
    ArtifactPrecheckFailed,
    SignToolRejected,
    SignatureVerificationFailed,
    ProfileFinalizationFailed,
    FinalizedValidationFailed,
    ReceiptSigningFailed,
    OutputPreparationFailed,
}

public sealed record WorkerSigningOperationResult(
    WorkerSigningFailure? Failure,
    string? EvidenceDigest)
{
    public bool IsSuccess => Failure is null && EvidenceDigest is not null;

    public static WorkerSigningOperationResult Success(string evidenceDigest)
    {
        WorkerContractRules.ValidateDigest(evidenceDigest, nameof(evidenceDigest));
        return new WorkerSigningOperationResult(null, evidenceDigest);
    }

    public static WorkerSigningOperationResult Failed(WorkerSigningFailure failure)
    {
        if (!Enum.IsDefined(failure))
        {
            throw new ArgumentOutOfRangeException(nameof(failure));
        }

        return new WorkerSigningOperationResult(failure, null);
    }
}

public enum WorkerProcessingOutcome
{
    Completed,
    FailedBeforeSigning,
    Quarantined,
    SigningBusy,
    StateMismatch,
    ReconciliationRequired,
    CancelledBeforeSigning,
}

public sealed record WorkerProcessingResult(
    WorkerProcessingOutcome Outcome,
    WorkerJobRecord? Job);

public enum WorkerReconciliationOutcome
{
    NoAction,
    Quarantined,
    Unresolved,
}

public sealed record WorkerReconciliationResult(
    Guid RequestId,
    WorkerReconciliationOutcome Outcome,
    WorkerJobRecord? Job);

internal static class WorkerContractRules
{
    internal static void ValidateRequest(Guid requestId, string requestDigest)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        ValidateDigest(requestDigest, nameof(requestDigest));
    }

    internal static void ValidateDigest(string digest, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(digest, parameterName);
        if (digest.Length != 64)
        {
            throw new ArgumentException(
                "Digest must be canonical lowercase SHA-256.",
                parameterName);
        }

        foreach (char character in digest)
        {
            if (!char.IsAsciiDigit(character)
                && character is not (>= 'a' and <= 'f'))
            {
                throw new ArgumentException(
                    "Digest must be canonical lowercase SHA-256.",
                    parameterName);
            }
        }
    }

    internal static void ValidateTimestamp(
        DateTimeOffset timestamp,
        string parameterName)
    {
        if (timestamp.Offset != TimeSpan.Zero
            || timestamp.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentException(
                "Timestamp must be UTC with whole-second precision.",
                parameterName);
        }
    }
}

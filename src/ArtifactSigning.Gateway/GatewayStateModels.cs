using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public enum GatewayResultCode
{
    RequestAccepted,
    ApprovalAccepted,
    RequestRejected,
    RequestCancelled,
    RequestExpired,
    IntakeRestartFailed,
    ValidatedStateDrift,
    WorkerDispatchAccepted,
    SigningCompleted,
    WorkerResultRejected,
}

public enum GatewayMutationOutcome
{
    Applied,
    AlreadyApplied,
    Conflict,
    StateMismatch,
    NonceReplay,
    DualControlViolation,
    ApprovalInvalid,
    CapacityExceeded,
}

public sealed record GatewayRequestRecord(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    long RowVersion,
    GatewayResultCode ResultCode,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceRepository,
    string SourceCommit,
    string ReleaseVersion,
    string SignerPolicyId,
    string TimestampPolicyId,
    string RequestNonce,
    string SubmitterSpkiSha256,
    DateTimeOffset RequestedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record GatewayApprovalRecord(
    Guid RequestId,
    string RequestDigest,
    string ApproverSpkiSha256,
    ApprovalDecision Decision,
    string Reason,
    DateTimeOffset ApprovedAt,
    DateTimeOffset ExpiresAt,
    string Nonce,
    string ApprovalCmsSha256,
    DateTimeOffset CreatedAt);

public sealed record GatewayMutationResult(
    GatewayMutationOutcome Outcome,
    GatewayRequestRecord? Request);

public sealed record GatewayApprovalMutationResult(
    GatewayMutationOutcome Outcome,
    GatewayRequestRecord? Request,
    GatewayApprovalRecord? Approval);

public enum GatewayIdentityObservationOutcome
{
    Recorded,
    Updated,
    IdentityMismatch,
}

public sealed record GatewayClientIdentityObservation(
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256,
    DateTimeOffset FirstObservedAt,
    DateTimeOffset LastObservedAt,
    long ObservationCount);

public sealed record GatewayIdentityObservationResult(
    GatewayIdentityObservationOutcome Outcome,
    GatewayClientIdentityObservation Observation);

internal static class GatewayContractRules
{
    internal static void ValidateRequestIdentity(
        Guid requestId,
        string requestDigest)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        ValidateDigest(requestDigest, nameof(requestDigest));
    }

    internal static void ValidateDigest(
        string digest,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(digest, parameterName);
        if (!IsLowerHex(digest, 64))
        {
            throw new ArgumentException(
                "Digest must be canonical lowercase SHA-256.",
                parameterName);
        }
    }

    internal static void ValidateSpki(
        string spkiSha256,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(spkiSha256, parameterName);
        if (!IsLowerHex(spkiSha256, 64))
        {
            throw new ArgumentException(
                "Identity must be canonical SPKI SHA-256.",
                parameterName);
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

    internal static bool IsSafeIdentifier(string value)
    {
        return value.Length is > 0 and <= 64
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.');
    }

    internal static bool IsLowerHex(string value, int length)
    {
        return value.Length == length
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
    }
}

namespace ArtifactSigning.Protocol;

public enum ApprovalDecision
{
    Approve,
    Reject,
}

public sealed record ArtifactSigningApprovalV1(
    Guid RequestId,
    string RequestDigest,
    ApprovalDecision Decision,
    string Reason,
    DateTimeOffset ApprovedAt,
    DateTimeOffset ExpiresAt,
    string Nonce)
{
    public const string FormatIdentifier = "ArtifactSigningApprovalV1";
}

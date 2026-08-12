namespace ArtifactSigning.Protocol;

public sealed record ArtifactSigningRequestV1(
    Guid RequestId,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceRepository,
    string SourceCommit,
    string ReleaseVersion,
    DateTimeOffset RequestedAt,
    DateTimeOffset ExpiresAt,
    string Nonce,
    string SignerPolicyId,
    string TimestampPolicyId,
    IReadOnlyList<RequestArtifactV1> Artifacts)
{
    public const string FormatIdentifier = "ArtifactSigningRequestV1";
}

public sealed record RequestArtifactV1(
    string Role,
    string File,
    long Size,
    string Sha256);

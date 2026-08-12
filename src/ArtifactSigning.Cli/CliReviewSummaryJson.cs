using System.Text.Json;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal sealed record CliReviewArtifactSummaryV1(
    string Role,
    string File,
    long Size,
    string Sha256);

internal sealed record CliReviewSummaryV1(
    string Format,
    Guid RequestId,
    string RequestDigest,
    string State,
    bool CanApprove,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceRepository,
    string SourceCommit,
    string ReleaseVersion,
    string SignerPolicyId,
    string TimestampPolicyId,
    string RequestedAt,
    string ExpiresAt,
    string CreatedAt,
    string UpdatedAt,
    string SubmitterSpkiSha256,
    IReadOnlyList<CliReviewArtifactSummaryV1> Artifacts)
{
    internal const string FormatIdentifier =
        "ArtifactSigningReviewSummaryV1";
}

internal static class CliReviewSummaryJson
{
    private static readonly JsonSerializerOptions
        SerializerOptions = new()
        {
            WriteIndented = false,
        };

    internal static string Serialize(
        CliRequestStatus status,
        CliReviewedRequest review)
    {
        ArgumentNullException.ThrowIfNull(status);
        ArgumentNullException.ThrowIfNull(review);
        ArtifactSigningRequestV1 request =
            review.Request;
        CliReviewSummaryV1 summary = new(
            CliReviewSummaryV1.FormatIdentifier,
            request.RequestId,
            review.RequestDigest,
            status.State.ToString(),
            status.CanApprove,
            request.ProjectId,
            request.ProfileId,
            request.ProfileVersion,
            request.SourceRepository,
            request.SourceCommit,
            request.ReleaseVersion,
            request.SignerPolicyId,
            request.TimestampPolicyId,
            FormatTimestamp(request.RequestedAt),
            FormatTimestamp(request.ExpiresAt),
            FormatTimestamp(status.CreatedAt),
            FormatTimestamp(status.UpdatedAt),
            review.Submitter.SubjectPublicKeyInfoSha256,
            request.Artifacts
                .Select(item =>
                    new CliReviewArtifactSummaryV1(
                        item.Role,
                        item.File,
                        item.Size,
                        item.Sha256))
                .ToArray());
        return JsonSerializer.Serialize(
            summary,
            SerializerOptions);
    }

    private static string FormatTimestamp(
        DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            System.Globalization.CultureInfo.InvariantCulture);
    }
}

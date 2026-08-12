using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Cli.Tests;

public sealed class CliReviewSummaryJsonTests
{
    [Fact]
    public void EmitsStableBoundedReviewContract()
    {
        Guid requestId = Guid.ParseExact(
            "01234567-89ab-4cde-8f01-23456789abcd",
            "D");
        DateTimeOffset requestedAt = new(
            2026,
            8,
            9,
            10,
            11,
            12,
            TimeSpan.Zero);
        ArtifactSigningRequestV1 request = new(
            requestId,
            "example-project",
            "ExampleBundleV1",
            3,
            "example/project",
            "0123456789abcdef0123456789abcdef01234567",
            "1.2.3",
            requestedAt,
            requestedAt.AddMinutes(15),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ExamplePublicTrustV1",
            "ExampleRfc3161V1",
            [
                new RequestArtifactV1(
                    "Agent",
                    "example.exe",
                    1234,
                    new string('a', 64)),
            ]);
        CliRequestStatus status = new(
            requestId,
            new string('b', 64),
            RequestState.PendingApproval,
            "SigningPendingApproval",
            request.ProjectId,
            request.ProfileId,
            request.ProfileVersion,
            request.SourceRepository,
            request.SourceCommit,
            request.ReleaseVersion,
            request.RequestedAt,
            request.ExpiresAt,
            requestedAt.AddSeconds(1),
            requestedAt.AddSeconds(2),
            true,
            false);
        CliReviewedRequest review = new(
            request,
            status.RequestDigest,
            new CmsSignerIdentity(
                new string('c', 64),
                new string('d', 64)));

        string json = CliReviewSummaryJson.Serialize(
            status,
            review);

        Assert.Equal(
            "{\"Format\":\"ArtifactSigningReviewSummaryV1\",\"RequestId\":\"01234567-89ab-4cde-8f01-23456789abcd\",\"RequestDigest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"State\":\"PendingApproval\",\"CanApprove\":true,\"ProjectId\":\"example-project\",\"ProfileId\":\"ExampleBundleV1\",\"ProfileVersion\":3,\"SourceRepository\":\"example/project\",\"SourceCommit\":\"0123456789abcdef0123456789abcdef01234567\",\"ReleaseVersion\":\"1.2.3\",\"SignerPolicyId\":\"ExamplePublicTrustV1\",\"TimestampPolicyId\":\"ExampleRfc3161V1\",\"RequestedAt\":\"2026-08-09T10:11:12Z\",\"ExpiresAt\":\"2026-08-09T10:26:12Z\",\"CreatedAt\":\"2026-08-09T10:11:13Z\",\"UpdatedAt\":\"2026-08-09T10:11:14Z\",\"SubmitterSpkiSha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"Artifacts\":[{\"Role\":\"Agent\",\"File\":\"example.exe\",\"Size\":1234,\"Sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}",
            json);
        Assert.DoesNotContain('\n', json);
        Assert.DoesNotContain('\r', json);
    }
}

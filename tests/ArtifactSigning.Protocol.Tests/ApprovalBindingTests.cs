using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ApprovalBindingTests
{
    private static readonly Guid RequestId =
        Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc");

    private const string RequestDigest =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static readonly DateTimeOffset ApprovedAt =
        new(2026, 7, 27, 10, 1, 0, TimeSpan.Zero);

    private static readonly ArtifactSigningApprovalV1 Approval = new(
        RequestId,
        RequestDigest,
        ApprovalDecision.Approve,
        "Accepted",
        ApprovedAt,
        ApprovedAt.AddMinutes(5),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");

    [Fact]
    public void ValidateAcceptsExactBindingWithinWindow()
    {
        ApprovalBindingError result = ApprovalBinding.Validate(
            Approval,
            RequestId,
            RequestDigest,
            ApprovedAt.AddSeconds(1));

        Assert.Equal(ApprovalBindingError.None, result);
    }

    [Theory]
    [InlineData("not-a-digest", ApprovalBindingError.InvalidExpectedRequestDigest)]
    [InlineData(
        "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ApprovalBindingError.RequestDigestMismatch)]
    public void ValidateRejectsInvalidOrMismatchedDigest(
        string expectedDigest,
        ApprovalBindingError expected)
    {
        ApprovalBindingError result = ApprovalBinding.Validate(
            Approval,
            RequestId,
            expectedDigest,
            ApprovedAt.AddSeconds(1));

        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateRejectsMismatchedRequestId()
    {
        ApprovalBindingError result = ApprovalBinding.Validate(
            Approval,
            Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abd"),
            RequestDigest,
            ApprovedAt.AddSeconds(1));

        Assert.Equal(ApprovalBindingError.RequestIdMismatch, result);
    }

    [Theory]
    [InlineData(-1, ApprovalBindingError.NotYetValid)]
    [InlineData(300, ApprovalBindingError.Expired)]
    [InlineData(301, ApprovalBindingError.Expired)]
    public void ValidateEnforcesClosedExpiryWindow(
        int offsetSeconds,
        ApprovalBindingError expected)
    {
        ApprovalBindingError result = ApprovalBinding.Validate(
            Approval,
            RequestId,
            RequestDigest,
            ApprovedAt.AddSeconds(offsetSeconds));

        Assert.Equal(expected, result);
    }
}

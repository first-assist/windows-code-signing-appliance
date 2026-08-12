using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Protocol;

public enum ApprovalBindingError
{
    None,
    InvalidExpectedRequestDigest,
    RequestIdMismatch,
    RequestDigestMismatch,
    NotYetValid,
    Expired,
}

public static class ApprovalBinding
{
    public static ApprovalBindingError Validate(
        ArtifactSigningApprovalV1 approval,
        Guid expectedRequestId,
        string expectedRequestDigest,
        DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(expectedRequestDigest);

        if (!StrictJsonRules.IsLowerHex(expectedRequestDigest, 64))
        {
            return ApprovalBindingError.InvalidExpectedRequestDigest;
        }

        if (approval.RequestId != expectedRequestId)
        {
            return ApprovalBindingError.RequestIdMismatch;
        }

        if (!FixedTimeEquals(approval.RequestDigest, expectedRequestDigest))
        {
            return ApprovalBindingError.RequestDigestMismatch;
        }

        DateTimeOffset utcObservedAt = observedAt.ToUniversalTime();
        if (utcObservedAt < approval.ApprovedAt)
        {
            return ApprovalBindingError.NotYetValid;
        }

        if (utcObservedAt >= approval.ExpiresAt)
        {
            return ApprovalBindingError.Expired;
        }

        return ApprovalBindingError.None;
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left),
            Encoding.ASCII.GetBytes(right));
    }
}

using ArtifactSigning.Profiles;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public static class VerifiedProfileEvidenceFactory
{
    public static VerifiedAuthenticodeArtifact Create(
        string trustedRole,
        string trustedFileName,
        AuthenticodeVerificationResult verificationResult)
    {
        ArgumentNullException.ThrowIfNull(verificationResult);
        if (!verificationResult.IsSuccess || verificationResult.Evidence is null)
        {
            throw new InvalidOperationException(
                "Only successful Windows verification can create profile evidence.");
        }

        VerifiedAuthenticodeFile evidence = verificationResult.Evidence;
        return new VerifiedAuthenticodeArtifact(
            trustedRole,
            trustedFileName,
            evidence.Size,
            evidence.Sha256,
            evidence.SignerThumbprint,
            evidence.TimestampedAt);
    }
}

namespace ArtifactSigning.Windows;

public interface IAuthenticodeFileVerifier
{
    AuthenticodeVerificationError VerifyUnsigned(
        string trustedAbsolutePath,
        long expectedSize,
        string expectedSha256);

    AuthenticodeVerificationResult VerifySigned(
        string trustedAbsolutePath,
        long expectedSize,
        string expectedSha256,
        AuthenticodeTrustPolicy trustPolicy);
}

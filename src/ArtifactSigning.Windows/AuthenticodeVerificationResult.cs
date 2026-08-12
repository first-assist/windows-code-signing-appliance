namespace ArtifactSigning.Windows;

public sealed record AuthenticodeVerificationResult(
    VerifiedAuthenticodeFile? Evidence,
    AuthenticodeVerificationError Error)
{
    public bool IsSuccess =>
        Error is AuthenticodeVerificationError.None && Evidence is not null;

    internal static AuthenticodeVerificationResult Failure(
        AuthenticodeVerificationError error)
    {
        return new AuthenticodeVerificationResult(null, error);
    }
}

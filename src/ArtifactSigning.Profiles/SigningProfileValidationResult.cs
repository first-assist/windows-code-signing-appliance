namespace ArtifactSigning.Profiles;

public enum SigningProfileValidationError
{
    None,
    ProfileMismatch,
    ProjectNotAllowed,
    SourceRepositoryNotAllowed,
    SignerPolicyNotAllowed,
    TimestampPolicyNotAllowed,
    ArtifactInventoryMismatch,
    ArtifactUnavailable,
    ArtifactSizeMismatch,
    ArtifactHashMismatch,
    ManifestInvalid,
    ManifestExpired,
    BuildEvidenceInvalid,
    BuildEvidenceMismatch,
    ArtifactFormatInvalid,
    ArtifactAlreadySigned,
    ArtifactNotSigned,
    ArtifactVersionMismatch,
    SignerBindingInvalid,
    SignatureEvidenceMismatch,
    TimestampEvidenceInvalid,
    FinalizedManifestInvalid,
}

public sealed record SigningProfileValidationResult(SigningProfileValidationError Error)
{
    public bool IsSuccess => Error is SigningProfileValidationError.None;

    public static SigningProfileValidationResult Success { get; } =
        new(SigningProfileValidationError.None);

    public static SigningProfileValidationResult Failure(
        SigningProfileValidationError error)
    {
        if (error is SigningProfileValidationError.None || !Enum.IsDefined(error))
        {
            throw new ArgumentOutOfRangeException(nameof(error));
        }

        return new SigningProfileValidationResult(error);
    }
}

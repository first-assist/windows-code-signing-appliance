namespace ArtifactSigning.Profiles;

public interface ISigningProfile
{
    SigningProfileDescriptor Descriptor { get; }

    SigningProfileValidationResult ValidateUnsignedBundle(
        SigningProfileValidationContext context);

    SigningProfileFinalizationResult FinalizeSignedBundle(
        SigningProfileFinalizationContext context);

    SigningProfileValidationResult ValidateFinalizedBundle(
        SigningProfileFinalizedValidationContext context);
}

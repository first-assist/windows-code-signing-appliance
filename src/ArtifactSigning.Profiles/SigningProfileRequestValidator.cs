using ArtifactSigning.Protocol;

namespace ArtifactSigning.Profiles;

public static class SigningProfileRequestValidator
{
    public static SigningProfileValidationError Validate(
        SigningProfileDescriptor descriptor,
        ArtifactSigningRequestV1 request)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(request);

        if (!string.Equals(
                request.ProfileId,
                descriptor.Identity.ProfileId,
                StringComparison.Ordinal)
            || request.ProfileVersion != descriptor.Identity.ProfileVersion)
        {
            return SigningProfileValidationError.ProfileMismatch;
        }

        if (!descriptor.AllowedProjectIds.Contains(
                request.ProjectId,
                StringComparer.Ordinal))
        {
            return SigningProfileValidationError.ProjectNotAllowed;
        }

        if (!descriptor.AllowedSourceRepositories.Contains(
                request.SourceRepository,
                StringComparer.Ordinal))
        {
            return SigningProfileValidationError.SourceRepositoryNotAllowed;
        }

        if (!descriptor.AllowedSignerPolicyIds.Contains(
                request.SignerPolicyId,
                StringComparer.Ordinal))
        {
            return SigningProfileValidationError.SignerPolicyNotAllowed;
        }

        if (!descriptor.AllowedTimestampPolicyIds.Contains(
                request.TimestampPolicyId,
                StringComparer.Ordinal))
        {
            return SigningProfileValidationError.TimestampPolicyNotAllowed;
        }

        if (request.Artifacts.Count != descriptor.Artifacts.Count)
        {
            return SigningProfileValidationError.ArtifactInventoryMismatch;
        }

        Dictionary<string, RequestArtifactV1> requestByRole = new(StringComparer.Ordinal);
        foreach (RequestArtifactV1 requestArtifact in request.Artifacts)
        {
            if (!requestByRole.TryAdd(requestArtifact.Role, requestArtifact))
            {
                return SigningProfileValidationError.ArtifactInventoryMismatch;
            }
        }

        long declaredArtifactBytes = 0;
        foreach (SigningProfileArtifactDefinition definition in descriptor.Artifacts)
        {
            if (!requestByRole.TryGetValue(
                    definition.Role,
                    out RequestArtifactV1? requestArtifact)
                || !string.Equals(
                    requestArtifact.File,
                    definition.FileName,
                    StringComparison.Ordinal)
                || requestArtifact.Size <= 0
                || requestArtifact.Size > definition.MaximumBytes)
            {
                return SigningProfileValidationError.ArtifactInventoryMismatch;
            }

            try
            {
                declaredArtifactBytes = checked(
                    declaredArtifactBytes + requestArtifact.Size);
            }
            catch (OverflowException)
            {
                return SigningProfileValidationError.ArtifactSizeMismatch;
            }
        }

        if (declaredArtifactBytes > descriptor.MaximumRequestBytes)
        {
            return SigningProfileValidationError.ArtifactSizeMismatch;
        }

        return SigningProfileValidationError.None;
    }
}

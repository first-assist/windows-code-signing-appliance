using System.Collections.ObjectModel;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Profiles;

public sealed record SigningProfileFinalizedValidationContext
{
    public SigningProfileFinalizedValidationContext(
        ArtifactSigningRequestV1 request,
        IProfileArtifactReader finalizedArtifactReader,
        IEnumerable<VerifiedAuthenticodeArtifact> verifiedArtifacts,
        DateTimeOffset validationTime)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(finalizedArtifactReader);
        ArgumentNullException.ThrowIfNull(verifiedArtifacts);

        VerifiedAuthenticodeArtifact[] evidence = verifiedArtifacts.ToArray();
        if (evidence.Length is 0 || evidence.Any(item => item is null))
        {
            throw new ArgumentException(
                "Verified artifact evidence cannot be empty or contain null values.",
                nameof(verifiedArtifacts));
        }

        Request = request;
        FinalizedArtifactReader = finalizedArtifactReader;
        VerifiedArtifacts = Array.AsReadOnly(evidence);
        ValidationTime = validationTime.ToUniversalTime();
    }

    public ArtifactSigningRequestV1 Request { get; }

    public IProfileArtifactReader FinalizedArtifactReader { get; }

    public ReadOnlyCollection<VerifiedAuthenticodeArtifact> VerifiedArtifacts { get; }

    public DateTimeOffset ValidationTime { get; }
}

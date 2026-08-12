using System.Collections.ObjectModel;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Profiles;

public sealed record SigningProfileFinalizationContext
{
    public SigningProfileFinalizationContext(
        ArtifactSigningRequestV1 request,
        IProfileArtifactReader unsignedArtifactReader,
        IProfileArtifactReader signedArtifactReader,
        IEnumerable<VerifiedAuthenticodeArtifact> verifiedArtifacts,
        DateTimeOffset finalizedAt)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(unsignedArtifactReader);
        ArgumentNullException.ThrowIfNull(signedArtifactReader);
        ArgumentNullException.ThrowIfNull(verifiedArtifacts);

        VerifiedAuthenticodeArtifact[] evidence = verifiedArtifacts.ToArray();
        if (evidence.Length is 0 || evidence.Any(item => item is null))
        {
            throw new ArgumentException(
                "Verified artifact evidence cannot be empty or contain null values.",
                nameof(verifiedArtifacts));
        }

        DateTimeOffset universalFinalizedAt = finalizedAt.ToUniversalTime();
        if (!ProfileContractRules.IsWholeSecond(universalFinalizedAt))
        {
            throw new ArgumentException(
                "Finalization time must have whole-second precision.",
                nameof(finalizedAt));
        }

        Request = request;
        UnsignedArtifactReader = unsignedArtifactReader;
        SignedArtifactReader = signedArtifactReader;
        VerifiedArtifacts = Array.AsReadOnly(evidence);
        FinalizedAt = universalFinalizedAt;
    }

    public ArtifactSigningRequestV1 Request { get; }

    public IProfileArtifactReader UnsignedArtifactReader { get; }

    public IProfileArtifactReader SignedArtifactReader { get; }

    public ReadOnlyCollection<VerifiedAuthenticodeArtifact> VerifiedArtifacts { get; }

    public DateTimeOffset FinalizedAt { get; }
}

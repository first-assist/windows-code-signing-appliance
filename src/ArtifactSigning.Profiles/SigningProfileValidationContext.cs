using ArtifactSigning.Protocol;

namespace ArtifactSigning.Profiles;

public sealed record SigningProfileValidationContext
{
    public SigningProfileValidationContext(
        ArtifactSigningRequestV1 request,
        IProfileArtifactReader artifactReader,
        DateTimeOffset validationTime)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(artifactReader);

        Request = request;
        ArtifactReader = artifactReader;
        ValidationTime = validationTime.ToUniversalTime();
    }

    public ArtifactSigningRequestV1 Request { get; }

    public IProfileArtifactReader ArtifactReader { get; }

    public DateTimeOffset ValidationTime { get; }
}

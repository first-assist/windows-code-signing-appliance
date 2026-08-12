namespace ArtifactSigning.Profiles;

public enum SigningProfileArtifactKind
{
    JsonManifest,
    JsonBuildEvidence,
    PortableExecutable,
}

public sealed record SigningProfileArtifactDefinition
{
    public SigningProfileArtifactDefinition(
        string role,
        string fileName,
        SigningProfileArtifactKind kind,
        long maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);

        if (!ProfileContractRules.IsSafeIdentifier(role, maximumCharacters: 64))
        {
            throw new ArgumentException(
                "Artifact role must use the safe identifier grammar.",
                nameof(role));
        }

        if (!ProfileContractRules.IsLeafFileName(fileName, maximumCharacters: 128))
        {
            throw new ArgumentException(
                "Artifact filename must be one canonical leaf token.",
                nameof(fileName));
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Role = role;
        FileName = fileName;
        Kind = kind;
        MaximumBytes = maximumBytes;
    }

    public string Role { get; }

    public string FileName { get; }

    public SigningProfileArtifactKind Kind { get; }

    public long MaximumBytes { get; }
}

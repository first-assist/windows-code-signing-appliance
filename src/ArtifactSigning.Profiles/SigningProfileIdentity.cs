namespace ArtifactSigning.Profiles;

public sealed record SigningProfileIdentity
{
    public SigningProfileIdentity(string profileId, int profileVersion)
    {
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(profileVersion);

        if (!ProfileContractRules.IsSafeIdentifier(profileId, maximumCharacters: 64))
        {
            throw new ArgumentException(
                "Profile identifier must use the safe identifier grammar.",
                nameof(profileId));
        }

        ProfileId = profileId;
        ProfileVersion = profileVersion;
    }

    public string ProfileId { get; }

    public int ProfileVersion { get; }
}

using ArtifactSigning.Profiles;

namespace ArtifactSigning.Cli;

internal sealed class CliProfileRegistry
{
    private readonly SigningProfileRegistry _profiles;

    internal CliProfileRegistry(
        SigningProfilePackageSet profilePackages)
    {
        ArgumentNullException.ThrowIfNull(profilePackages);
        ProfilePackages = profilePackages;
        _profiles = SigningProfileRegistry.FromPackageSet(
            profilePackages);
    }

    internal SigningProfilePackageSet ProfilePackages { get; }

    internal ISigningProfile Resolve(
        string profileId,
        int profileVersion)
    {
        return _profiles.Resolve(profileId, profileVersion)
            ?? throw new InvalidDataException(
                "The requested client profile is not installed.");
    }

    internal ISigningProfile ResolveUnique(
        string profileId)
    {
        ArgumentNullException.ThrowIfNull(profileId);
        return ProfilePackages.Profiles.Where(item =>
                string.Equals(
                    item.Descriptor.Identity.ProfileId,
                    profileId,
                    StringComparison.Ordinal))
            .SingleOrDefault()
            ?? throw new InvalidDataException(
                "The requested client profile is not installed or is version-ambiguous.");
    }

    internal SigningProfilePackageDescriptor ResolvePackage(
        string profileId,
        int profileVersion)
    {
        return _profiles.ResolvePackage(profileId, profileVersion)
            ?? throw new InvalidDataException(
                "The requested client profile package is not installed.");
    }

    internal void RequireServerMatch(
        string projectId,
        string profileId,
        IReadOnlyList<CliVisibleProfile> visibleProfiles)
    {
        ArgumentNullException.ThrowIfNull(projectId);
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentNullException.ThrowIfNull(visibleProfiles);

        ISigningProfile profile = ResolveUnique(profileId);
        SigningProfileIdentity identity = profile.Descriptor.Identity;
        SigningProfilePackageDescriptor package = ResolvePackage(
            identity.ProfileId,
            identity.ProfileVersion);
        CliVisibleProfile? visible = visibleProfiles.SingleOrDefault(item =>
            string.Equals(item.ProjectId, projectId, StringComparison.Ordinal)
            && string.Equals(item.ProfileId, identity.ProfileId, StringComparison.Ordinal)
            && item.ProfileVersion == identity.ProfileVersion);
        if (visible is null
            || !string.Equals(
                visible.ProfileSetSha256,
                ProfilePackages.PackageSetSha256,
                StringComparison.Ordinal)
            || !string.Equals(visible.PackageId, package.PackageId, StringComparison.Ordinal)
            || !string.Equals(
                visible.PackageVersion,
                package.PackageVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                visible.PackageSha256,
                package.PackageSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                visible.AssemblySha256,
                package.AssemblySha256,
                StringComparison.Ordinal)
            || !string.Equals(
                visible.DescriptorSha256,
                package.DescriptorSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The signing service profile package does not match the installed client profile set.");
        }
    }
}

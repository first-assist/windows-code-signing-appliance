using System.Collections.ObjectModel;

namespace ArtifactSigning.Profiles;

public sealed class SigningProfileRegistry
{
    private readonly ReadOnlyDictionary<(string ProfileId, int ProfileVersion), ISigningProfile>
        _profiles;
    private readonly ReadOnlyDictionary<
        (string ProfileId, int ProfileVersion),
        SigningProfilePackageDescriptor> _packages;

    public SigningProfileRegistry(IEnumerable<ISigningProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);

        Dictionary<(string ProfileId, int ProfileVersion), ISigningProfile> registered = [];
        foreach (ISigningProfile profile in profiles)
        {
            if (profile is null)
            {
                throw new ArgumentException(
                    "Profile registry cannot contain null values.",
                    nameof(profiles));
            }

            SigningProfileIdentity identity = profile.Descriptor.Identity;
            if (!registered.TryAdd((identity.ProfileId, identity.ProfileVersion), profile))
            {
                throw new ArgumentException(
                    "Profile registry contains a duplicate identity.",
                    nameof(profiles));
            }
        }

        if (registered.Count is 0)
        {
            throw new ArgumentException(
                "Profile registry must contain at least one compiled profile.",
                nameof(profiles));
        }

        _profiles = new ReadOnlyDictionary<
            (string ProfileId, int ProfileVersion),
            ISigningProfile>(registered);
        _packages = new ReadOnlyDictionary<
            (string ProfileId, int ProfileVersion),
            SigningProfilePackageDescriptor>(
                new Dictionary<
                    (string ProfileId, int ProfileVersion),
                    SigningProfilePackageDescriptor>());
        PackageSetSha256 = null;
    }

    public int Count => _profiles.Count;

    public string? PackageSetSha256 { get; }

    public static SigningProfileRegistry FromPackageSet(SigningProfilePackageSet packageSet)
    {
        ArgumentNullException.ThrowIfNull(packageSet);
        return new SigningProfileRegistry(packageSet);
    }

    public ISigningProfile? Resolve(string profileId, int profileVersion)
    {
        ArgumentNullException.ThrowIfNull(profileId);
        return _profiles.GetValueOrDefault((profileId, profileVersion));
    }

    public SigningProfilePackageDescriptor? ResolvePackage(
        string profileId,
        int profileVersion)
    {
        ArgumentNullException.ThrowIfNull(profileId);
        return _packages.GetValueOrDefault((profileId, profileVersion));
    }

    private SigningProfileRegistry(SigningProfilePackageSet packageSet)
    {
        Dictionary<(string ProfileId, int ProfileVersion), ISigningProfile> registered = [];
        Dictionary<
            (string ProfileId, int ProfileVersion),
            SigningProfilePackageDescriptor> packages = [];
        foreach (ISigningProfile profile in packageSet.Profiles)
        {
            SigningProfileIdentity identity = profile.Descriptor.Identity;
            (string ProfileId, int ProfileVersion) key =
                (identity.ProfileId, identity.ProfileVersion);
            SigningProfilePackageDescriptor package = packageSet.ResolvePackage(
                identity.ProfileId,
                identity.ProfileVersion)
                ?? throw new ArgumentException(
                    "Profile package set is missing a profile registration.",
                    nameof(packageSet));
            if (!registered.TryAdd(key, profile) || !packages.TryAdd(key, package))
            {
                throw new ArgumentException(
                    "Profile package set contains a duplicate profile registration.",
                    nameof(packageSet));
            }
        }

        _profiles = new ReadOnlyDictionary<
            (string ProfileId, int ProfileVersion),
            ISigningProfile>(registered);
        _packages = new ReadOnlyDictionary<
            (string ProfileId, int ProfileVersion),
            SigningProfilePackageDescriptor>(packages);
        PackageSetSha256 = packageSet.PackageSetSha256;
    }
}

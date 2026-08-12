using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Profiles;

/// <summary>
/// Validates the complete static profile set linked into one appliance release. This type accepts
/// package instances supplied by application code only; it never probes the filesystem or loads
/// assemblies.
/// </summary>
public sealed class SigningProfilePackageSet
{
    private const string PackageSetFormat = "ArtifactSigningProfilePackageSetV1";
    private readonly ReadOnlyDictionary<
        (string ProfileId, int ProfileVersion),
        SigningProfilePackageDescriptor> _packagesByProfile;

    public SigningProfilePackageSet(IEnumerable<ISigningProfilePackage> packages)
    {
        ArgumentNullException.ThrowIfNull(packages);

        ISigningProfilePackage[] packageArray = packages.ToArray();
        if (packageArray.Length is 0 or > 64 || packageArray.Any(package => package is null))
        {
            throw new ArgumentException(
                "Profile package set must contain from one through sixty-four packages.",
                nameof(packages));
        }

        Dictionary<string, ISigningProfilePackage> packagesById =
            new(StringComparer.Ordinal);
        Dictionary<(string ProfileId, int ProfileVersion), ISigningProfile> profiles = [];
        Dictionary<
            (string ProfileId, int ProfileVersion),
            SigningProfilePackageDescriptor> packageDescriptors = [];
        foreach (ISigningProfilePackage package in packageArray)
        {
            SigningProfilePackageDescriptor descriptor = package.Descriptor
                ?? throw new ArgumentException(
                    "Profile package descriptor cannot be null.",
                    nameof(packages));
            ReadOnlyCollection<ISigningProfile> packageProfiles = package.Profiles
                ?? throw new ArgumentException(
                    "Profile package profiles cannot be null.",
                    nameof(packages));

            if (!packagesById.TryAdd(descriptor.PackageId, package))
            {
                throw new ArgumentException(
                    "Profile package set contains a duplicate package identifier.",
                    nameof(packages));
            }

            ISigningProfile[] profilesForPackage = packageProfiles.ToArray();
            if (profilesForPackage.Length != descriptor.ProfileIdentities.Count
                || profilesForPackage.Any(profile => profile is null))
            {
                throw new ArgumentException(
                    "Profile package implementation does not match its registration metadata.",
                    nameof(packages));
            }

            HashSet<(string ProfileId, int ProfileVersion)> expected = descriptor.ProfileIdentities
                .Select(identity => (identity.ProfileId, identity.ProfileVersion))
                .ToHashSet();
            foreach (ISigningProfile profile in profilesForPackage)
            {
                SigningProfileIdentity identity = profile.Descriptor?.Identity
                    ?? throw new ArgumentException(
                        "Profile package profile descriptor cannot be null.",
                        nameof(packages));
                (string ProfileId, int ProfileVersion) key =
                    (identity.ProfileId, identity.ProfileVersion);
                if (!expected.Remove(key)
                    || !profiles.TryAdd(key, profile)
                    || !packageDescriptors.TryAdd(key, descriptor))
                {
                    throw new ArgumentException(
                        "Profile package set contains a duplicate or unregistered profile identity.",
                        nameof(packages));
                }
            }

            if (expected.Count != 0)
            {
                throw new ArgumentException(
                    "Profile package registration metadata has no matching profile implementation.",
                    nameof(packages));
            }
        }

        ISigningProfilePackage[] orderedPackages = packageArray
            .OrderBy(package => package.Descriptor.PackageId, StringComparer.Ordinal)
            .ToArray();
        Packages = Array.AsReadOnly(orderedPackages);
        Profiles = Array.AsReadOnly(profiles.Values.ToArray());
        _packagesByProfile = new ReadOnlyDictionary<
            (string ProfileId, int ProfileVersion),
            SigningProfilePackageDescriptor>(packageDescriptors);
        PackageSetSha256 = ComputePackageSetSha256(orderedPackages);
    }

    public ReadOnlyCollection<ISigningProfilePackage> Packages { get; }

    public ReadOnlyCollection<ISigningProfile> Profiles { get; }

    public string PackageSetSha256 { get; }

    public SigningProfilePackageDescriptor? ResolvePackage(
        string profileId,
        int profileVersion)
    {
        ArgumentNullException.ThrowIfNull(profileId);
        return _packagesByProfile.GetValueOrDefault((profileId, profileVersion));
    }

    private static string ComputePackageSetSha256(
        IEnumerable<ISigningProfilePackage> packages)
    {
        StringBuilder canonical = new();
        canonical.Append(PackageSetFormat).Append('\n');
        canonical.Append("AbiVersion=")
            .Append(SigningProfilePackageAbi.CurrentVersion)
            .Append('\n');
        foreach (ISigningProfilePackage package in packages)
        {
            SigningProfilePackageDescriptor descriptor = package.Descriptor;
            canonical.Append("PackageId=").Append(descriptor.PackageId).Append('\n');
            canonical.Append("PackageVersion=").Append(descriptor.PackageVersion).Append('\n');
            canonical.Append("PackageSha256=").Append(descriptor.PackageSha256).Append('\n');
            canonical.Append("AssemblySha256=").Append(descriptor.AssemblySha256).Append('\n');
            canonical.Append("DescriptorSha256=").Append(descriptor.DescriptorSha256).Append('\n');
        }

        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.ASCII.GetBytes(canonical.ToString())));
    }
}

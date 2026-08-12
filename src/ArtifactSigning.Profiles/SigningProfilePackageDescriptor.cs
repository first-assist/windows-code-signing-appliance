using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Profiles;

/// <summary>
/// Immutable, build-time registration metadata for one linked signing-profile package.
/// Assembly and package digests are release evidence: the installer verifies the sealed release
/// inventory; this type verifies that the static registration metadata is internally consistent.
/// </summary>
public sealed class SigningProfilePackageDescriptor
{
    private const string DescriptorFormat = "ArtifactSigningProfilePackageDescriptorV1";
    private const string PackageFormat = "ArtifactSigningProfilePackageReleaseV1";

    public SigningProfilePackageDescriptor(
        int abiVersion,
        string packageId,
        string packageVersion,
        string packageSha256,
        string assemblySha256,
        string descriptorSha256,
        IEnumerable<SigningProfileIdentity> profileIdentities)
    {
        ArgumentNullException.ThrowIfNull(packageId);
        ArgumentNullException.ThrowIfNull(packageVersion);
        ArgumentNullException.ThrowIfNull(packageSha256);
        ArgumentNullException.ThrowIfNull(assemblySha256);
        ArgumentNullException.ThrowIfNull(descriptorSha256);
        ArgumentNullException.ThrowIfNull(profileIdentities);

        if (abiVersion != SigningProfilePackageAbi.CurrentVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(abiVersion),
                "Profile package ABI is not supported by this appliance release.");
        }

        if (!ProfileContractRules.IsSafeIdentifier(packageId, maximumCharacters: 64))
        {
            throw new ArgumentException(
                "Package identifier must use the safe identifier grammar.",
                nameof(packageId));
        }

        if (!ProfileContractRules.IsCanonicalSemanticVersion(packageVersion))
        {
            throw new ArgumentException(
                "Package version must be canonical Semantic Versioning.",
                nameof(packageVersion));
        }

        if (!ProfileContractRules.IsLowerSha256(packageSha256)
            || !ProfileContractRules.IsLowerSha256(assemblySha256)
            || !ProfileContractRules.IsLowerSha256(descriptorSha256))
        {
            throw new ArgumentException(
                "Package registration digests must be canonical lowercase SHA-256 values.");
        }

        SigningProfileIdentity[] identities = CopyAndOrderProfileIdentities(profileIdentities);
        string expectedDescriptorSha256 = ComputeDescriptorSha256(
            abiVersion,
            packageId,
            packageVersion,
            assemblySha256,
            identities);
        string expectedPackageSha256 = ComputePackageSha256(
            expectedDescriptorSha256,
            assemblySha256);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(descriptorSha256),
                Encoding.ASCII.GetBytes(expectedDescriptorSha256))
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(packageSha256),
                Encoding.ASCII.GetBytes(expectedPackageSha256)))
        {
            throw new ArgumentException(
                "Profile package registration digest is inconsistent with its static metadata.");
        }

        AbiVersion = abiVersion;
        PackageId = packageId;
        PackageVersion = packageVersion;
        PackageSha256 = packageSha256;
        AssemblySha256 = assemblySha256;
        DescriptorSha256 = descriptorSha256;
        ProfileIdentities = Array.AsReadOnly(identities);
    }

    public int AbiVersion { get; }

    public string PackageId { get; }

    public string PackageVersion { get; }

    public string PackageSha256 { get; }

    public string AssemblySha256 { get; }

    public string DescriptorSha256 { get; }

    public ReadOnlyCollection<SigningProfileIdentity> ProfileIdentities { get; }

    public static bool IsCanonicalPackageVersion(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ProfileContractRules.IsCanonicalSemanticVersion(value);
    }

    public static string ComputeDescriptorSha256(
        int abiVersion,
        string packageId,
        string packageVersion,
        string assemblySha256,
        IEnumerable<SigningProfileIdentity> profileIdentities)
    {
        ArgumentNullException.ThrowIfNull(packageId);
        ArgumentNullException.ThrowIfNull(packageVersion);
        ArgumentNullException.ThrowIfNull(assemblySha256);
        ArgumentNullException.ThrowIfNull(profileIdentities);

        SigningProfileIdentity[] identities = CopyAndOrderProfileIdentities(profileIdentities);
        StringBuilder canonical = new();
        canonical.Append(DescriptorFormat).Append('\n');
        canonical.Append("AbiVersion=").Append(abiVersion).Append('\n');
        canonical.Append("PackageId=").Append(packageId).Append('\n');
        canonical.Append("PackageVersion=").Append(packageVersion).Append('\n');
        canonical.Append("AssemblySha256=").Append(assemblySha256).Append('\n');
        foreach (SigningProfileIdentity identity in identities)
        {
            canonical.Append("Profile=")
                .Append(identity.ProfileId)
                .Append('@')
                .Append(identity.ProfileVersion)
                .Append('\n');
        }

        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.ASCII.GetBytes(canonical.ToString())));
    }

    public static string ComputePackageSha256(
        string descriptorSha256,
        string assemblySha256)
    {
        ArgumentNullException.ThrowIfNull(descriptorSha256);
        ArgumentNullException.ThrowIfNull(assemblySha256);

        if (!ProfileContractRules.IsLowerSha256(descriptorSha256)
            || !ProfileContractRules.IsLowerSha256(assemblySha256))
        {
            throw new ArgumentException(
                "Package release inputs must be canonical lowercase SHA-256 values.");
        }

        string canonical = string.Concat(
            PackageFormat,
            "\nDescriptorSha256=",
            descriptorSha256,
            "\nAssemblySha256=",
            assemblySha256,
            "\n");
        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.ASCII.GetBytes(canonical)));
    }

    private static SigningProfileIdentity[] CopyAndOrderProfileIdentities(
        IEnumerable<SigningProfileIdentity> profileIdentities)
    {
        SigningProfileIdentity[] identities = profileIdentities.ToArray();
        if (identities.Length is 0 or > 64 || identities.Any(identity => identity is null))
        {
            throw new ArgumentException(
                "Profile package must define from one through sixty-four profile identities.",
                nameof(profileIdentities));
        }

        Array.Sort(
            identities,
            static (left, right) =>
            {
                int idComparison = string.Compare(
                    left.ProfileId,
                    right.ProfileId,
                    StringComparison.Ordinal);
                return idComparison != 0
                    ? idComparison
                    : left.ProfileVersion.CompareTo(right.ProfileVersion);
            });

        for (int index = 1; index < identities.Length; index++)
        {
            SigningProfileIdentity previous = identities[index - 1];
            SigningProfileIdentity current = identities[index];
            if (string.Equals(
                    previous.ProfileId,
                    current.ProfileId,
                    StringComparison.Ordinal)
                && previous.ProfileVersion == current.ProfileVersion)
            {
                throw new ArgumentException(
                    "Profile package contains a duplicate profile identity.",
                    nameof(profileIdentities));
            }
        }

        return identities;
    }
}

using ArtifactSigning.Profiles;

namespace ArtifactSigning.Composition;

// The release composer generates the other half of this type from operator-reviewed,
// hash-pinned profile packages. A normal source build intentionally has no installed profiles;
// attempting to start a distributable without composition therefore fails closed.
internal static partial class InstalledProfileSet
{
    internal static SigningProfilePackageSet Create()
    {
        List<ISigningProfilePackage> packages = [];
        AddPackages(packages);
        return new SigningProfilePackageSet(packages);
    }

    static partial void AddPackages(List<ISigningProfilePackage> packages);
}

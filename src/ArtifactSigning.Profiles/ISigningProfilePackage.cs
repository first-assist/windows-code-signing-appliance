using System.Collections.ObjectModel;

namespace ArtifactSigning.Profiles;

/// <summary>
/// Represents one operator-approved signing-profile package linked into an appliance release.
/// Implementations must return a fixed collection; packages are never discovered, loaded, or
/// modified at runtime.
/// </summary>
public interface ISigningProfilePackage
{
    SigningProfilePackageDescriptor Descriptor { get; }

    ReadOnlyCollection<ISigningProfile> Profiles { get; }
}

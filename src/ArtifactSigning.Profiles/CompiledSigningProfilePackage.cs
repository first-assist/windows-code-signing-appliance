using System.Collections.ObjectModel;

namespace ArtifactSigning.Profiles;

/// <summary>
/// A sealed-release registration for profiles instantiated from a separately built assembly.
/// The release-composition project creates this object from operator-verified assembly/package
/// digests and externally instantiated profile types. Profile assemblies do not self-declare
/// their own file digest.
/// </summary>
public sealed class CompiledSigningProfilePackage : ISigningProfilePackage
{
    public CompiledSigningProfilePackage(
        SigningProfilePackageDescriptor descriptor,
        IEnumerable<ISigningProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(profiles);

        ISigningProfile[] profileArray = profiles.ToArray();
        if (profileArray.Length is 0 or > 64 || profileArray.Any(profile => profile is null))
        {
            throw new ArgumentException(
                "Compiled profile package must contain from one through sixty-four profiles.",
                nameof(profiles));
        }

        Descriptor = descriptor;
        Profiles = Array.AsReadOnly(profileArray);
    }

    public SigningProfilePackageDescriptor Descriptor { get; }

    public ReadOnlyCollection<ISigningProfile> Profiles { get; }
}

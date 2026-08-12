using ArtifactSigning.Profiles;

namespace ArtifactSigning.TestProfile;

public static class ExampleProfilePackage
{
    public const string PackageId = "Example.Endpoint.Profile";
    public const string PackageVersion = "1.0.0";
    public const string AssemblySha256 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    public static SigningProfilePackageSet CreatePackageSet()
    {
        SigningProfileIdentity[] identities =
        [
            ExampleEndpointBundleV1.Identity,
        ];
        string descriptorSha256 =
            SigningProfilePackageDescriptor.ComputeDescriptorSha256(
                SigningProfilePackageAbi.CurrentVersion,
                PackageId,
                PackageVersion,
                AssemblySha256,
                identities);
        string packageSha256 =
            SigningProfilePackageDescriptor.ComputePackageSha256(
                descriptorSha256,
                AssemblySha256);
        SigningProfilePackageDescriptor descriptor = new(
            SigningProfilePackageAbi.CurrentVersion,
            PackageId,
            PackageVersion,
            packageSha256,
            AssemblySha256,
            descriptorSha256,
            identities);
        return new SigningProfilePackageSet(
            [
                new CompiledSigningProfilePackage(
                    descriptor,
                    [ExampleEndpointBundleV1.Instance]),
            ]);
    }
}

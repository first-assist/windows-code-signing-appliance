using Xunit;

namespace ArtifactSigning.TestProfile.Tests;

public sealed class ExampleEndpointBundleV1Tests
{
    [Fact]
    public void IdentityMatchesVersionedContract()
    {
        Assert.Equal("ExampleEndpointBundleV1", ExampleEndpointBundleV1.ProfileId);
        Assert.Equal(2, ExampleEndpointBundleV1.ProfileVersion);
        Assert.Equal(ExampleEndpointBundleV1.ProfileId, ExampleEndpointBundleV1.Identity.ProfileId);
        Assert.Equal(ExampleEndpointBundleV1.ProfileVersion, ExampleEndpointBundleV1.Identity.ProfileVersion);
    }

    [Fact]
    public void DescriptorIsClosedToExactExampleInventoryAndPolicies()
    {
        ArtifactSigning.Profiles.SigningProfileDescriptor descriptor =
            ExampleEndpointBundleV1.Instance.Descriptor;

        Assert.Equal([ExampleEndpointBundleV1.ProjectId], descriptor.AllowedProjectIds);
        Assert.Equal(
            [ExampleEndpointBundleV1.SourceRepository],
            descriptor.AllowedSourceRepositories);
        Assert.Equal([ExampleEndpointBundleV1.SignerPolicyId], descriptor.AllowedSignerPolicyIds);
        Assert.Equal(
            [ExampleEndpointBundleV1.TimestampPolicyId],
            descriptor.AllowedTimestampPolicyIds);
        Assert.Equal(
            [
                (ExampleEndpointBundleV1.ManifestRole, ExampleEndpointBundleV1.ManifestFileName),
                (
                    ExampleEndpointBundleV1.BuildEvidenceRole,
                    ExampleEndpointBundleV1.BuildEvidenceFileName
                ),
                (ExampleEndpointBundleV1.AgentRole, ExampleEndpointBundleV1.AgentFileName),
                (ExampleEndpointBundleV1.MediaRole, ExampleEndpointBundleV1.MediaFileName),
                (
                    ExampleEndpointBundleV1.DesktopWorkerRole,
                    ExampleEndpointBundleV1.DesktopWorkerFileName
                ),
            ],
            descriptor.Artifacts.Select(artifact => (artifact.Role, artifact.FileName)));
    }
}

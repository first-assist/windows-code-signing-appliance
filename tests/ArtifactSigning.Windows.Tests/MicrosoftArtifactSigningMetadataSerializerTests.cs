using System.Text;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class MicrosoftArtifactSigningMetadataSerializerTests
{
    [Fact]
    public void SerializesOnlyCanonicalManagedIdentityMetadata()
    {
        MicrosoftArtifactSigningPolicy policy = CreatePolicy();
        Guid requestId = Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc");

        byte[] actual = MicrosoftArtifactSigningMetadataSerializer.Serialize(
            policy,
            requestId,
            "DesktopWorker");

        Assert.Equal(
            "{\"Endpoint\":\"https://jpe.codesigning.azure.net/\",\"CodeSigningAccountName\":\"example-signing-account\",\"CertificateProfileName\":\"Example-PublicTrust\",\"CorrelationId\":\"018f84a7-2f4c-7d8e-a123-123456789abc:DesktopWorker\",\"ExcludeCredentials\":[\"EnvironmentCredential\",\"WorkloadIdentityCredential\",\"SharedTokenCacheCredential\",\"VisualStudioCredential\",\"VisualStudioCodeCredential\",\"AzureCliCredential\",\"AzurePowerShellCredential\",\"AzureDeveloperCliCredential\",\"InteractiveBrowserCredential\"]}",
            Encoding.UTF8.GetString(actual));
        Assert.InRange(
            actual.Length,
            1,
            MicrosoftArtifactSigningMetadataSerializer.MaximumMetadataBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Agent-1")]
    [InlineData("Agent/1")]
    [InlineData("Agent\"1")]
    [InlineData(" Agent")]
    public void RejectsUnsafeArtifactRole(string role)
    {
        Assert.Throws<ArgumentException>(
            () => MicrosoftArtifactSigningMetadataSerializer.CreateCorrelationId(
                Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                role));
    }

    [Fact]
    public void RejectsEmptyRequestId()
    {
        Assert.Throws<ArgumentException>(
            () => MicrosoftArtifactSigningMetadataSerializer.CreateCorrelationId(
                Guid.Empty,
                "Agent"));
    }

    private static MicrosoftArtifactSigningPolicy CreatePolicy()
    {
        return new MicrosoftArtifactSigningPolicy(
            MicrosoftArtifactSigningRegion.JapanEast,
            "example-signing-account",
            "Example-PublicTrust",
            MicrosoftArtifactSigningPolicyTests.GetSignToolPath(),
            new string('0', 64),
            new Version(10, 0, 26100, 4188),
            MicrosoftArtifactSigningPolicyTests.GetDlibPath(),
            new string('1', 64),
            new Version(1, 2, 3, 4),
            new string('2', 64),
            TimeSpan.FromSeconds(120));
    }
}

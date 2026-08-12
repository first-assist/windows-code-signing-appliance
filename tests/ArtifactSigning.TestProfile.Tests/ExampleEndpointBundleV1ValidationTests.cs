using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.TestProfile.Tests;

public sealed class ExampleEndpointBundleV1ValidationTests
{
    private static readonly DateTimeOffset ValidationTime =
        new(2026, 7, 28, 10, 1, 0, TimeSpan.Zero);

    [Fact]
    public void ValidateAcceptsExactHardenedUnsignedBundle()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create();

        SigningProfileValidationResult result = Validate(bundle);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningProfileValidationError.None, result.Error);
    }

    [Theory]
    [InlineData("Authenticode", "already-finalized")]
    [InlineData("Unexpected", "value")]
    public void ValidateRejectsUnknownManifestProperty(string property, string value)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest => manifest[property] = value);

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsDuplicateManifestProperty()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        byte[] manifest = ReadManifest(valid);
        string json = Encoding.UTF8.GetString(manifest).Replace(
            "\"Channel\": \"acceptance\",",
            "\"Channel\": \"acceptance\", \"Channel\": \"other\",",
            StringComparison.Ordinal);

        AssertError(
            valid.WithManifestBytes(Encoding.UTF8.GetBytes(json)),
            SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsInvalidManifestUtf8()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithManifestBytes([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsNonCanonicalIntegerToken()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        string json = Encoding.UTF8.GetString(ReadManifest(valid)).Replace(
            "\"ProtocolVersion\": 1",
            "\"ProtocolVersion\": 1.0",
            StringComparison.Ordinal);

        AssertError(
            valid.WithManifestBytes(Encoding.UTF8.GetBytes(json)),
            SigningProfileValidationError.ManifestInvalid);
    }

    [Theory]
    [InlineData("Hardened", false)]
    [InlineData("EnrollmentMode", "DeploymentKey")]
    [InlineData("Target", "aarch64-pc-windows-msvc")]
    [InlineData("ProtocolVersion", 2)]
    [InlineData("ManifestSequence", 0)]
    [InlineData("Artifact", "other.exe")]
    public void ValidateRejectsInvalidReleaseInvariant(string property, object value)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest => manifest[property] = JsonSerializer.SerializeToNode(value));

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Theory]
    [InlineData("05.12.12")]
    [InlineData("5.12")]
    [InlineData("5.12.12-01")]
    [InlineData("5.12.12+")]
    public void ValidateRejectsNonCanonicalReleaseVersion(string version)
    {
        ExampleBundleTestData original = ExampleBundleTestData.Create();
        ExampleBundleTestData bundle = original.WithRequest(
            original.Request with { ReleaseVersion = version });

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsExpiredManifest()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest => manifest["ExpiresAt"] = "2026-07-28T10:00:59Z");

        AssertError(bundle, SigningProfileValidationError.ManifestExpired);
    }

    [Fact]
    public void ValidateRejectsManifestThatExpiresBeforeRequest()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest => manifest["ExpiresAt"] = "2026-07-28T10:14:59Z");

        AssertError(bundle, SigningProfileValidationError.ManifestExpired);
    }

    [Fact]
    public void ValidateRejectsManifestArtifactDigestNotBoundByRequest()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest =>
            {
                JsonArray artifacts = manifest["Artifacts"]!.AsArray();
                artifacts[1]!.AsObject()["Sha256"] = new string('0', 64);
            });

        AssertError(bundle, SigningProfileValidationError.ArtifactInventoryMismatch);
    }

    [Fact]
    public void ValidateRejectsLegacyTopLevelAgentHashMismatch()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest => manifest["Sha256"] = new string('0', 64));

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsNonCanonicalSignerThumbprint()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            manifest =>
                manifest["ExpectedAuthenticodeSignerThumbprint"] =
                    new string('a', 40));

        AssertError(bundle, SigningProfileValidationError.ManifestInvalid);
    }

    [Fact]
    public void ValidateRejectsAlteredArtifactBytes()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithUnboundArtifactMutation(ExampleEndpointBundleV1.MediaFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactSizeMismatch);
    }

    [Fact]
    public void ValidateRejectsSameSizeArtifactHashSubstitution()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithUnboundSameSizeArtifactMutation(ExampleEndpointBundleV1.MediaFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactHashMismatch);
    }

    [Fact]
    public void ValidateRejectsUnavailableArtifact()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithoutArtifact(ExampleEndpointBundleV1.DesktopWorkerFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactUnavailable);
    }

    [Fact]
    public void ValidateRejectsPreSignedOrPartiallySignedPortableExecutable()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(agentHasSignature: true);

        AssertError(bundle, SigningProfileValidationError.ArtifactAlreadySigned);
    }

    [Fact]
    public void ValidateRejectsWrongPortableExecutableMachine()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(agentMachine: 0x014c);

        AssertError(bundle, SigningProfileValidationError.ArtifactFormatInvalid);
    }

    [Theory]
    [InlineData("5.12.11", "example-endpoint-service.exe")]
    [InlineData("5.12.12", "other.exe")]
    public void ValidateRejectsWrongPortableExecutableIdentity(
        string peVersion,
        string originalFileName)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            agentPeVersion: peVersion,
            agentOriginalFileName: originalFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactVersionMismatch);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void ValidateRequiresExactlyOneEmbeddedSignerPin(int occurrences)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            signerOccurrences: occurrences);

        AssertError(bundle, SigningProfileValidationError.SignerBindingInvalid);
    }

    [Fact]
    public void ValidateRejectsRequestWithWrongArtifactRoleFilenamePair()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create();
        ArtifactSigningRequestV1 request = bundle.Request with
        {
            Artifacts = bundle.Request.Artifacts.Select(
                artifact => string.Equals(
                    artifact.Role,
                    ExampleEndpointBundleV1.MediaRole,
                    StringComparison.Ordinal)
                    ? artifact with { File = "media.exe" }
                    : artifact).ToArray(),
        };

        SigningProfileValidationResult result =
            ExampleEndpointBundleV1.Instance.ValidateUnsignedBundle(
                new SigningProfileValidationContext(request, bundle, ValidationTime));

        Assert.Equal(SigningProfileValidationError.ArtifactInventoryMismatch, result.Error);
    }

    private static SigningProfileValidationResult Validate(ExampleBundleTestData bundle)
    {
        return ExampleEndpointBundleV1.Instance.ValidateUnsignedBundle(
            new SigningProfileValidationContext(
                bundle.Request,
                bundle,
                ValidationTime));
    }

    private static void AssertError(
        ExampleBundleTestData bundle,
        SigningProfileValidationError expected)
    {
        SigningProfileValidationResult result = Validate(bundle);

        Assert.False(result.IsSuccess);
        Assert.Equal(expected, result.Error);
    }

    private static byte[] ReadManifest(ExampleBundleTestData bundle)
    {
        using Stream stream = bundle.OpenRead(ExampleEndpointBundleV1.ManifestFileName);
        using MemoryStream content = new();
        stream.CopyTo(content);
        return content.ToArray();
    }
}

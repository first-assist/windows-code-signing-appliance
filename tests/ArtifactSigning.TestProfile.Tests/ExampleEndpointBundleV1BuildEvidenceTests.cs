using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.TestProfile.Tests;

public sealed class ExampleEndpointBundleV1BuildEvidenceTests
{
    private static readonly DateTimeOffset ValidationTime =
        new(2026, 7, 28, 10, 1, 0, TimeSpan.Zero);

    [Fact]
    public void ValidateAcceptsExactHashBoundHardenedBuildEvidence()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create();

        SigningProfileValidationResult result = Validate(bundle);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningProfileValidationError.None, result.Error);
    }

    [Fact]
    public void ValidateAcceptsSha256SourceCommitAndNoRelayGrantKey()
    {
        string sourceCommit = new('a', 64);
        ExampleBundleTestData evidenceBound = ExampleBundleTestData.Create()
            .WithBuildEvidence(
                evidence =>
                {
                    evidence["SourceCommit"] = sourceCommit;
                    evidence["RelayGrantPublicKeyPresent"] = false;
                });
        ExampleBundleTestData bundle = evidenceBound.WithRequest(
            evidenceBound.Request with { SourceCommit = sourceCommit });

        SigningProfileValidationResult result = Validate(bundle);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningProfileValidationError.None, result.Error);
    }

    [Fact]
    public void ValidateRequiresBuildEvidenceInRequestInventory()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create();
        ArtifactSigningRequestV1 request = bundle.Request with
        {
            Artifacts = bundle.Request.Artifacts.Where(
                artifact => !string.Equals(
                    artifact.Role,
                    ExampleEndpointBundleV1.BuildEvidenceRole,
                    StringComparison.Ordinal)).ToArray(),
        };

        SigningProfileValidationResult result =
            ExampleEndpointBundleV1.Instance.ValidateUnsignedBundle(
                new SigningProfileValidationContext(request, bundle, ValidationTime));

        Assert.Equal(
            SigningProfileValidationError.ArtifactInventoryMismatch,
            result.Error);
    }

    [Fact]
    public void ValidateRejectsUnavailableBuildEvidence()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithoutArtifact(ExampleEndpointBundleV1.BuildEvidenceFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactUnavailable);
    }

    [Fact]
    public void ValidateRejectsOversizedBuildEvidence()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithBuildEvidenceBytes(
                new byte[ExampleEndpointBundleV1.MaximumBuildEvidenceBytes + 1]);

        AssertError(
            bundle,
            SigningProfileValidationError.ArtifactInventoryMismatch);
    }

    [Theory]
    [InlineData("RootCaPem")]
    [InlineData("EnrollUrl")]
    [InlineData("MtlsUrl")]
    [InlineData("DeploymentEnrollmentKey")]
    [InlineData("UpdateManifestKeys")]
    [InlineData("CommandAuthorityKeys")]
    public void ValidateRejectsRawProvisioningMaterialProperty(string property)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence => evidence[property] = "not-admissible");

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsDuplicateBuildEvidenceProperty()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        string json = Encoding.UTF8.GetString(ReadEvidence(valid)).Replace(
            "\"SourceTreeState\": \"Clean\",",
            "\"SourceTreeState\": \"Clean\", \"SourceTreeState\": \"Dirty\",",
            StringComparison.Ordinal);

        AssertError(
            valid.WithBuildEvidenceBytes(Encoding.UTF8.GetBytes(json)),
            SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsMissingBuildEvidenceProperty()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
                Assert.True(evidence.Remove("BuildRecipeSha256")));

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsEscapedBuildEvidencePropertyName()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        string json = Encoding.UTF8.GetString(ReadEvidence(valid)).Replace(
            "\"SourceCommit\":",
            "\"\\u0053ourceCommit\":",
            StringComparison.Ordinal);

        AssertError(
            valid.WithBuildEvidenceBytes(Encoding.UTF8.GetBytes(json)),
            SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsWrongBuildEvidencePropertyType()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence => evidence["RootSpkiPinCount"] = "1");

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsInvalidBuildEvidenceUtf8()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithBuildEvidenceBytes([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsBuildEvidenceUtf8Bom()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        byte[] evidence = ReadEvidence(valid);
        byte[] withBom = [0xef, 0xbb, 0xbf, .. evidence];

        AssertError(
            valid.WithBuildEvidenceBytes(withBom),
            SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsNonCanonicalBuildEvidenceInteger()
    {
        ExampleBundleTestData valid = ExampleBundleTestData.Create();
        string json = Encoding.UTF8.GetString(ReadEvidence(valid)).Replace(
            "\"RootSpkiPinCount\": 1",
            "\"RootSpkiPinCount\": 1.0",
            StringComparison.Ordinal);

        AssertError(
            valid.WithBuildEvidenceBytes(Encoding.UTF8.GetBytes(json)),
            SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Theory]
    [InlineData("Format", "OtherBuildEvidence")]
    [InlineData("SourceTreeState", "Dirty")]
    [InlineData("BuildRecipe", "scripts/other.sh")]
    [InlineData("DependencyLock", "other.lock")]
    [InlineData("ToolchainFile", "other.toml")]
    [InlineData("Target", "aarch64-pc-windows-msvc")]
    [InlineData("BuildConfiguration", "Debug")]
    [InlineData("DefaultFeaturesEnabled", true)]
    [InlineData("DeploymentEnrollmentKeyPresent", true)]
    [InlineData("ProvisioningMaterial", "IncludesPrivateMaterial")]
    [InlineData("RootSpkiPinCount", 0)]
    [InlineData("RootSpkiPinCount", 9)]
    [InlineData("UpdateManifestPublicKeyCount", 0)]
    [InlineData("UpdateManifestPublicKeyCount", 5)]
    [InlineData("CommandAuthorityPublicKeyCount", 0)]
    [InlineData("CommandAuthorityPublicKeyCount", 5)]
    public void ValidateRejectsNonHardenedBuildAssertion(
        string property,
        object value)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
                evidence[property] = JsonSerializer.SerializeToNode(value));

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Theory]
    [InlineData("SourceRepository", "other/repository")]
    [InlineData("SourceCommit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("ReleaseVersion", "5.12.11")]
    [InlineData("BuildId", "other-build")]
    [InlineData("BuildTimestamp", "2026-07-28T09:58:59Z")]
    public void ValidateRejectsBuildIdentityMismatch(string property, string value)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence => evidence[property] = value);

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Theory]
    [InlineData("BuildRecipeSha256")]
    [InlineData("DependencyLockSha256")]
    [InlineData("ToolchainFileSha256")]
    [InlineData("ProvisioningInputSha256")]
    public void ValidateRejectsNonCanonicalEvidenceDigest(string property)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence => evidence[property] = new string('A', 64));

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Theory]
    [InlineData("BuildRecipeSha256")]
    [InlineData("DependencyLockSha256")]
    [InlineData("ToolchainFileSha256")]
    [InlineData("ProvisioningInputSha256")]
    public void ValidateRejectsPlaceholderEvidenceDigest(string property)
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence => evidence[property] = new string('0', 64));

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsEvidenceArtifactHashSubstitution()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
            {
                JsonArray artifacts = evidence["Artifacts"]!.AsArray();
                artifacts[2]!.AsObject()["Sha256"] = new string('0', 64);
            });

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceMismatch);
    }

    [Fact]
    public void ValidateRejectsEvidenceArtifactSizeSubstitution()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
            {
                JsonArray artifacts = evidence["Artifacts"]!.AsArray();
                JsonObject media = artifacts[2]!.AsObject();
                media["Size"] = media["Size"]!.GetValue<long>() + 1;
            });

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceMismatch);
    }

    [Fact]
    public void ValidateRejectsNonCanonicalEvidenceArtifactOrder()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
            {
                JsonArray artifacts = evidence["Artifacts"]!.AsArray();
                JsonNode agent = artifacts[1]!;
                artifacts.RemoveAt(1);
                artifacts.Insert(2, agent);
            });

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceMismatch);
    }

    [Fact]
    public void ValidateRejectsDuplicateEvidenceArtifactRole()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
            {
                JsonArray artifacts = evidence["Artifacts"]!.AsArray();
                artifacts[2]!.AsObject()["Role"] = ExampleEndpointBundleV1.AgentRole;
            });

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsUnknownEvidenceArtifactProperty()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            mutateBuildEvidence: evidence =>
            {
                JsonArray artifacts = evidence["Artifacts"]!.AsArray();
                artifacts[0]!.AsObject()["Path"] = "/not-admissible";
            });

        AssertError(bundle, SigningProfileValidationError.BuildEvidenceInvalid);
    }

    [Fact]
    public void ValidateRejectsBuildEvidenceBytesNotBoundByRequest()
    {
        ExampleBundleTestData bundle = ExampleBundleTestData.Create()
            .WithUnboundSameSizeArtifactMutation(
                ExampleEndpointBundleV1.BuildEvidenceFileName);

        AssertError(bundle, SigningProfileValidationError.ArtifactHashMismatch);
    }

    private static SigningProfileValidationResult Validate(
        ExampleBundleTestData bundle)
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

    private static byte[] ReadEvidence(ExampleBundleTestData bundle)
    {
        using Stream stream = bundle.OpenRead(
            ExampleEndpointBundleV1.BuildEvidenceFileName);
        using MemoryStream content = new();
        stream.CopyTo(content);
        return content.ToArray();
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArtifactSigning.Profiles;
using Xunit;

namespace ArtifactSigning.TestProfile.Tests;

public sealed class ExampleEndpointBundleV1FinalizationTests
{
    private static readonly byte[] Utf8Bom = [0xef, 0xbb, 0xbf];

    private static readonly JsonSerializerOptions IndentedJson = new()
    {
        WriteIndented = true,
    };

    private static readonly string[] PreservedManifestProperties =
    [
        "AgentVersion",
        "ProtocolVersion",
        "MinCompatibleAgentVersion",
        "DeploymentId",
        "BuildTimestamp",
        "BuildId",
        "ManifestSequence",
        "Channel",
        "ExpiresAt",
        "Target",
        "Hardened",
        "EnrollmentMode",
        "Artifact",
    ];

    private static readonly DateTimeOffset FinalizedAt =
        new(2026, 7, 28, 10, 5, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset TimestampedAt =
        new(2026, 7, 28, 10, 4, 0, TimeSpan.Zero);

    [Fact]
    public void FinalizeProducesDeterministicCurrentExampleManifestShape()
    {
        FinalizedFixture fixture = CreateFinalizedFixture();

        SigningProfileFinalizationResult repeated =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(
                    fixture.UnsignedBundle,
                    fixture.SignedBundle,
                    fixture.Evidence));
        byte[] first = fixture.Finalization.GetFinalizedManifestBytes();
        byte[] second = repeated.GetFinalizedManifestBytes();

        Assert.Equal(first, second);
        Assert.Equal((byte)'\n', first[^1]);
        Assert.NotEqual((byte)'\n', first[^2]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.False(first.AsSpan().StartsWith(Utf8Bom));
        string finalizedJson = Encoding.UTF8.GetString(first);
        Assert.Contains("\n  \"AgentVersion\":", finalizedJson, StringComparison.Ordinal);
        Assert.Contains("\n    \"SignerThumbprint\":", finalizedJson, StringComparison.Ordinal);

        using JsonDocument document = JsonDocument.Parse(first);
        JsonElement root = document.RootElement;
        using Stream unsignedManifestStream = fixture.UnsignedBundle.OpenRead(
            ExampleEndpointBundleV1.ManifestFileName);
        using JsonDocument unsignedDocument = JsonDocument.Parse(unsignedManifestStream);
        foreach (string preservedProperty in PreservedManifestProperties)
        {
            Assert.Equal(
                unsignedDocument.RootElement.GetProperty(preservedProperty).GetRawText(),
                root.GetProperty(preservedProperty).GetRawText());
        }

        Assert.Equal(
            [
                "AgentVersion",
                "ProtocolVersion",
                "MinCompatibleAgentVersion",
                "Sha256",
                "DeploymentId",
                "BuildTimestamp",
                "BuildId",
                "ManifestSequence",
                "Channel",
                "ExpiresAt",
                "Target",
                "Hardened",
                "EnrollmentMode",
                "Artifact",
                "Artifacts",
                "Authenticode",
            ],
            root.EnumerateObject().Select(property => property.Name));
        Assert.False(root.TryGetProperty(
            "ExpectedAuthenticodeSignerThumbprint",
            out _));

        JsonElement authenticode = root.GetProperty("Authenticode");
        Assert.Equal(
            ExampleBundleTestData.SignerThumbprint,
            authenticode.GetProperty("SignerThumbprint").GetString());
        Assert.True(authenticode.GetProperty("Timestamped").GetBoolean());
        Assert.Equal(
            "2026-07-28T10:05:00Z",
            authenticode.GetProperty("FinalizedAt").GetString());

        Dictionary<string, VerifiedAuthenticodeArtifact> evidenceByRole =
            fixture.Evidence.ToDictionary(evidence => evidence.Role, StringComparer.Ordinal);
        foreach (JsonElement artifact in root.GetProperty("Artifacts").EnumerateArray())
        {
            string role = artifact.GetProperty("Role").GetString()!;
            Assert.Equal(
                evidenceByRole[role].Sha256,
                artifact.GetProperty("Sha256").GetString());
        }

        Assert.Equal(
            evidenceByRole[ExampleEndpointBundleV1.AgentRole].Sha256,
            root.GetProperty("Sha256").GetString());
    }

    [Fact]
    public void ValidateFinalizedAcceptsExactSignedBundleAndTrustedEvidence()
    {
        FinalizedFixture fixture = CreateFinalizedFixture();

        SigningProfileValidationResult result =
            ExampleEndpointBundleV1.Instance.ValidateFinalizedBundle(
                CreateValidationContext(fixture));

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningProfileValidationError.None, result.Error);
    }

    [Fact]
    public void FinalizeRejectsUnsignedPayloads()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(unsigned, TimestampedAt);

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, unsigned, evidence));

        AssertError(result, SigningProfileValidationError.ArtifactNotSigned);
    }

    [Fact]
    public void FinalizeRejectsPartiallySignedPayloads()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData partiallySigned = unsigned.WithPayloadsStructurallySigned(
            ExampleEndpointBundleV1.AgentFileName);
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(partiallySigned, TimestampedAt);

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, partiallySigned, evidence));

        AssertError(result, SigningProfileValidationError.ArtifactNotSigned);
    }

    [Fact]
    public void FinalizeRejectsMalformedEmbeddedCertificateTable()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData malformed = unsigned
            .WithAllPayloadsStructurallySigned()
            .WithUnboundSameSizeArtifactMutation(
                ExampleEndpointBundleV1.DesktopWorkerFileName);
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(malformed, TimestampedAt);

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, malformed, evidence));

        AssertError(result, SigningProfileValidationError.ArtifactFormatInvalid);
    }

    [Fact]
    public void FinalizeRejectsSignerEvidenceThatDiffersFromUnsignedPin()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData signed = unsigned.WithAllPayloadsStructurallySigned();
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(
                signed,
                TimestampedAt,
                signerThumbprint: new string('B', 40));

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, signed, evidence));

        AssertError(result, SigningProfileValidationError.SignatureEvidenceMismatch);
    }

    [Fact]
    public void FinalizeRejectsTimestampEvidenceAfterFinalization()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData signed = unsigned.WithAllPayloadsStructurallySigned();
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(signed, FinalizedAt.AddSeconds(1));

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, signed, evidence));

        AssertError(result, SigningProfileValidationError.TimestampEvidenceInvalid);
    }

    [Fact]
    public void FinalizeRejectsFinalizationAtRequestExpiry()
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData signed = unsigned.WithAllPayloadsStructurallySigned();
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(signed, TimestampedAt);
        SigningProfileFinalizationContext context = new(
            unsigned.Request,
            unsigned,
            signed,
            evidence,
            unsigned.Request.ExpiresAt);

        SigningProfileFinalizationResult result =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(context);

        AssertError(result, SigningProfileValidationError.TimestampEvidenceInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsUnknownManifestProperty()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest => manifest["Unexpected"] = true);

        AssertValidationError(
            fixture,
            SigningProfileValidationError.FinalizedManifestInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsDuplicateAuthenticodeProperty()
    {
        FinalizedFixture fixture = CreateFinalizedFixture();
        byte[] validManifest = ReadManifest(fixture.FinalizedBundle);
        string duplicateJson = Encoding.UTF8.GetString(validManifest).Replace(
            "\"Timestamped\": true,",
            "\"Timestamped\": true,\n    \"Timestamped\": true,",
            StringComparison.Ordinal);
        FinalizedFixture duplicate = fixture with
        {
            FinalizedBundle = fixture.FinalizedBundle
                .WithManifestBytesPreservingRequest(
                    Encoding.UTF8.GetBytes(duplicateJson)),
        };

        AssertValidationError(
            duplicate,
            SigningProfileValidationError.FinalizedManifestInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsUnsignedOnlySignerExpectation()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest =>
                manifest["ExpectedAuthenticodeSignerThumbprint"] =
                    ExampleBundleTestData.SignerThumbprint);

        AssertValidationError(
            fixture,
            SigningProfileValidationError.FinalizedManifestInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsFalseTimestampClaim()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest =>
                manifest["Authenticode"]!.AsObject()["Timestamped"] = false);

        AssertValidationError(
            fixture,
            SigningProfileValidationError.TimestampEvidenceInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsNonCanonicalFinalizationTime()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest =>
                manifest["Authenticode"]!.AsObject()["FinalizedAt"] =
                    "2026-07-28T10:05:00+00:00");

        AssertValidationError(
            fixture,
            SigningProfileValidationError.FinalizedManifestInvalid);
    }

    [Fact]
    public void ValidateFinalizedRejectsManifestSignerEvidenceMismatch()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest =>
                manifest["Authenticode"]!.AsObject()["SignerThumbprint"] =
                    new string('B', 40));

        AssertValidationError(
            fixture,
            SigningProfileValidationError.SignatureEvidenceMismatch);
    }

    [Fact]
    public void ValidateFinalizedRejectsSignedArtifactHashSubstitution()
    {
        FinalizedFixture fixture = CreateFinalizedFixture(
            manifest =>
            {
                JsonArray artifacts = manifest["Artifacts"]!.AsArray();
                artifacts[1]!.AsObject()["Sha256"] = new string('0', 64);
            });

        AssertValidationError(
            fixture,
            SigningProfileValidationError.ArtifactHashMismatch);
    }

    [Fact]
    public void ValidateFinalizedRejectsAlteredSignedArtifactBytes()
    {
        FinalizedFixture fixture = CreateFinalizedFixture();
        FinalizedFixture altered = fixture with
        {
            FinalizedBundle = fixture.FinalizedBundle
                .WithUnboundSameSizeArtifactMutation(
                    ExampleEndpointBundleV1.DesktopWorkerFileName),
        };

        AssertValidationError(
            altered,
            SigningProfileValidationError.ArtifactHashMismatch);
    }

    private static FinalizedFixture CreateFinalizedFixture(
        Action<JsonObject>? mutateFinalizedManifest = null)
    {
        ExampleBundleTestData unsigned = ExampleBundleTestData.Create();
        ExampleBundleTestData signed = unsigned.WithAllPayloadsStructurallySigned();
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence =
            CreateEvidence(signed, TimestampedAt);
        SigningProfileFinalizationResult finalization =
            ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                CreateFinalizationContext(unsigned, signed, evidence));
        Assert.True(finalization.IsSuccess);

        byte[] manifestBytes = finalization.GetFinalizedManifestBytes();
        if (mutateFinalizedManifest is not null)
        {
            JsonObject manifest = JsonNode.Parse(manifestBytes)!.AsObject();
            mutateFinalizedManifest(manifest);
            manifestBytes = JsonSerializer.SerializeToUtf8Bytes(
                manifest,
                IndentedJson);
        }

        ExampleBundleTestData finalized =
            signed.WithManifestBytesPreservingRequest(manifestBytes);
        return new FinalizedFixture(
            unsigned,
            signed,
            finalized,
            evidence,
            finalization);
    }

    private static SigningProfileFinalizationContext CreateFinalizationContext(
        ExampleBundleTestData unsigned,
        ExampleBundleTestData signed,
        IReadOnlyList<VerifiedAuthenticodeArtifact> evidence)
    {
        return new SigningProfileFinalizationContext(
            unsigned.Request,
            unsigned,
            signed,
            evidence,
            FinalizedAt);
    }

    private static SigningProfileFinalizedValidationContext CreateValidationContext(
        FinalizedFixture fixture)
    {
        return new SigningProfileFinalizedValidationContext(
            fixture.UnsignedBundle.Request,
            fixture.FinalizedBundle,
            fixture.Evidence,
            FinalizedAt.AddSeconds(1));
    }

    private static IReadOnlyList<VerifiedAuthenticodeArtifact> CreateEvidence(
        ExampleBundleTestData bundle,
        DateTimeOffset timestampedAt,
        string signerThumbprint = ExampleBundleTestData.SignerThumbprint)
    {
        return
        [
            CreateEvidence(
                bundle,
                ExampleEndpointBundleV1.AgentRole,
                ExampleEndpointBundleV1.AgentFileName,
                signerThumbprint,
                timestampedAt),
            CreateEvidence(
                bundle,
                ExampleEndpointBundleV1.MediaRole,
                ExampleEndpointBundleV1.MediaFileName,
                signerThumbprint,
                timestampedAt),
            CreateEvidence(
                bundle,
                ExampleEndpointBundleV1.DesktopWorkerRole,
                ExampleEndpointBundleV1.DesktopWorkerFileName,
                signerThumbprint,
                timestampedAt),
        ];
    }

    private static VerifiedAuthenticodeArtifact CreateEvidence(
        ExampleBundleTestData bundle,
        string role,
        string fileName,
        string signerThumbprint,
        DateTimeOffset timestampedAt)
    {
        using Stream stream = bundle.OpenRead(fileName);
        return new VerifiedAuthenticodeArtifact(
            role,
            fileName,
            stream.Length,
            Convert.ToHexStringLower(SHA256.HashData(stream)),
            signerThumbprint,
            timestampedAt);
    }

    private static void AssertError(
        SigningProfileFinalizationResult result,
        SigningProfileValidationError expected)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(expected, result.Error);
    }

    private static void AssertValidationError(
        FinalizedFixture fixture,
        SigningProfileValidationError expected)
    {
        SigningProfileValidationResult result =
            ExampleEndpointBundleV1.Instance.ValidateFinalizedBundle(
                CreateValidationContext(fixture));

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

    private sealed record FinalizedFixture(
        ExampleBundleTestData UnsignedBundle,
        ExampleBundleTestData SignedBundle,
        ExampleBundleTestData FinalizedBundle,
        IReadOnlyList<VerifiedAuthenticodeArtifact> Evidence,
        SigningProfileFinalizationResult Finalization);
}

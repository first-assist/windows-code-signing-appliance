using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Profiles.Tests;

public sealed class SigningProfileContractTests
{
    [Fact]
    public void DescriptorPreservesClosedCompiledPolicy()
    {
        SigningProfileDescriptor descriptor = CreateDescriptor();

        Assert.Equal("ExampleProfileV1", descriptor.Identity.ProfileId);
        Assert.Equal(["example-project"], descriptor.AllowedProjectIds);
        Assert.Equal(["example/repository"], descriptor.AllowedSourceRepositories);
        Assert.Equal(2, descriptor.Artifacts.Count);
        Assert.Equal(1000, descriptor.MaximumRequestBytes);
    }

    [Fact]
    public void DescriptorAllowsClosedJsonBuildEvidenceAlongsideOneManifest()
    {
        SigningProfileDescriptor descriptor = new(
            new SigningProfileIdentity("ExampleProfileV1", 1),
            ["example-project"],
            ["example/repository"],
            [
                new SigningProfileArtifactDefinition(
                    "Manifest",
                    "manifest.json",
                    SigningProfileArtifactKind.JsonManifest,
                    100),
                new SigningProfileArtifactDefinition(
                    "BuildEvidence",
                    "build-evidence.json",
                    SigningProfileArtifactKind.JsonBuildEvidence,
                    100),
                new SigningProfileArtifactDefinition(
                    "Payload",
                    "payload.exe",
                    SigningProfileArtifactKind.PortableExecutable,
                    100),
            ],
            ["ExampleSignerV1"],
            ["ExampleTimestampV1"],
            1000);

        Assert.Equal(
            SigningProfileArtifactKind.JsonBuildEvidence,
            descriptor.Artifacts[1].Kind);
    }

    [Fact]
    public void DescriptorRejectsDuplicateArtifactRole()
    {
        SigningProfileArtifactDefinition first = new(
            "Payload",
            "first.exe",
            SigningProfileArtifactKind.PortableExecutable,
            100);
        SigningProfileArtifactDefinition second = new(
            "Payload",
            "second.exe",
            SigningProfileArtifactKind.PortableExecutable,
            100);

        Assert.Throws<ArgumentException>(
            () => new SigningProfileDescriptor(
                new SigningProfileIdentity("ExampleProfileV1", 1),
                ["example-project"],
                ["example/repository"],
                [
                    new SigningProfileArtifactDefinition(
                        "Manifest",
                        "manifest.json",
                        SigningProfileArtifactKind.JsonManifest,
                        100),
                    first,
                    second,
                ],
                ["ExampleSignerV1"],
                ["ExampleTimestampV1"],
                1000));
    }

    [Theory]
    [InlineData("../payload.exe")]
    [InlineData("directory/payload.exe")]
    [InlineData("payload.exe:stream")]
    public void ArtifactDefinitionRejectsPathLikeFilename(string fileName)
    {
        Assert.Throws<ArgumentException>(
            () => new SigningProfileArtifactDefinition(
                "Payload",
                fileName,
                SigningProfileArtifactKind.PortableExecutable,
                100));
    }

    [Theory]
    [InlineData("../repository")]
    [InlineData("owner//repository")]
    [InlineData("owner/repository/")]
    public void DescriptorRejectsInvalidSourceRepository(string sourceRepository)
    {
        Assert.Throws<ArgumentException>(
            () => new SigningProfileDescriptor(
                new SigningProfileIdentity("ExampleProfileV1", 1),
                ["example-project"],
                [sourceRepository],
                [
                    new SigningProfileArtifactDefinition(
                        "Manifest",
                        "manifest.json",
                        SigningProfileArtifactKind.JsonManifest,
                        100),
                ],
                ["ExampleSignerV1"],
                ["ExampleTimestampV1"],
                1000));
    }

    [Fact]
    public void RequestValidatorAcceptsExactInstalledContract()
    {
        SigningProfileValidationError result = SigningProfileRequestValidator.Validate(
            CreateDescriptor(),
            CreateRequest());

        Assert.Equal(SigningProfileValidationError.None, result);
    }

    [Theory]
    [InlineData(
        "OtherProfileV1",
        "example-project",
        "example/repository",
        "ExampleSignerV1",
        "ExampleTimestampV1",
        SigningProfileValidationError.ProfileMismatch)]
    [InlineData(
        "ExampleProfileV1",
        "other-project",
        "example/repository",
        "ExampleSignerV1",
        "ExampleTimestampV1",
        SigningProfileValidationError.ProjectNotAllowed)]
    [InlineData(
        "ExampleProfileV1",
        "example-project",
        "other/repository",
        "ExampleSignerV1",
        "ExampleTimestampV1",
        SigningProfileValidationError.SourceRepositoryNotAllowed)]
    [InlineData(
        "ExampleProfileV1",
        "example-project",
        "example/repository",
        "OtherSignerV1",
        "ExampleTimestampV1",
        SigningProfileValidationError.SignerPolicyNotAllowed)]
    [InlineData(
        "ExampleProfileV1",
        "example-project",
        "example/repository",
        "ExampleSignerV1",
        "OtherTimestampV1",
        SigningProfileValidationError.TimestampPolicyNotAllowed)]
    public void RequestValidatorRejectsPolicyMismatch(
        string profileId,
        string projectId,
        string sourceRepository,
        string signerPolicyId,
        string timestampPolicyId,
        SigningProfileValidationError expected)
    {
        ArtifactSigningRequestV1 request = CreateRequest() with
        {
            ProfileId = profileId,
            ProjectId = projectId,
            SourceRepository = sourceRepository,
            SignerPolicyId = signerPolicyId,
            TimestampPolicyId = timestampPolicyId,
        };

        SigningProfileValidationError result = SigningProfileRequestValidator.Validate(
            CreateDescriptor(),
            request);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void RequestValidatorRejectsUnexpectedArtifactFilename()
    {
        ArtifactSigningRequestV1 request = CreateRequest() with
        {
            Artifacts =
            [
                new RequestArtifactV1("Manifest", "manifest.json", 2, new string('0', 64)),
                new RequestArtifactV1("Payload", "other.exe", 3, new string('1', 64)),
            ],
        };

        SigningProfileValidationError result = SigningProfileRequestValidator.Validate(
            CreateDescriptor(),
            request);

        Assert.Equal(SigningProfileValidationError.ArtifactInventoryMismatch, result);
    }

    [Fact]
    public void RequestValidatorRejectsAggregateSizeAboveProfileLimit()
    {
        SigningProfileDescriptor descriptor = new(
            new SigningProfileIdentity("ExampleProfileV1", 1),
            ["example-project"],
            ["example/repository"],
            [
                new SigningProfileArtifactDefinition(
                    "Manifest",
                    "manifest.json",
                    SigningProfileArtifactKind.JsonManifest,
                    700),
                new SigningProfileArtifactDefinition(
                    "Payload",
                    "payload.exe",
                    SigningProfileArtifactKind.PortableExecutable,
                    700),
            ],
            ["ExampleSignerV1"],
            ["ExampleTimestampV1"],
            1000);
        ArtifactSigningRequestV1 request = CreateRequest() with
        {
            Artifacts =
            [
                new RequestArtifactV1("Manifest", "manifest.json", 600, new string('0', 64)),
                new RequestArtifactV1("Payload", "payload.exe", 600, new string('1', 64)),
            ],
        };

        SigningProfileValidationError result = SigningProfileRequestValidator.Validate(
            descriptor,
            request);

        Assert.Equal(SigningProfileValidationError.ArtifactSizeMismatch, result);
    }

    [Fact]
    public void RegistryResolvesExactVersionAndRejectsDuplicateRegistration()
    {
        StubSigningProfile profile = new(CreateDescriptor());
        SigningProfileRegistry registry = new([profile]);

        Assert.Same(profile, registry.Resolve("ExampleProfileV1", 1));
        Assert.Null(registry.Resolve("ExampleProfileV1", 2));
        Assert.Throws<ArgumentException>(
            () => new SigningProfileRegistry([profile, profile]));
    }

    [Fact]
    public void PackageDescriptorCanonicalDigestDoesNotDependOnProfileDeclarationOrder()
    {
        SigningProfileIdentity first = new("ExampleProfileV1", 1);
        SigningProfileIdentity second = new("AnotherExampleProfileV1", 2);
        const string AssemblyDigest =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        string firstDigest = SigningProfilePackageDescriptor.ComputeDescriptorSha256(
            SigningProfilePackageAbi.CurrentVersion,
            "Example.Package",
            "1.2.3-alpha.1+build-7",
            AssemblyDigest,
            [first, second]);
        string secondDigest = SigningProfilePackageDescriptor.ComputeDescriptorSha256(
            SigningProfilePackageAbi.CurrentVersion,
            "Example.Package",
            "1.2.3-alpha.1+build-7",
            AssemblyDigest,
            [second, first]);

        Assert.Equal(firstDigest, secondDigest);
    }

    [Fact]
    public void PackageDescriptorRejectsUnsupportedAbiAndDigestDrift()
    {
        SigningProfileIdentity identity = new("ExampleProfileV1", 1);
        const string AssemblyDigest =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string descriptorDigest = SigningProfilePackageDescriptor.ComputeDescriptorSha256(
            SigningProfilePackageAbi.CurrentVersion,
            "Example.Package",
            "1.2.3",
            AssemblyDigest,
            [identity]);
        string packageDigest = SigningProfilePackageDescriptor.ComputePackageSha256(
            descriptorDigest,
            AssemblyDigest);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SigningProfilePackageDescriptor(
                SigningProfilePackageAbi.CurrentVersion + 1,
                "Example.Package",
                "1.2.3",
                packageDigest,
                AssemblyDigest,
                descriptorDigest,
                [identity]));
        Assert.Throws<ArgumentException>(
            () => new SigningProfilePackageDescriptor(
                SigningProfilePackageAbi.CurrentVersion,
                "Example.Package",
                "1.2.3",
                new string('b', 64),
                AssemblyDigest,
                descriptorDigest,
                [identity]));
        Assert.Throws<ArgumentException>(
            () => new SigningProfilePackageDescriptor(
                SigningProfilePackageAbi.CurrentVersion,
                "Example.Package",
                "1.2.3",
                packageDigest,
                AssemblyDigest,
                new string('b', 64),
                [identity]));
    }

    [Fact]
    public void PackageSetResolvesStaticPackageProfilesAndRejectsDuplicatePackageOrProfile()
    {
        StubSigningProfile first = new(CreateDescriptor());
        StubSigningProfile second = new(CreateDescriptor("AnotherExampleProfileV1"));
        StubSigningProfile duplicate = new(CreateDescriptor());
        CompiledSigningProfilePackage firstPackage = new(
            CreatePackageDescriptor("Example.Package", "1.0.0", first.Descriptor.Identity),
            [first]);
        CompiledSigningProfilePackage secondPackage = new(
            CreatePackageDescriptor("Another.Package", "1.0.0", second.Descriptor.Identity),
            [second]);

        SigningProfilePackageSet packageSet = new([firstPackage, secondPackage]);
        SigningProfilePackageSet reorderedPackageSet = new([secondPackage, firstPackage]);
        SigningProfileRegistry registry = SigningProfileRegistry.FromPackageSet(packageSet);

        Assert.Equal(2, packageSet.Packages.Count);
        Assert.Equal(packageSet.PackageSetSha256, reorderedPackageSet.PackageSetSha256);
        Assert.Same(first, registry.Resolve("ExampleProfileV1", 1));
        Assert.Same(second, registry.Resolve("AnotherExampleProfileV1", 1));
        Assert.Same(
            firstPackage.Descriptor,
            registry.ResolvePackage("ExampleProfileV1", 1));
        Assert.Null(registry.ResolvePackage("ExampleProfileV1", 2));
        Assert.Throws<ArgumentException>(
            () => new SigningProfilePackageSet(
                [
                    firstPackage,
                    new CompiledSigningProfilePackage(
                        CreatePackageDescriptor(
                            "Example.Package",
                            "2.0.0",
                            second.Descriptor.Identity),
                        [second]),
                ]));
        Assert.Throws<ArgumentException>(
            () => new SigningProfilePackageSet(
                [
                    firstPackage,
                    new CompiledSigningProfilePackage(
                        CreatePackageDescriptor(
                            "Third.Package",
                            "1.0.0",
                            duplicate.Descriptor.Identity),
                        [duplicate]),
                ]));
    }

    [Fact]
    public void PackageSetRejectsProfileImplementationsThatDoNotMatchStaticMetadata()
    {
        StubSigningProfile profile = new(CreateDescriptor());
        SigningProfilePackageDescriptor descriptor = CreatePackageDescriptor(
            "Example.Package",
            "1.0.0",
            new SigningProfileIdentity("DifferentExampleProfileV1", 1));

        Assert.Throws<ArgumentException>(
            () => new SigningProfilePackageSet(
                [new CompiledSigningProfilePackage(descriptor, [profile])]));
    }

    [Fact]
    public void VerifiedAuthenticodeEvidencePreservesCanonicalPublicValues()
    {
        VerifiedAuthenticodeArtifact evidence = new(
            "Payload",
            "payload.exe",
            123,
            new string('a', 64),
            new string('A', 40),
            new DateTimeOffset(2026, 7, 28, 11, 0, 0, TimeSpan.FromHours(1)));

        Assert.Equal("Payload", evidence.Role);
        Assert.Equal("payload.exe", evidence.FileName);
        Assert.Equal(123, evidence.Size);
        Assert.Equal(new string('a', 64), evidence.Sha256);
        Assert.Equal(new string('A', 40), evidence.SignerThumbprint);
        Assert.Equal(
            new DateTimeOffset(2026, 7, 28, 10, 0, 0, TimeSpan.Zero),
            evidence.TimestampedAt);
    }

    [Theory]
    [InlineData("payload.exe", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("../payload.exe", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("payload.exe", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void VerifiedAuthenticodeEvidenceRejectsNonCanonicalValues(
        string fileName,
        string sha256,
        string signerThumbprint)
    {
        Assert.Throws<ArgumentException>(
            () => new VerifiedAuthenticodeArtifact(
                "Payload",
                fileName,
                123,
                sha256,
                signerThumbprint,
                new DateTimeOffset(2026, 7, 28, 10, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void FinalizationContextCopiesEvidenceAndRequiresWholeSecondTime()
    {
        ArtifactSigningRequestV1 request = CreateRequest();
        StubArtifactReader reader = new();
        List<VerifiedAuthenticodeArtifact> evidence =
        [
            CreateEvidence(),
        ];
        SigningProfileFinalizationContext context = new(
            request,
            reader,
            reader,
            evidence,
            new DateTimeOffset(2026, 7, 28, 10, 1, 0, TimeSpan.Zero));

        evidence.Clear();

        Assert.Single(context.VerifiedArtifacts);
        Assert.Throws<ArgumentException>(
            () => new SigningProfileFinalizationContext(
                request,
                reader,
                reader,
                [CreateEvidence()],
                new DateTimeOffset(
                    2026,
                    7,
                    28,
                    10,
                    1,
                    0,
                    TimeSpan.Zero).AddTicks(1)));
    }

    [Fact]
    public void FinalizationResultReturnsDefensiveManifestCopies()
    {
        SigningProfileFinalizationResult result =
            SigningProfileFinalizationResult.Success("{}"u8);

        byte[] first = result.GetFinalizedManifestBytes();
        first[0] = (byte)'[';
        byte[] second = result.GetFinalizedManifestBytes();

        Assert.Equal("{}"u8.ToArray(), second);
    }

    private static SigningProfileDescriptor CreateDescriptor(
        string profileId = "ExampleProfileV1")
    {
        return new SigningProfileDescriptor(
            new SigningProfileIdentity(profileId, 1),
            ["example-project"],
            ["example/repository"],
            [
                new SigningProfileArtifactDefinition(
                    "Manifest",
                    "manifest.json",
                    SigningProfileArtifactKind.JsonManifest,
                    100),
                new SigningProfileArtifactDefinition(
                    "Payload",
                    "payload.exe",
                    SigningProfileArtifactKind.PortableExecutable,
                    500),
            ],
            ["ExampleSignerV1"],
            ["ExampleTimestampV1"],
            1000);
    }

    private static ArtifactSigningRequestV1 CreateRequest()
    {
        return new ArtifactSigningRequestV1(
            Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
            "example-project",
            "ExampleProfileV1",
            1,
            "example/repository",
            new string('0', 40),
            "1.2.3",
            new DateTimeOffset(2026, 7, 28, 10, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 7, 28, 10, 15, 0, TimeSpan.Zero),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "ExampleSignerV1",
            "ExampleTimestampV1",
            [
                new RequestArtifactV1("Manifest", "manifest.json", 2, new string('0', 64)),
                new RequestArtifactV1("Payload", "payload.exe", 3, new string('1', 64)),
            ]);
    }

    private sealed class StubSigningProfile(SigningProfileDescriptor descriptor) : ISigningProfile
    {
        public SigningProfileDescriptor Descriptor { get; } = descriptor;

        public SigningProfileFinalizationResult FinalizeSignedBundle(
            SigningProfileFinalizationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return SigningProfileFinalizationResult.Failure(
                SigningProfileValidationError.FinalizedManifestInvalid);
        }

        public SigningProfileValidationResult ValidateFinalizedBundle(
            SigningProfileFinalizedValidationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return SigningProfileValidationResult.Failure(
                SigningProfileValidationError.FinalizedManifestInvalid);
        }

        public SigningProfileValidationResult ValidateUnsignedBundle(
            SigningProfileValidationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return SigningProfileValidationResult.Success;
        }
    }

    private static SigningProfilePackageDescriptor CreatePackageDescriptor(
        string packageId,
        string packageVersion,
        params SigningProfileIdentity[] identities)
    {
        const string AssemblyDigest =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string descriptorDigest = SigningProfilePackageDescriptor.ComputeDescriptorSha256(
            SigningProfilePackageAbi.CurrentVersion,
            packageId,
            packageVersion,
            AssemblyDigest,
            identities);
        return new SigningProfilePackageDescriptor(
            SigningProfilePackageAbi.CurrentVersion,
            packageId,
            packageVersion,
            SigningProfilePackageDescriptor.ComputePackageSha256(
                descriptorDigest,
                AssemblyDigest),
            AssemblyDigest,
            descriptorDigest,
            identities);
    }

    private sealed class StubArtifactReader : IProfileArtifactReader
    {
        public Stream OpenRead(string fileName)
        {
            ArgumentNullException.ThrowIfNull(fileName);
            return Stream.Null;
        }
    }

    private static VerifiedAuthenticodeArtifact CreateEvidence()
    {
        return new VerifiedAuthenticodeArtifact(
            "Payload",
            "payload.exe",
            123,
            new string('a', 64),
            new string('A', 40),
            new DateTimeOffset(2026, 7, 28, 10, 0, 0, TimeSpan.Zero));
    }
}

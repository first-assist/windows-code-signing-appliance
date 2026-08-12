using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.TestProfile;

public sealed class ExampleEndpointBundleV1 : ISigningProfile
{
    public const string ProfileId = "ExampleEndpointBundleV1";
    public const int ProfileVersion = 2;
    public const string ProjectId = "example-endpoint";
    public const string SourceRepository = "example/endpoint";
    public const string SignerPolicyId = "LabAuthenticodeV1";
    public const string TimestampPolicyId = "DigiCertRfc3161V1";

    public const string ManifestRole = "Manifest";
    public const string ManifestFileName = "release-manifest.json";
    public const string BuildEvidenceRole = "BuildEvidence";
    public const string BuildEvidenceFileName = "build-evidence.json";
    public const string BuildEvidenceFormat = "ExampleEndpointBuildEvidenceV1";
    public const string AgentRole = "Agent";
    public const string AgentFileName = "example-agent.exe";
    public const string MediaRole = "Media";
    public const string MediaFileName = "ExampleMedia.exe";
    public const string DesktopWorkerRole = "DesktopWorker";
    public const string DesktopWorkerFileName = "ExampleDesktopWorker.exe";

    public const int MaximumManifestBytes = 64 * 1024;
    public const int MaximumBuildEvidenceBytes = 32 * 1024;
    public const int MaximumPortableExecutableBytes = 32 * 1024 * 1024;
    public const int MaximumRequestBytes = 100 * 1024 * 1024;

    private const string BuildRecipe = "scripts/build-provisioned-agent.sh";
    private const string DependencyLock = "Cargo.lock";
    private const string ToolchainFile = "rust-toolchain.toml";
    private const string Target = "x86_64-pc-windows-msvc";
    private const string BuildConfiguration = "Release";
    private const string CleanSourceTreeState = "Clean";
    private const string PublicTrustOnlyProvisioning = "PublicTrustOnly";

    public static SigningProfileIdentity Identity { get; } = new(ProfileId, ProfileVersion);

    private static readonly Dictionary<string, ExamplePortableExecutableContract>
        PortableExecutableContracts =
            new Dictionary<string, ExamplePortableExecutableContract>(StringComparer.Ordinal)
            {
                [AgentRole] = new(
                    AgentFileName,
                    "example-agent.exe",
                    "example-endpoint-service",
                    "Example Endpoint Agent"),
                [MediaRole] = new(
                    MediaFileName,
                    "ExampleMedia.exe",
                    "example-media",
                    "Example Endpoint Media"),
                [DesktopWorkerRole] = new(
                    DesktopWorkerFileName,
                    "ExampleDesktopWorker.exe",
                    "example-desktop-worker",
                    "Example Endpoint Desktop Worker"),
            };

    private static readonly SigningProfileDescriptor CompiledDescriptor = new(
        Identity,
        [ProjectId],
        [SourceRepository],
        [
            new SigningProfileArtifactDefinition(
                ManifestRole,
                ManifestFileName,
                SigningProfileArtifactKind.JsonManifest,
                MaximumManifestBytes),
            new SigningProfileArtifactDefinition(
                BuildEvidenceRole,
                BuildEvidenceFileName,
                SigningProfileArtifactKind.JsonBuildEvidence,
                MaximumBuildEvidenceBytes),
            new SigningProfileArtifactDefinition(
                AgentRole,
                AgentFileName,
                SigningProfileArtifactKind.PortableExecutable,
                MaximumPortableExecutableBytes),
            new SigningProfileArtifactDefinition(
                MediaRole,
                MediaFileName,
                SigningProfileArtifactKind.PortableExecutable,
                MaximumPortableExecutableBytes),
            new SigningProfileArtifactDefinition(
                DesktopWorkerRole,
                DesktopWorkerFileName,
                SigningProfileArtifactKind.PortableExecutable,
                MaximumPortableExecutableBytes),
        ],
        [SignerPolicyId],
        [TimestampPolicyId],
        MaximumRequestBytes);

    private ExampleEndpointBundleV1()
    {
    }

    public static ExampleEndpointBundleV1 Instance { get; } = new();

    public SigningProfileDescriptor Descriptor => CompiledDescriptor;

    public SigningProfileValidationResult ValidateUnsignedBundle(
        SigningProfileValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        SigningProfileValidationError requestError = SigningProfileRequestValidator.Validate(
            Descriptor,
            context.Request);
        if (requestError is not SigningProfileValidationError.None)
        {
            return SigningProfileValidationResult.Failure(requestError);
        }

        if (!ExampleSemanticVersion.TryParse(
                context.Request.ReleaseVersion,
                out ExampleSemanticVersion? requestVersion))
        {
            return Failure(SigningProfileValidationError.ManifestInvalid);
        }

        RequestArtifactV1 buildEvidenceRequest = GetRequestArtifact(
            context.Request,
            BuildEvidenceRole);
        ArtifactReadResult buildEvidenceRead = ReadArtifact(
            context.ArtifactReader,
            BuildEvidenceFileName,
            buildEvidenceRequest,
            MaximumBuildEvidenceBytes,
            captureContent: true,
            asciiNeedle: null);
        if (buildEvidenceRead.Error is not SigningProfileValidationError.None)
        {
            return Failure(buildEvidenceRead.Error);
        }

        ExampleBuildEvidenceParseResult buildEvidenceResult =
            ExampleBuildEvidenceParser.Parse(buildEvidenceRead.Content!);
        if (!buildEvidenceResult.IsSuccess)
        {
            return Failure(SigningProfileValidationError.BuildEvidenceInvalid);
        }

        RequestArtifactV1 manifestRequest = GetRequestArtifact(context.Request, ManifestRole);
        ArtifactReadResult manifestRead = ReadArtifact(
            context.ArtifactReader,
            ManifestFileName,
            manifestRequest,
            MaximumManifestBytes,
            captureContent: true,
            asciiNeedle: null);
        if (manifestRead.Error is not SigningProfileValidationError.None)
        {
            return Failure(manifestRead.Error);
        }

        ExampleUnsignedManifestParseResult manifestResult =
            ExampleManifestParser.ParseUnsigned(manifestRead.Content!);
        if (!manifestResult.IsSuccess)
        {
            return Failure(SigningProfileValidationError.ManifestInvalid);
        }

        ExampleUnsignedManifest manifest = manifestResult.Manifest!;
        SigningProfileValidationError manifestError = ValidateManifest(
            manifest,
            context.Request,
            context.ValidationTime,
            requestVersion!,
            requireUnsignedArtifactHashes: true);
        if (manifestError is not SigningProfileValidationError.None)
        {
            return Failure(manifestError);
        }

        SigningProfileValidationError buildEvidenceError = ValidateBuildEvidence(
            buildEvidenceResult.Evidence!,
            context.Request,
            manifest);
        if (buildEvidenceError is not SigningProfileValidationError.None)
        {
            return Failure(buildEvidenceError);
        }

        foreach ((string role, ExamplePortableExecutableContract executableContract)
                 in PortableExecutableContracts)
        {
            RequestArtifactV1 requestArtifact = GetRequestArtifact(context.Request, role);
            ExampleManifestArtifact manifestArtifact = manifest.Artifacts.Single(
                artifact => string.Equals(artifact.Role, role, StringComparison.Ordinal));
            string? asciiNeedle = role is AgentRole
                ? manifest.ExpectedAuthenticodeSignerThumbprint
                : null;

            ArtifactReadResult artifactRead = ReadArtifact(
                context.ArtifactReader,
                executableContract.FileName,
                requestArtifact,
                MaximumPortableExecutableBytes,
                captureContent: false,
                asciiNeedle);
            if (artifactRead.Error is not SigningProfileValidationError.None)
            {
                return Failure(artifactRead.Error);
            }

            if (!string.Equals(
                    artifactRead.Sha256,
                    manifestArtifact.Sha256,
                    StringComparison.Ordinal))
            {
                return Failure(SigningProfileValidationError.ArtifactHashMismatch);
            }

            if (role is AgentRole && artifactRead.AsciiOccurrenceCount is not 1)
            {
                return Failure(SigningProfileValidationError.SignerBindingInvalid);
            }

            using Stream artifactStream = OpenArtifact(
                context.ArtifactReader,
                executableContract.FileName,
                out SigningProfileValidationError openError);
            if (openError is not SigningProfileValidationError.None)
            {
                return Failure(openError);
            }

            PortableExecutableInspectionResult inspection =
                PortableExecutableInspector.InspectUnsigned(artifactStream);
            if (inspection.Error is PortableExecutableInspectionError.SignaturePresent)
            {
                return Failure(SigningProfileValidationError.ArtifactAlreadySigned);
            }

            if (!inspection.IsSuccess)
            {
                return Failure(SigningProfileValidationError.ArtifactFormatInvalid);
            }

            if (!executableContract.Matches(inspection.Information!, requestVersion!))
            {
                return Failure(SigningProfileValidationError.ArtifactVersionMismatch);
            }

            ArtifactReadResult stabilityRead = ReadArtifact(
                context.ArtifactReader,
                executableContract.FileName,
                requestArtifact,
                MaximumPortableExecutableBytes,
                captureContent: false,
                asciiNeedle: null);
            if (stabilityRead.Error is not SigningProfileValidationError.None)
            {
                return Failure(stabilityRead.Error);
            }

            if (!string.Equals(
                    artifactRead.Sha256,
                    stabilityRead.Sha256,
                    StringComparison.Ordinal))
            {
                return Failure(SigningProfileValidationError.ArtifactHashMismatch);
            }
        }

        return SigningProfileValidationResult.Success;
    }

    public SigningProfileFinalizationResult FinalizeSignedBundle(
        SigningProfileFinalizationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.FinalizedAt < context.Request.RequestedAt
            || context.FinalizedAt >= context.Request.ExpiresAt)
        {
            return FinalizationFailure(
                SigningProfileValidationError.TimestampEvidenceInvalid);
        }

        SigningProfileValidationResult unsignedValidation = ValidateUnsignedBundle(
            new SigningProfileValidationContext(
                context.Request,
                context.UnsignedArtifactReader,
                context.FinalizedAt));
        if (!unsignedValidation.IsSuccess)
        {
            return FinalizationFailure(unsignedValidation.Error);
        }

        if (!ExampleSemanticVersion.TryParse(
                context.Request.ReleaseVersion,
                out ExampleSemanticVersion? requestVersion))
        {
            return FinalizationFailure(SigningProfileValidationError.ManifestInvalid);
        }

        ExampleUnsignedManifest? unsignedManifest = ReadUnsignedManifest(
            context.Request,
            context.UnsignedArtifactReader,
            out SigningProfileValidationError manifestError);
        if (manifestError is not SigningProfileValidationError.None)
        {
            return FinalizationFailure(manifestError);
        }

        SigningProfileValidationError signedError = ValidateSignedArtifacts(
            context.Request,
            context.SignedArtifactReader,
            context.VerifiedArtifacts,
            unsignedManifest!.ExpectedAuthenticodeSignerThumbprint,
            context.FinalizedAt,
            requestVersion!,
            out IReadOnlyDictionary<string, VerifiedAuthenticodeArtifact>? signedArtifacts);
        if (signedError is not SigningProfileValidationError.None)
        {
            return FinalizationFailure(signedError);
        }

        byte[] finalizedManifest = ExampleFinalizedManifestSerializer.Serialize(
            unsignedManifest,
            signedArtifacts!,
            context.FinalizedAt);
        if (finalizedManifest.Length > MaximumManifestBytes
            || !ExampleManifestParser.ParseFinalized(finalizedManifest).IsSuccess)
        {
            return FinalizationFailure(
                SigningProfileValidationError.FinalizedManifestInvalid);
        }

        return SigningProfileFinalizationResult.Success(finalizedManifest);
    }

    public SigningProfileValidationResult ValidateFinalizedBundle(
        SigningProfileFinalizedValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        SigningProfileValidationError requestError = SigningProfileRequestValidator.Validate(
            Descriptor,
            context.Request);
        if (requestError is not SigningProfileValidationError.None)
        {
            return Failure(requestError);
        }

        if (!ExampleSemanticVersion.TryParse(
                context.Request.ReleaseVersion,
                out ExampleSemanticVersion? requestVersion))
        {
            return Failure(SigningProfileValidationError.FinalizedManifestInvalid);
        }

        ArtifactReadResult manifestRead = ReadArtifact(
            context.FinalizedArtifactReader,
            ManifestFileName,
            expectedSize: null,
            expectedSha256: null,
            maximumBytes: MaximumManifestBytes,
            captureContent: true,
            asciiNeedle: null);
        if (manifestRead.Error is not SigningProfileValidationError.None)
        {
            return Failure(manifestRead.Error);
        }

        ExampleFinalizedManifestParseResult manifestResult =
            ExampleManifestParser.ParseFinalized(manifestRead.Content!);
        if (!manifestResult.IsSuccess)
        {
            return Failure(SigningProfileValidationError.FinalizedManifestInvalid);
        }

        ExampleFinalizedManifest manifest = manifestResult.Manifest!;
        SigningProfileValidationError manifestError = ValidateManifest(
            manifest,
            context.Request,
            context.ValidationTime,
            requestVersion!,
            requireUnsignedArtifactHashes: false);
        if (manifestError is not SigningProfileValidationError.None)
        {
            return Failure(
                manifestError is SigningProfileValidationError.ManifestInvalid
                    ? SigningProfileValidationError.FinalizedManifestInvalid
                    : manifestError);
        }

        if (!manifest.Authenticode.Timestamped
            || manifest.Authenticode.FinalizedAt < context.Request.RequestedAt
            || manifest.Authenticode.FinalizedAt >= context.Request.ExpiresAt
            || manifest.Authenticode.FinalizedAt > context.ValidationTime
            || manifest.Authenticode.FinalizedAt >= manifest.ExpiresAt)
        {
            return Failure(SigningProfileValidationError.TimestampEvidenceInvalid);
        }

        SigningProfileValidationError signedError = ValidateSignedArtifacts(
            context.Request,
            context.FinalizedArtifactReader,
            context.VerifiedArtifacts,
            manifest.Authenticode.SignerThumbprint,
            manifest.Authenticode.FinalizedAt,
            requestVersion!,
            out IReadOnlyDictionary<string, VerifiedAuthenticodeArtifact>? signedArtifacts);
        if (signedError is not SigningProfileValidationError.None)
        {
            return Failure(signedError);
        }

        foreach (ExampleManifestArtifact manifestArtifact in manifest.Artifacts)
        {
            if (!string.Equals(
                    manifestArtifact.Sha256,
                    signedArtifacts![manifestArtifact.Role].Sha256,
                    StringComparison.Ordinal))
            {
                return Failure(SigningProfileValidationError.ArtifactHashMismatch);
            }
        }

        return SigningProfileValidationResult.Success;
    }

    private static ExampleUnsignedManifest? ReadUnsignedManifest(
        ArtifactSigningRequestV1 request,
        IProfileArtifactReader artifactReader,
        out SigningProfileValidationError error)
    {
        RequestArtifactV1 manifestRequest = GetRequestArtifact(request, ManifestRole);
        ArtifactReadResult manifestRead = ReadArtifact(
            artifactReader,
            ManifestFileName,
            manifestRequest,
            MaximumManifestBytes,
            captureContent: true,
            asciiNeedle: null);
        if (manifestRead.Error is not SigningProfileValidationError.None)
        {
            error = manifestRead.Error;
            return null;
        }

        ExampleUnsignedManifestParseResult manifestResult =
            ExampleManifestParser.ParseUnsigned(manifestRead.Content!);
        if (!manifestResult.IsSuccess)
        {
            error = SigningProfileValidationError.ManifestInvalid;
            return null;
        }

        error = SigningProfileValidationError.None;
        return manifestResult.Manifest;
    }

    private static SigningProfileValidationError ValidateSignedArtifacts(
        ArtifactSigningRequestV1 request,
        IProfileArtifactReader signedArtifactReader,
        ReadOnlyCollection<VerifiedAuthenticodeArtifact> verifiedArtifacts,
        string expectedSignerThumbprint,
        DateTimeOffset finalizedAt,
        ExampleSemanticVersion requestVersion,
        out IReadOnlyDictionary<string, VerifiedAuthenticodeArtifact>? signedArtifacts)
    {
        signedArtifacts = null;
        if (verifiedArtifacts.Count != PortableExecutableContracts.Count)
        {
            return SigningProfileValidationError.SignatureEvidenceMismatch;
        }

        Dictionary<string, VerifiedAuthenticodeArtifact> evidenceByRole =
            new(StringComparer.Ordinal);
        foreach (VerifiedAuthenticodeArtifact evidence in verifiedArtifacts)
        {
            if (!evidenceByRole.TryAdd(evidence.Role, evidence))
            {
                return SigningProfileValidationError.SignatureEvidenceMismatch;
            }
        }

        foreach ((string role, ExamplePortableExecutableContract executableContract)
                 in PortableExecutableContracts)
        {
            if (!evidenceByRole.TryGetValue(
                    role,
                    out VerifiedAuthenticodeArtifact? evidence)
                || !string.Equals(
                    evidence.FileName,
                    executableContract.FileName,
                    StringComparison.Ordinal)
                || !string.Equals(
                    evidence.SignerThumbprint,
                    expectedSignerThumbprint,
                    StringComparison.Ordinal))
            {
                return SigningProfileValidationError.SignatureEvidenceMismatch;
            }

            if (evidence.TimestampedAt < request.RequestedAt
                || evidence.TimestampedAt > finalizedAt)
            {
                return SigningProfileValidationError.TimestampEvidenceInvalid;
            }

            string? asciiNeedle = role is AgentRole
                ? expectedSignerThumbprint
                : null;
            ArtifactReadResult artifactRead = ReadArtifact(
                signedArtifactReader,
                executableContract.FileName,
                evidence.Size,
                evidence.Sha256,
                MaximumPortableExecutableBytes,
                captureContent: false,
                asciiNeedle);
            if (artifactRead.Error is not SigningProfileValidationError.None)
            {
                return artifactRead.Error;
            }

            if (role is AgentRole && artifactRead.AsciiOccurrenceCount is not 1)
            {
                return SigningProfileValidationError.SignerBindingInvalid;
            }

            using Stream artifactStream = OpenArtifact(
                signedArtifactReader,
                executableContract.FileName,
                out SigningProfileValidationError openError);
            if (openError is not SigningProfileValidationError.None)
            {
                return openError;
            }

            PortableExecutableInspectionResult inspection =
                PortableExecutableInspector.InspectSigned(artifactStream);
            if (inspection.Error is PortableExecutableInspectionError.SignatureMissing)
            {
                return SigningProfileValidationError.ArtifactNotSigned;
            }

            if (!inspection.IsSuccess)
            {
                return SigningProfileValidationError.ArtifactFormatInvalid;
            }

            if (!executableContract.Matches(inspection.Information!, requestVersion))
            {
                return SigningProfileValidationError.ArtifactVersionMismatch;
            }

            RequestArtifactV1 unsignedRequestArtifact = GetRequestArtifact(request, role);
            if (string.Equals(
                    evidence.Sha256,
                    unsignedRequestArtifact.Sha256,
                    StringComparison.Ordinal))
            {
                return SigningProfileValidationError.SignatureEvidenceMismatch;
            }

            ArtifactReadResult stabilityRead = ReadArtifact(
                signedArtifactReader,
                executableContract.FileName,
                evidence.Size,
                evidence.Sha256,
                MaximumPortableExecutableBytes,
                captureContent: false,
                asciiNeedle: null);
            if (stabilityRead.Error is not SigningProfileValidationError.None)
            {
                return stabilityRead.Error;
            }

            if (!string.Equals(
                    artifactRead.Sha256,
                    stabilityRead.Sha256,
                    StringComparison.Ordinal))
            {
                return SigningProfileValidationError.ArtifactHashMismatch;
            }
        }

        signedArtifacts = evidenceByRole;
        return SigningProfileValidationError.None;
    }

    private static SigningProfileValidationError ValidateManifest(
        IExampleManifest manifest,
        ArtifactSigningRequestV1 request,
        DateTimeOffset validationTime,
        ExampleSemanticVersion requestVersion,
        bool requireUnsignedArtifactHashes)
    {
        if (!string.Equals(
                manifest.AgentVersion,
                request.ReleaseVersion,
                StringComparison.Ordinal)
            || !ExampleSemanticVersion.TryParse(
                manifest.AgentVersion,
                out ExampleSemanticVersion? agentVersion)
            || !ExampleSemanticVersion.TryParse(
                manifest.MinCompatibleAgentVersion,
                out ExampleSemanticVersion? minimumVersion)
            || minimumVersion!.CompareTo(agentVersion) > 0
            || manifest.ProtocolVersion is not 1
            || !string.Equals(
                manifest.Target,
                Target,
                StringComparison.Ordinal)
            || !manifest.Hardened
            || !string.Equals(
                manifest.EnrollmentMode,
                "PendingApproval",
                StringComparison.Ordinal)
            || !IsSafeManifestIdentifier(manifest.DeploymentId, maximumCharacters: 64)
            || !IsSafeManifestIdentifier(manifest.BuildId, maximumCharacters: 128)
            || !IsSafeManifestIdentifier(manifest.Channel, maximumCharacters: 32)
            || manifest.ManifestSequence <= 0
            || manifest.BuildTimestamp > request.RequestedAt
            || !string.Equals(manifest.Artifact, AgentFileName, StringComparison.Ordinal)
            || !string.Equals(manifest.Sha256, manifest.Artifacts.Single(
                artifact => string.Equals(
                    artifact.Role,
                    AgentRole,
                    StringComparison.Ordinal)).Sha256, StringComparison.Ordinal))
        {
            return SigningProfileValidationError.ManifestInvalid;
        }

        if (manifest.ExpiresAt <= validationTime
            || manifest.ExpiresAt < request.ExpiresAt)
        {
            return SigningProfileValidationError.ManifestExpired;
        }

        foreach (ExampleManifestArtifact manifestArtifact in manifest.Artifacts)
        {
            ExamplePortableExecutableContract contract =
                PortableExecutableContracts[manifestArtifact.Role];
            if (!string.Equals(
                    manifestArtifact.File,
                    contract.FileName,
                    StringComparison.Ordinal))
            {
                return SigningProfileValidationError.ArtifactInventoryMismatch;
            }

            if (requireUnsignedArtifactHashes)
            {
                RequestArtifactV1 requestArtifact = GetRequestArtifact(
                    request,
                    manifestArtifact.Role);
                if (!string.Equals(
                        manifestArtifact.Sha256,
                        requestArtifact.Sha256,
                        StringComparison.Ordinal))
                {
                    return SigningProfileValidationError.ArtifactInventoryMismatch;
                }
            }
        }

        return SigningProfileValidationError.None;
    }

    private static SigningProfileValidationError ValidateBuildEvidence(
        ExampleBuildEvidence evidence,
        ArtifactSigningRequestV1 request,
        ExampleUnsignedManifest manifest)
    {
        if (!string.Equals(
                evidence.Format,
                BuildEvidenceFormat,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.SourceRepository,
                request.SourceRepository,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.SourceCommit,
                request.SourceCommit,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.SourceTreeState,
                CleanSourceTreeState,
                StringComparison.Ordinal)
            || !string.Equals(evidence.BuildRecipe, BuildRecipe, StringComparison.Ordinal)
            || !string.Equals(
                evidence.DependencyLock,
                DependencyLock,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.ToolchainFile,
                ToolchainFile,
                StringComparison.Ordinal)
            || !string.Equals(evidence.Target, Target, StringComparison.Ordinal)
            || !string.Equals(
                evidence.BuildConfiguration,
                BuildConfiguration,
                StringComparison.Ordinal)
            || evidence.DefaultFeaturesEnabled
            || evidence.DeploymentEnrollmentKeyPresent
            || !string.Equals(
                evidence.ProvisioningMaterial,
                PublicTrustOnlyProvisioning,
                StringComparison.Ordinal)
            || evidence.RootSpkiPinCount is < 1 or > 8
            || evidence.UpdateManifestPublicKeyCount is < 1 or > 4
            || evidence.CommandAuthorityPublicKeyCount is < 1 or > 4
            || !string.Equals(
                evidence.ReleaseVersion,
                request.ReleaseVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.BuildId,
                manifest.BuildId,
                StringComparison.Ordinal)
            || evidence.BuildTimestamp != manifest.BuildTimestamp)
        {
            return SigningProfileValidationError.BuildEvidenceInvalid;
        }

        string[] expectedRoles =
        [
            ManifestRole,
            AgentRole,
            MediaRole,
            DesktopWorkerRole,
        ];
        for (int index = 0; index < expectedRoles.Length; index++)
        {
            string expectedRole = expectedRoles[index];
            ExampleBuildEvidenceArtifact evidenceArtifact = evidence.Artifacts[index];
            RequestArtifactV1 requestArtifact = GetRequestArtifact(request, expectedRole);
            if (!string.Equals(
                    evidenceArtifact.Role,
                    expectedRole,
                    StringComparison.Ordinal)
                || !string.Equals(
                    evidenceArtifact.File,
                    requestArtifact.File,
                    StringComparison.Ordinal)
                || evidenceArtifact.Size != requestArtifact.Size
                || !string.Equals(
                    evidenceArtifact.Sha256,
                    requestArtifact.Sha256,
                    StringComparison.Ordinal))
            {
                return SigningProfileValidationError.BuildEvidenceMismatch;
            }
        }

        return SigningProfileValidationError.None;
    }

    private static ArtifactReadResult ReadArtifact(
        IProfileArtifactReader artifactReader,
        string fileName,
        RequestArtifactV1 requestArtifact,
        long maximumBytes,
        bool captureContent,
        string? asciiNeedle)
    {
        return ReadArtifact(
            artifactReader,
            fileName,
            requestArtifact.Size,
            requestArtifact.Sha256,
            maximumBytes,
            captureContent,
            asciiNeedle);
    }

    private static ArtifactReadResult ReadArtifact(
        IProfileArtifactReader artifactReader,
        string fileName,
        long? expectedSize,
        string? expectedSha256,
        long maximumBytes,
        bool captureContent,
        string? asciiNeedle)
    {
        using Stream stream = OpenArtifact(
            artifactReader,
            fileName,
            out SigningProfileValidationError openError);
        if (openError is not SigningProfileValidationError.None)
        {
            return ArtifactReadResult.Failure(openError);
        }

        try
        {
            if (!stream.CanRead)
            {
                return ArtifactReadResult.Failure(
                    SigningProfileValidationError.ArtifactUnavailable);
            }

            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using MemoryStream? content = captureContent ? new MemoryStream() : null;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            long totalBytes = 0;
            int occurrenceCount = 0;
            string tail = string.Empty;

            try
            {
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    totalBytes = checked(totalBytes + read);
                    if (totalBytes > maximumBytes)
                    {
                        return ArtifactReadResult.Failure(
                            SigningProfileValidationError.ArtifactSizeMismatch);
                    }

                    hash.AppendData(buffer, 0, read);
                    content?.Write(buffer, 0, read);

                    if (asciiNeedle is not null)
                    {
                        string combined = tail
                            + System.Text.Encoding.ASCII.GetString(buffer, 0, read);
                        int offset = 0;
                        while ((offset = combined.IndexOf(
                                   asciiNeedle,
                                   offset,
                                   StringComparison.Ordinal)) >= 0)
                        {
                            occurrenceCount++;
                            offset++;
                        }

                        int tailLength = Math.Min(asciiNeedle.Length - 1, combined.Length);
                        tail = combined[^tailLength..];
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }

            if (expectedSize.HasValue && totalBytes != expectedSize.Value)
            {
                return ArtifactReadResult.Failure(
                    SigningProfileValidationError.ArtifactSizeMismatch);
            }

            string actualSha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
            if (expectedSha256 is not null
                && !string.Equals(
                    actualSha256,
                    expectedSha256,
                    StringComparison.Ordinal))
            {
                return ArtifactReadResult.Failure(
                    SigningProfileValidationError.ArtifactHashMismatch);
            }

            return new ArtifactReadResult(
                content?.ToArray(),
                actualSha256,
                occurrenceCount,
                SigningProfileValidationError.None);
        }
        catch (IOException)
        {
            return ArtifactReadResult.Failure(
                SigningProfileValidationError.ArtifactUnavailable);
        }
        catch (NotSupportedException)
        {
            return ArtifactReadResult.Failure(
                SigningProfileValidationError.ArtifactUnavailable);
        }
        catch (OverflowException)
        {
            return ArtifactReadResult.Failure(
                SigningProfileValidationError.ArtifactSizeMismatch);
        }
    }

    private static Stream OpenArtifact(
        IProfileArtifactReader artifactReader,
        string fileName,
        out SigningProfileValidationError error)
    {
        try
        {
            Stream? stream = artifactReader.OpenRead(fileName);
            if (stream is null)
            {
                error = SigningProfileValidationError.ArtifactUnavailable;
                return Stream.Null;
            }

            error = SigningProfileValidationError.None;
            return stream;
        }
        catch (IOException)
        {
            error = SigningProfileValidationError.ArtifactUnavailable;
            return Stream.Null;
        }
        catch (UnauthorizedAccessException)
        {
            error = SigningProfileValidationError.ArtifactUnavailable;
            return Stream.Null;
        }
        catch (NotSupportedException)
        {
            error = SigningProfileValidationError.ArtifactUnavailable;
            return Stream.Null;
        }
    }

    private static RequestArtifactV1 GetRequestArtifact(
        ArtifactSigningRequestV1 request,
        string role)
    {
        return request.Artifacts.Single(
            artifact => string.Equals(artifact.Role, role, StringComparison.Ordinal));
    }

    private static bool IsSafeManifestIdentifier(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    private static SigningProfileValidationResult Failure(
        SigningProfileValidationError error)
    {
        return SigningProfileValidationResult.Failure(error);
    }

    private static SigningProfileFinalizationResult FinalizationFailure(
        SigningProfileValidationError error)
    {
        return SigningProfileFinalizationResult.Failure(error);
    }

    private sealed record ArtifactReadResult(
        byte[]? Content,
        string? Sha256,
        int AsciiOccurrenceCount,
        SigningProfileValidationError Error)
    {
        internal static ArtifactReadResult Failure(SigningProfileValidationError error)
        {
            return new ArtifactReadResult(null, null, 0, error);
        }
    }

    private sealed record ExamplePortableExecutableContract(
        string FileName,
        string OriginalFileName,
        string InternalName,
        string FileDescription)
    {
        internal bool Matches(
            PortableExecutableInformation information,
            ExampleSemanticVersion expectedVersion)
        {
            return string.Equals(
                    information.CompanyName,
                    "Example Organization",
                    StringComparison.Ordinal)
                && string.Equals(
                    information.ProductName,
                    "Example Endpoint Agent",
                    StringComparison.Ordinal)
                && string.Equals(
                    information.OriginalFileName,
                    OriginalFileName,
                    StringComparison.Ordinal)
                && string.Equals(
                    information.InternalName,
                    InternalName,
                    StringComparison.Ordinal)
                && string.Equals(
                    information.FileDescription,
                    FileDescription,
                    StringComparison.Ordinal)
                && string.Equals(
                    information.FileVersion,
                    expectedVersion.Original,
                    StringComparison.Ordinal)
                && string.Equals(
                    information.ProductVersion,
                    expectedVersion.Original,
                    StringComparison.Ordinal)
                && information.FixedFileVersion == expectedVersion.FixedVersion
                && information.FixedProductVersion == expectedVersion.FixedVersion;
        }
    }
}

namespace ArtifactSigning.TestProfile;

internal sealed record ExampleBuildEvidence(
    string Format,
    string SourceRepository,
    string SourceCommit,
    string SourceTreeState,
    string BuildRecipe,
    string BuildRecipeSha256,
    string DependencyLock,
    string DependencyLockSha256,
    string ToolchainFile,
    string ToolchainFileSha256,
    string Target,
    string BuildConfiguration,
    bool DefaultFeaturesEnabled,
    bool DeploymentEnrollmentKeyPresent,
    string ProvisioningMaterial,
    string ProvisioningInputSha256,
    int RootSpkiPinCount,
    int UpdateManifestPublicKeyCount,
    int CommandAuthorityPublicKeyCount,
    bool RelayGrantPublicKeyPresent,
    string ReleaseVersion,
    string BuildId,
    DateTimeOffset BuildTimestamp,
    IReadOnlyList<ExampleBuildEvidenceArtifact> Artifacts);

internal sealed record ExampleBuildEvidenceArtifact(
    string Role,
    string File,
    long Size,
    string Sha256);

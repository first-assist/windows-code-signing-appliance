namespace ArtifactSigning.TestProfile;

internal interface IExampleManifest
{
    string AgentVersion { get; }

    int ProtocolVersion { get; }

    string MinCompatibleAgentVersion { get; }

    string Sha256 { get; }

    string DeploymentId { get; }

    DateTimeOffset BuildTimestamp { get; }

    string BuildId { get; }

    long ManifestSequence { get; }

    string Channel { get; }

    DateTimeOffset ExpiresAt { get; }

    string Target { get; }

    bool Hardened { get; }

    string EnrollmentMode { get; }

    string Artifact { get; }

    IReadOnlyList<ExampleManifestArtifact> Artifacts { get; }
}

internal sealed record ExampleUnsignedManifest(
    string AgentVersion,
    int ProtocolVersion,
    string MinCompatibleAgentVersion,
    string Sha256,
    string DeploymentId,
    DateTimeOffset BuildTimestamp,
    string BuildId,
    long ManifestSequence,
    string Channel,
    DateTimeOffset ExpiresAt,
    string Target,
    bool Hardened,
    string EnrollmentMode,
    string ExpectedAuthenticodeSignerThumbprint,
    string Artifact,
    IReadOnlyList<ExampleManifestArtifact> Artifacts) : IExampleManifest;

internal sealed record ExampleFinalizedManifest(
    string AgentVersion,
    int ProtocolVersion,
    string MinCompatibleAgentVersion,
    string Sha256,
    string DeploymentId,
    DateTimeOffset BuildTimestamp,
    string BuildId,
    long ManifestSequence,
    string Channel,
    DateTimeOffset ExpiresAt,
    string Target,
    bool Hardened,
    string EnrollmentMode,
    string Artifact,
    IReadOnlyList<ExampleManifestArtifact> Artifacts,
    ExampleManifestAuthenticode Authenticode) : IExampleManifest;

internal sealed record ExampleManifestAuthenticode(
    string SignerThumbprint,
    bool Timestamped,
    DateTimeOffset FinalizedAt);

internal sealed record ExampleManifestArtifact(
    string Role,
    string File,
    string Sha256);

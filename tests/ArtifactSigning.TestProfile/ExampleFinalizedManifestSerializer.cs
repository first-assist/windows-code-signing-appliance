using System.Globalization;
using System.Text.Json;
using ArtifactSigning.Profiles;

namespace ArtifactSigning.TestProfile;

internal static class ExampleFinalizedManifestSerializer
{
    internal static byte[] Serialize(
        ExampleUnsignedManifest unsignedManifest,
        IReadOnlyDictionary<string, VerifiedAuthenticodeArtifact> signedArtifacts,
        DateTimeOffset finalizedAt)
    {
        ArgumentNullException.ThrowIfNull(unsignedManifest);
        ArgumentNullException.ThrowIfNull(signedArtifacts);

        using MemoryStream content = new();
        using (Utf8JsonWriter writer = new(
                   content,
                   new JsonWriterOptions
                   {
                       Indented = true,
                       IndentCharacter = ' ',
                       IndentSize = 2,
                       NewLine = "\n",
                   }))
        {
            writer.WriteStartObject();
            writer.WriteString("AgentVersion", unsignedManifest.AgentVersion);
            writer.WriteNumber("ProtocolVersion", unsignedManifest.ProtocolVersion);
            writer.WriteString(
                "MinCompatibleAgentVersion",
                unsignedManifest.MinCompatibleAgentVersion);
            writer.WriteString(
                "Sha256",
                signedArtifacts[ExampleEndpointBundleV1.AgentRole].Sha256);
            writer.WriteString("DeploymentId", unsignedManifest.DeploymentId);
            WriteTimestamp(writer, "BuildTimestamp", unsignedManifest.BuildTimestamp);
            writer.WriteString("BuildId", unsignedManifest.BuildId);
            writer.WriteNumber("ManifestSequence", unsignedManifest.ManifestSequence);
            writer.WriteString("Channel", unsignedManifest.Channel);
            WriteTimestamp(writer, "ExpiresAt", unsignedManifest.ExpiresAt);
            writer.WriteString("Target", unsignedManifest.Target);
            writer.WriteBoolean("Hardened", unsignedManifest.Hardened);
            writer.WriteString("EnrollmentMode", unsignedManifest.EnrollmentMode);
            writer.WriteString("Artifact", ExampleEndpointBundleV1.AgentFileName);
            writer.WriteStartArray("Artifacts");
            WriteArtifact(
                writer,
                ExampleEndpointBundleV1.AgentRole,
                ExampleEndpointBundleV1.AgentFileName,
                signedArtifacts);
            WriteArtifact(
                writer,
                ExampleEndpointBundleV1.MediaRole,
                ExampleEndpointBundleV1.MediaFileName,
                signedArtifacts);
            WriteArtifact(
                writer,
                ExampleEndpointBundleV1.DesktopWorkerRole,
                ExampleEndpointBundleV1.DesktopWorkerFileName,
                signedArtifacts);
            writer.WriteEndArray();
            writer.WriteStartObject("Authenticode");
            writer.WriteString(
                "SignerThumbprint",
                signedArtifacts[ExampleEndpointBundleV1.AgentRole].SignerThumbprint);
            writer.WriteBoolean("Timestamped", true);
            WriteTimestamp(writer, "FinalizedAt", finalizedAt);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        content.WriteByte((byte)'\n');
        return content.ToArray();
    }

    private static void WriteArtifact(
        Utf8JsonWriter writer,
        string role,
        string fileName,
        IReadOnlyDictionary<string, VerifiedAuthenticodeArtifact> signedArtifacts)
    {
        writer.WriteStartObject();
        writer.WriteString("Role", role);
        writer.WriteString("File", fileName);
        writer.WriteString("Sha256", signedArtifacts[role].Sha256);
        writer.WriteEndObject();
    }

    private static void WriteTimestamp(
        Utf8JsonWriter writer,
        string propertyName,
        DateTimeOffset value)
    {
        writer.WriteString(
            propertyName,
            value.ToUniversalTime().ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture));
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.TestProfile.Tests;

internal sealed class ExampleBundleTestData : IProfileArtifactReader
{
    internal const string Version = "5.12.12";
    internal const string SignerThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    internal const string SourceCommit = "0123456789abcdef0123456789abcdef01234567";

    private static readonly JsonSerializerOptions IndentedJson = new()
    {
        WriteIndented = true,
    };

    private readonly Dictionary<string, byte[]> _artifacts;

    private ExampleBundleTestData(
        Dictionary<string, byte[]> artifacts,
        ArtifactSigningRequestV1 request)
    {
        _artifacts = artifacts;
        Request = request;
    }

    internal ArtifactSigningRequestV1 Request { get; }

    internal static ExampleBundleTestData Create(
        Action<JsonObject>? mutateManifest = null,
        string agentPeVersion = Version,
        string agentOriginalFileName = "example-agent.exe",
        bool agentHasSignature = false,
        ushort agentMachine = 0x8664,
        int signerOccurrences = 1,
        Action<JsonObject>? mutateBuildEvidence = null,
        string signerThumbprint = SignerThumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signerThumbprint);
        Dictionary<string, byte[]> artifacts = new(StringComparer.Ordinal)
        {
            [ExampleEndpointBundleV1.AgentFileName] = PortableExecutableTestBuilder.Create(
                agentPeVersion,
                "Example Endpoint Agent",
                "example-endpoint-service",
                agentOriginalFileName,
                agentHasSignature,
                agentMachine,
                string.Concat(Enumerable.Repeat(signerThumbprint, signerOccurrences))),
            [ExampleEndpointBundleV1.MediaFileName] = PortableExecutableTestBuilder.Create(
                Version,
                "Example Endpoint Media",
                "example-media",
                "ExampleMedia.exe",
                hasSignature: false,
                machine: 0x8664,
                overlay: string.Empty),
            [ExampleEndpointBundleV1.DesktopWorkerFileName] =
                PortableExecutableTestBuilder.Create(
                    Version,
                    "Example Endpoint Desktop Worker",
                    "example-desktop-worker",
                    "ExampleDesktopWorker.exe",
                    hasSignature: false,
                    machine: 0x8664,
                    overlay: string.Empty),
        };

        JsonArray manifestArtifacts =
        [
            CreateManifestArtifact(
                ExampleEndpointBundleV1.AgentRole,
                ExampleEndpointBundleV1.AgentFileName,
                Sha256(artifacts[ExampleEndpointBundleV1.AgentFileName])),
            CreateManifestArtifact(
                ExampleEndpointBundleV1.MediaRole,
                ExampleEndpointBundleV1.MediaFileName,
                Sha256(artifacts[ExampleEndpointBundleV1.MediaFileName])),
            CreateManifestArtifact(
                ExampleEndpointBundleV1.DesktopWorkerRole,
                ExampleEndpointBundleV1.DesktopWorkerFileName,
                Sha256(artifacts[ExampleEndpointBundleV1.DesktopWorkerFileName])),
        ];

        JsonObject manifest = new()
        {
            ["AgentVersion"] = Version,
            ["ProtocolVersion"] = 1,
            ["MinCompatibleAgentVersion"] = "5.11.2",
            ["Sha256"] = Sha256(artifacts[ExampleEndpointBundleV1.AgentFileName]),
            ["DeploymentId"] = "e2e-lab",
            ["BuildTimestamp"] = "2026-07-28T09:59:00Z",
            ["BuildId"] = "acceptance-5.12.12-profile-tests",
            ["ManifestSequence"] = 12,
            ["Channel"] = "acceptance",
            ["ExpiresAt"] = "2026-08-23T00:00:00Z",
            ["Target"] = "x86_64-pc-windows-msvc",
            ["Hardened"] = true,
            ["EnrollmentMode"] = "PendingApproval",
            ["ExpectedAuthenticodeSignerThumbprint"] = signerThumbprint,
            ["Artifact"] = ExampleEndpointBundleV1.AgentFileName,
            ["Artifacts"] = manifestArtifacts,
        };
        mutateManifest?.Invoke(manifest);

        artifacts[ExampleEndpointBundleV1.ManifestFileName] =
            JsonSerializer.SerializeToUtf8Bytes(manifest, IndentedJson);
        JsonObject buildEvidence = CreateBuildEvidence(artifacts);
        mutateBuildEvidence?.Invoke(buildEvidence);
        artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName] =
            JsonSerializer.SerializeToUtf8Bytes(buildEvidence, IndentedJson);

        ArtifactSigningRequestV1 request = CreateRequest(artifacts);
        return new ExampleBundleTestData(artifacts, request);
    }

    internal ExampleBundleTestData WithManifestBytes(byte[] manifestBytes)
    {
        ArgumentNullException.ThrowIfNull(manifestBytes);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        artifacts[ExampleEndpointBundleV1.ManifestFileName] = manifestBytes;
        RebindBuildEvidenceArtifacts(artifacts);
        return new ExampleBundleTestData(artifacts, CreateRequest(artifacts));
    }

    internal ExampleBundleTestData WithBuildEvidence(
        Action<JsonObject> mutateBuildEvidence)
    {
        ArgumentNullException.ThrowIfNull(mutateBuildEvidence);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        JsonObject buildEvidence = JsonNode.Parse(
            artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName])!.AsObject();
        mutateBuildEvidence(buildEvidence);
        artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName] =
            JsonSerializer.SerializeToUtf8Bytes(buildEvidence, IndentedJson);
        return new ExampleBundleTestData(artifacts, CreateRequest(artifacts));
    }

    internal ExampleBundleTestData WithBuildEvidenceBytes(byte[] evidenceBytes)
    {
        ArgumentNullException.ThrowIfNull(evidenceBytes);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName] = evidenceBytes;
        return new ExampleBundleTestData(artifacts, CreateRequest(artifacts));
    }

    internal ExampleBundleTestData WithManifestBytesPreservingRequest(byte[] manifestBytes)
    {
        ArgumentNullException.ThrowIfNull(manifestBytes);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        artifacts[ExampleEndpointBundleV1.ManifestFileName] = manifestBytes;
        return new ExampleBundleTestData(artifacts, Request);
    }

    internal ExampleBundleTestData WithArtifactBytes(
        IReadOnlyDictionary<string, byte[]> replacements)
    {
        ArgumentNullException.ThrowIfNull(replacements);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        foreach ((string fileName, byte[] content) in replacements)
        {
            if (!artifacts.ContainsKey(fileName) || content is null)
            {
                throw new ArgumentException(
                    "Replacement artifacts must name existing files with non-null content.",
                    nameof(replacements));
            }

            artifacts[fileName] = content.ToArray();
        }

        return new ExampleBundleTestData(artifacts, Request);
    }

    internal ExampleBundleTestData WithAllPayloadsStructurallySigned()
    {
        return WithPayloadsStructurallySigned(
            ExampleEndpointBundleV1.AgentFileName,
            ExampleEndpointBundleV1.MediaFileName,
            ExampleEndpointBundleV1.DesktopWorkerFileName);
    }

    internal ExampleBundleTestData WithPayloadsStructurallySigned(
        params string[] fileNames)
    {
        ArgumentNullException.ThrowIfNull(fileNames);
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        foreach (string fileName in fileNames)
        {
            artifacts[fileName] =
                PortableExecutableTestBuilder.AddEmbeddedSignature(artifacts[fileName]);
        }

        return new ExampleBundleTestData(artifacts, Request);
    }

    internal ExampleBundleTestData WithRequest(ArtifactSigningRequestV1 request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new ExampleBundleTestData(CopyArtifacts(), request);
    }

    internal ExampleBundleTestData WithUnboundArtifactMutation(string fileName)
    {
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        byte[] mutated = [.. artifacts[fileName], 0x01];
        artifacts[fileName] = mutated;
        return new ExampleBundleTestData(artifacts, Request);
    }

    internal ExampleBundleTestData WithUnboundSameSizeArtifactMutation(string fileName)
    {
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        byte[] mutated = artifacts[fileName];
        mutated[^1] ^= 0x01;
        return new ExampleBundleTestData(artifacts, Request);
    }

    internal ExampleBundleTestData WithoutArtifact(string fileName)
    {
        Dictionary<string, byte[]> artifacts = CopyArtifacts();
        _ = artifacts.Remove(fileName);
        return new ExampleBundleTestData(artifacts, Request);
    }

    public Stream OpenRead(string fileName)
    {
        if (!_artifacts.TryGetValue(fileName, out byte[]? content))
        {
            throw new FileNotFoundException();
        }

        return new MemoryStream(content, writable: false);
    }

    internal byte[] ReadAllBytes(string fileName)
    {
        if (!_artifacts.TryGetValue(fileName, out byte[]? content))
        {
            throw new FileNotFoundException();
        }

        return content.ToArray();
    }

    private static ArtifactSigningRequestV1 CreateRequest(
        Dictionary<string, byte[]> artifacts)
    {
        return new ArtifactSigningRequestV1(
            Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
            ExampleEndpointBundleV1.ProjectId,
            ExampleEndpointBundleV1.ProfileId,
            ExampleEndpointBundleV1.ProfileVersion,
            ExampleEndpointBundleV1.SourceRepository,
            SourceCommit,
            Version,
            new DateTimeOffset(2026, 7, 28, 10, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 7, 28, 10, 15, 0, TimeSpan.Zero),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            ExampleEndpointBundleV1.SignerPolicyId,
            ExampleEndpointBundleV1.TimestampPolicyId,
            [
                CreateRequestArtifact(
                    ExampleEndpointBundleV1.ManifestRole,
                    ExampleEndpointBundleV1.ManifestFileName,
                    artifacts[ExampleEndpointBundleV1.ManifestFileName]),
                CreateRequestArtifact(
                    ExampleEndpointBundleV1.BuildEvidenceRole,
                    ExampleEndpointBundleV1.BuildEvidenceFileName,
                    artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName]),
                CreateRequestArtifact(
                    ExampleEndpointBundleV1.AgentRole,
                    ExampleEndpointBundleV1.AgentFileName,
                    artifacts[ExampleEndpointBundleV1.AgentFileName]),
                CreateRequestArtifact(
                    ExampleEndpointBundleV1.MediaRole,
                    ExampleEndpointBundleV1.MediaFileName,
                    artifacts[ExampleEndpointBundleV1.MediaFileName]),
                CreateRequestArtifact(
                    ExampleEndpointBundleV1.DesktopWorkerRole,
                    ExampleEndpointBundleV1.DesktopWorkerFileName,
                    artifacts[ExampleEndpointBundleV1.DesktopWorkerFileName]),
            ]);
    }

    private static JsonObject CreateBuildEvidence(
        Dictionary<string, byte[]> artifacts)
    {
        return new JsonObject
        {
            ["Format"] = ExampleEndpointBundleV1.BuildEvidenceFormat,
            ["SourceRepository"] = ExampleEndpointBundleV1.SourceRepository,
            ["SourceCommit"] = SourceCommit,
            ["SourceTreeState"] = "Clean",
            ["BuildRecipe"] = "scripts/build-provisioned-agent.sh",
            ["BuildRecipeSha256"] = new string('1', 64),
            ["DependencyLock"] = "Cargo.lock",
            ["DependencyLockSha256"] = new string('2', 64),
            ["ToolchainFile"] = "rust-toolchain.toml",
            ["ToolchainFileSha256"] = new string('3', 64),
            ["Target"] = "x86_64-pc-windows-msvc",
            ["BuildConfiguration"] = "Release",
            ["DefaultFeaturesEnabled"] = false,
            ["DeploymentEnrollmentKeyPresent"] = false,
            ["ProvisioningMaterial"] = "PublicTrustOnly",
            ["ProvisioningInputSha256"] = new string('4', 64),
            ["RootSpkiPinCount"] = 1,
            ["UpdateManifestPublicKeyCount"] = 1,
            ["CommandAuthorityPublicKeyCount"] = 1,
            ["RelayGrantPublicKeyPresent"] = true,
            ["ReleaseVersion"] = Version,
            ["BuildId"] = "acceptance-5.12.12-profile-tests",
            ["BuildTimestamp"] = "2026-07-28T09:59:00Z",
            ["Artifacts"] = CreateBuildEvidenceArtifacts(artifacts),
        };
    }

    private static JsonArray CreateBuildEvidenceArtifacts(
        Dictionary<string, byte[]> artifacts)
    {
        return
        [
            CreateBuildEvidenceArtifact(
                ExampleEndpointBundleV1.ManifestRole,
                ExampleEndpointBundleV1.ManifestFileName,
                artifacts[ExampleEndpointBundleV1.ManifestFileName]),
            CreateBuildEvidenceArtifact(
                ExampleEndpointBundleV1.AgentRole,
                ExampleEndpointBundleV1.AgentFileName,
                artifacts[ExampleEndpointBundleV1.AgentFileName]),
            CreateBuildEvidenceArtifact(
                ExampleEndpointBundleV1.MediaRole,
                ExampleEndpointBundleV1.MediaFileName,
                artifacts[ExampleEndpointBundleV1.MediaFileName]),
            CreateBuildEvidenceArtifact(
                ExampleEndpointBundleV1.DesktopWorkerRole,
                ExampleEndpointBundleV1.DesktopWorkerFileName,
                artifacts[ExampleEndpointBundleV1.DesktopWorkerFileName]),
        ];
    }

    private static JsonObject CreateBuildEvidenceArtifact(
        string role,
        string fileName,
        byte[] content)
    {
        return new JsonObject
        {
            ["Role"] = role,
            ["File"] = fileName,
            ["Size"] = content.LongLength,
            ["Sha256"] = Sha256(content),
        };
    }

    private static void RebindBuildEvidenceArtifacts(
        Dictionary<string, byte[]> artifacts)
    {
        JsonObject buildEvidence = JsonNode.Parse(
            artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName])!.AsObject();
        buildEvidence["Artifacts"] = CreateBuildEvidenceArtifacts(artifacts);
        artifacts[ExampleEndpointBundleV1.BuildEvidenceFileName] =
            JsonSerializer.SerializeToUtf8Bytes(buildEvidence, IndentedJson);
    }

    private static RequestArtifactV1 CreateRequestArtifact(
        string role,
        string fileName,
        byte[] content)
    {
        return new RequestArtifactV1(role, fileName, content.LongLength, Sha256(content));
    }

    private static JsonObject CreateManifestArtifact(
        string role,
        string fileName,
        string sha256)
    {
        return new JsonObject
        {
            ["Role"] = role,
            ["File"] = fileName,
            ["Sha256"] = sha256,
        };
    }

    private static string Sha256(byte[] content)
    {
        return Convert.ToHexStringLower(SHA256.HashData(content));
    }

    private Dictionary<string, byte[]> CopyArtifacts()
    {
        return _artifacts.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.Ordinal);
    }
}

internal static class PortableExecutableTestBuilder
{
    private const int PeOffset = 0x80;
    private const int OptionalHeaderBytes = 240;
    private const int RawOffset = 0x200;
    private const int ResourceRva = 0x1000;
    private const int VersionOffsetInResource = 88;

    internal static byte[] Create(
        string version,
        string fileDescription,
        string internalName,
        string originalFileName,
        bool hasSignature,
        ushort machine,
        string overlay)
    {
        byte[] versionResource = CreateVersionResource(
            version,
            fileDescription,
            internalName,
            originalFileName);
        int resourceBytes = checked(VersionOffsetInResource + versionResource.Length);
        int rawBytes = Align(resourceBytes, 0x200);
        byte[] overlayBytes = Encoding.ASCII.GetBytes(overlay);
        byte[] pe = new byte[checked(RawOffset + rawBytes + overlayBytes.Length)];

        BinaryPrimitives.WriteUInt16LittleEndian(pe, 0x5a4d);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x3c), PeOffset);
        "PE\0\0"u8.CopyTo(pe.AsSpan(PeOffset));

        int coff = PeOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coff), machine);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coff + 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coff + 16), OptionalHeaderBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coff + 18), 0x22);

        int optional = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(optional), 0x020b);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 32), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 36), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 56), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 60), RawOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(optional + 68), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 108), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optional + 112 + 16), ResourceRva);
        BinaryPrimitives.WriteUInt32LittleEndian(
            pe.AsSpan(optional + 112 + 20),
            checked((uint)resourceBytes));
        int section = optional + OptionalHeaderBytes;
        Encoding.ASCII.GetBytes(".rsrc\0\0\0").CopyTo(pe.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(
            pe.AsSpan(section + 8),
            checked((uint)resourceBytes));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 12), ResourceRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 16), checked((uint)rawBytes));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 20), RawOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 36), 0x40000040);

        Span<byte> resources = pe.AsSpan(RawOffset, rawBytes);
        WriteResourceDirectory(resources, versionResource.Length);
        versionResource.CopyTo(resources[VersionOffsetInResource..]);
        overlayBytes.CopyTo(pe.AsSpan(RawOffset + rawBytes));
        return hasSignature ? AddEmbeddedSignature(pe) : pe;
    }

    internal static byte[] AddEmbeddedSignature(byte[] unsignedPe)
    {
        ArgumentNullException.ThrowIfNull(unsignedPe);

        int certificateOffset = Align(unsignedPe.Length, 8);
        const int certificateBytes = 8;
        byte[] signedPe = new byte[checked(certificateOffset + certificateBytes)];
        unsignedPe.CopyTo(signedPe, 0);

        int certificateDirectory = PeOffset + 4 + 20 + 112 + 32;
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedPe.AsSpan(certificateDirectory),
            checked((uint)certificateOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedPe.AsSpan(certificateDirectory + 4),
            certificateBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedPe.AsSpan(certificateOffset),
            certificateBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(
            signedPe.AsSpan(certificateOffset + 4),
            0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(
            signedPe.AsSpan(certificateOffset + 6),
            0x0002);
        return signedPe;
    }

    private static void WriteResourceDirectory(
        Span<byte> resources,
        int versionResourceLength)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(resources[14..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[16..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[20..], 0x80000018);

        BinaryPrimitives.WriteUInt16LittleEndian(resources[38..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[40..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[44..], 0x80000030);

        BinaryPrimitives.WriteUInt16LittleEndian(resources[62..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[64..], 0x0409);
        BinaryPrimitives.WriteUInt32LittleEndian(resources[68..], 72);

        BinaryPrimitives.WriteUInt32LittleEndian(
            resources[72..],
            ResourceRva + VersionOffsetInResource);
        BinaryPrimitives.WriteUInt32LittleEndian(
            resources[76..],
            checked((uint)versionResourceLength));
    }

    private static byte[] CreateVersionResource(
        string version,
        string fileDescription,
        string internalName,
        string originalFileName)
    {
        byte[] stringTable = CreateBlock(
            "040904b0",
            valueLength: 0,
            type: 1,
            value: [],
            [
                CreateString("CompanyName", "Example Organization"),
                CreateString("FileDescription", fileDescription),
                CreateString("FileVersion", version),
                CreateString("InternalName", internalName),
                CreateString("OriginalFilename", originalFileName),
                CreateString("ProductName", "Example Endpoint Agent"),
                CreateString("ProductVersion", version),
            ]);
        byte[] stringFileInformation = CreateBlock(
            "StringFileInfo",
            valueLength: 0,
            type: 1,
            value: [],
            [stringTable]);

        string[] versionParts = version.Split('-', 2)[0].Split('.');
        ushort major = ushort.Parse(versionParts[0], System.Globalization.CultureInfo.InvariantCulture);
        ushort minor = ushort.Parse(versionParts[1], System.Globalization.CultureInfo.InvariantCulture);
        ushort patch = ushort.Parse(versionParts[2], System.Globalization.CultureInfo.InvariantCulture);
        byte[] fixedInformation = new byte[52];
        WriteUInt32(fixedInformation, 0, 0xfeef04bd);
        WriteUInt32(fixedInformation, 4, 0x00010000);
        WriteUInt32(fixedInformation, 8, ((uint)major << 16) | minor);
        WriteUInt32(fixedInformation, 12, (uint)patch << 16);
        WriteUInt32(fixedInformation, 16, ((uint)major << 16) | minor);
        WriteUInt32(fixedInformation, 20, (uint)patch << 16);
        WriteUInt32(fixedInformation, 24, 0x3f);
        WriteUInt32(fixedInformation, 32, 0x00040004);
        WriteUInt32(fixedInformation, 36, 1);

        return CreateBlock(
            "VS_VERSION_INFO",
            valueLength: 52,
            type: 0,
            fixedInformation,
            [stringFileInformation]);
    }

    private static byte[] CreateString(string key, string value)
    {
        byte[] encoded = Encoding.Unicode.GetBytes(value + '\0');
        return CreateBlock(
            key,
            checked((ushort)(value.Length + 1)),
            type: 1,
            encoded,
            []);
    }

    private static byte[] CreateBlock(
        string key,
        ushort valueLength,
        ushort type,
        byte[] value,
        IReadOnlyList<byte[]> children)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream, Encoding.Unicode, leaveOpen: true);
        writer.Write((ushort)0);
        writer.Write(valueLength);
        writer.Write(type);
        writer.Write(Encoding.Unicode.GetBytes(key + '\0'));
        Pad4(stream, writer);
        writer.Write(value);
        Pad4(stream, writer);
        foreach (byte[] child in children)
        {
            writer.Write(child);
            Pad4(stream, writer);
        }

        writer.Flush();
        byte[] result = stream.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(
            result,
            checked((ushort)result.Length));
        return result;
    }

    private static void Pad4(Stream stream, BinaryWriter writer)
    {
        while (stream.Length % 4 is not 0)
        {
            writer.Write((byte)0);
        }
    }

    private static void WriteUInt32(byte[] target, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(target.AsSpan(offset), value);
    }

    private static int Align(int value, int alignment)
    {
        return checked((value + alignment - 1) & ~(alignment - 1));
    }
}

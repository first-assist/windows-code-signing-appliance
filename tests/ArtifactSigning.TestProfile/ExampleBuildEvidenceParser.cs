using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ArtifactSigning.TestProfile;

internal sealed record ExampleBuildEvidenceParseResult(
    ExampleBuildEvidence? Evidence,
    bool IsMalformed)
{
    internal bool IsSuccess => !IsMalformed && Evidence is not null;
}

internal static class ExampleBuildEvidenceParser
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly HashSet<string> RootProperties = new(
        [
            "Format",
            "SourceRepository",
            "SourceCommit",
            "SourceTreeState",
            "BuildRecipe",
            "BuildRecipeSha256",
            "DependencyLock",
            "DependencyLockSha256",
            "ToolchainFile",
            "ToolchainFileSha256",
            "Target",
            "BuildConfiguration",
            "DefaultFeaturesEnabled",
            "DeploymentEnrollmentKeyPresent",
            "ProvisioningMaterial",
            "ProvisioningInputSha256",
            "RootSpkiPinCount",
            "UpdateManifestPublicKeyCount",
            "CommandAuthorityPublicKeyCount",
            "RelayGrantPublicKeyPresent",
            "ReleaseVersion",
            "BuildId",
            "BuildTimestamp",
            "Artifacts",
        ],
        StringComparer.Ordinal);

    private static readonly HashSet<string> ArtifactProperties = new(
        ["Role", "File", "Size", "Sha256"],
        StringComparer.Ordinal);

    internal static ExampleBuildEvidenceParseResult Parse(
        ReadOnlyMemory<byte> evidenceJson)
    {
        if (!CanParse(evidenceJson))
        {
            return Failure();
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                evidenceJson,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 5,
                });
            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object
                || !HasExactProperties(root, RootProperties)
                || !TryGetString(root, "Format", out string format)
                || !TryGetString(
                    root,
                    "SourceRepository",
                    out string sourceRepository)
                || !TryGetString(root, "SourceCommit", out string sourceCommit)
                || !TryGetString(
                    root,
                    "SourceTreeState",
                    out string sourceTreeState)
                || !TryGetString(root, "BuildRecipe", out string buildRecipe)
                || !TryGetString(
                    root,
                    "BuildRecipeSha256",
                    out string buildRecipeSha256)
                || !TryGetString(root, "DependencyLock", out string dependencyLock)
                || !TryGetString(
                    root,
                    "DependencyLockSha256",
                    out string dependencyLockSha256)
                || !TryGetString(root, "ToolchainFile", out string toolchainFile)
                || !TryGetString(
                    root,
                    "ToolchainFileSha256",
                    out string toolchainFileSha256)
                || !TryGetString(root, "Target", out string target)
                || !TryGetString(
                    root,
                    "BuildConfiguration",
                    out string buildConfiguration)
                || !TryGetBoolean(
                    root,
                    "DefaultFeaturesEnabled",
                    out bool defaultFeaturesEnabled)
                || !TryGetBoolean(
                    root,
                    "DeploymentEnrollmentKeyPresent",
                    out bool deploymentEnrollmentKeyPresent)
                || !TryGetString(
                    root,
                    "ProvisioningMaterial",
                    out string provisioningMaterial)
                || !TryGetString(
                    root,
                    "ProvisioningInputSha256",
                    out string provisioningInputSha256)
                || !TryGetInt32(
                    root,
                    "RootSpkiPinCount",
                    out int rootSpkiPinCount)
                || !TryGetInt32(
                    root,
                    "UpdateManifestPublicKeyCount",
                    out int updateManifestPublicKeyCount)
                || !TryGetInt32(
                    root,
                    "CommandAuthorityPublicKeyCount",
                    out int commandAuthorityPublicKeyCount)
                || !TryGetBoolean(
                    root,
                    "RelayGrantPublicKeyPresent",
                    out bool relayGrantPublicKeyPresent)
                || !TryGetString(root, "ReleaseVersion", out string releaseVersion)
                || !TryGetString(root, "BuildId", out string buildId)
                || !TryGetString(
                    root,
                    "BuildTimestamp",
                    out string buildTimestampText)
                || !TryParseTimestamp(
                    buildTimestampText,
                    out DateTimeOffset buildTimestamp)
                || !IsCanonicalSourceCommit(sourceCommit)
                || !IsNonZeroLowerSha256(buildRecipeSha256)
                || !IsNonZeroLowerSha256(dependencyLockSha256)
                || !IsNonZeroLowerSha256(toolchainFileSha256)
                || !IsNonZeroLowerSha256(provisioningInputSha256)
                || !TryParseArtifacts(
                    root,
                    out IReadOnlyList<ExampleBuildEvidenceArtifact>? artifacts))
            {
                return Failure();
            }

            return new ExampleBuildEvidenceParseResult(
                new ExampleBuildEvidence(
                    format,
                    sourceRepository,
                    sourceCommit,
                    sourceTreeState,
                    buildRecipe,
                    buildRecipeSha256,
                    dependencyLock,
                    dependencyLockSha256,
                    toolchainFile,
                    toolchainFileSha256,
                    target,
                    buildConfiguration,
                    defaultFeaturesEnabled,
                    deploymentEnrollmentKeyPresent,
                    provisioningMaterial,
                    provisioningInputSha256,
                    rootSpkiPinCount,
                    updateManifestPublicKeyCount,
                    commandAuthorityPublicKeyCount,
                    relayGrantPublicKeyPresent,
                    releaseVersion,
                    buildId,
                    buildTimestamp,
                    artifacts!),
                IsMalformed: false);
        }
        catch (JsonException)
        {
            return Failure();
        }
    }

    private static bool TryParseArtifacts(
        JsonElement root,
        out IReadOnlyList<ExampleBuildEvidenceArtifact>? artifacts)
    {
        artifacts = null;
        if (!root.TryGetProperty("Artifacts", out JsonElement array)
            || array.ValueKind is not JsonValueKind.Array
            || array.GetArrayLength() is not 4)
        {
            return false;
        }

        List<ExampleBuildEvidenceArtifact> parsed = new(4);
        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> files = new(StringComparer.Ordinal);
        foreach (JsonElement element in array.EnumerateArray())
        {
            if (element.ValueKind is not JsonValueKind.Object
                || !HasExactProperties(element, ArtifactProperties)
                || !TryGetString(element, "Role", out string role)
                || !TryGetString(element, "File", out string file)
                || !TryGetInt64(element, "Size", out long size)
                || size <= 0
                || !TryGetString(element, "Sha256", out string sha256)
                || !IsLowerSha256(sha256)
                || !roles.Add(role)
                || !files.Add(file)
                || !IsExpectedArtifact(role, file))
            {
                return false;
            }

            parsed.Add(new ExampleBuildEvidenceArtifact(role, file, size, sha256));
        }

        if (!roles.SetEquals(
                [
                    ExampleEndpointBundleV1.ManifestRole,
                    ExampleEndpointBundleV1.AgentRole,
                    ExampleEndpointBundleV1.MediaRole,
                    ExampleEndpointBundleV1.DesktopWorkerRole,
                ]))
        {
            return false;
        }

        artifacts = parsed.AsReadOnly();
        return true;
    }

    private static bool CanParse(ReadOnlyMemory<byte> json)
    {
        ReadOnlySpan<byte> span = json.Span;
        return !json.IsEmpty
            && json.Length <= ExampleEndpointBundleV1.MaximumBuildEvidenceBytes
            && !(span.Length >= 3
                && span[0] is 0xef
                && span[1] is 0xbb
                && span[2] is 0xbf)
            && HasCanonicalEncodingAndPropertyNames(span);
    }

    private static bool HasCanonicalEncodingAndPropertyNames(
        ReadOnlySpan<byte> json)
    {
        try
        {
            _ = StrictUtf8.GetCharCount(json);
            Utf8JsonReader reader = new(
                json,
                new JsonReaderOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 5,
                });
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName
                    && reader.ValueIsEscaped)
                {
                    return false;
                }
            }

            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasExactProperties(
        JsonElement element,
        HashSet<string> expected)
    {
        HashSet<string> observed = new(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!expected.Contains(property.Name) || !observed.Add(property.Name))
            {
                return false;
            }
        }

        return observed.Count == expected.Count;
    }

    private static bool TryGetString(
        JsonElement element,
        string name,
        out string value)
    {
        if (element.TryGetProperty(name, out JsonElement property)
            && property.ValueKind is JsonValueKind.String
            && property.GetString() is string parsed)
        {
            value = parsed;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetBoolean(
        JsonElement element,
        string name,
        out bool value)
    {
        if (element.TryGetProperty(name, out JsonElement property)
            && property.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            value = property.GetBoolean();
            return true;
        }

        value = false;
        return false;
    }

    private static bool TryGetInt32(
        JsonElement element,
        string name,
        out int value)
    {
        if (element.TryGetProperty(name, out JsonElement property)
            && property.ValueKind is JsonValueKind.Number
            && property.TryGetInt32(out value)
            && string.Equals(
                property.GetRawText(),
                value.ToString(CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            return true;
        }

        value = 0;
        return false;
    }

    private static bool TryGetInt64(
        JsonElement element,
        string name,
        out long value)
    {
        if (element.TryGetProperty(name, out JsonElement property)
            && property.ValueKind is JsonValueKind.Number
            && property.TryGetInt64(out value)
            && string.Equals(
                property.GetRawText(),
                value.ToString(CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            return true;
        }

        value = 0;
        return false;
    }

    private static bool TryParseTimestamp(
        string value,
        out DateTimeOffset timestamp)
    {
        return DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);
    }

    private static bool IsCanonicalSourceCommit(string value)
    {
        return value.Length is 40 or 64
            && value.Any(character => character is not '0')
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static bool IsNonZeroLowerSha256(string value)
    {
        return IsLowerSha256(value)
            && value.Any(character => character is not '0');
    }

    private static bool IsLowerSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static bool IsExpectedArtifact(string role, string file)
    {
        return role switch
        {
            ExampleEndpointBundleV1.ManifestRole =>
                file is ExampleEndpointBundleV1.ManifestFileName,
            ExampleEndpointBundleV1.AgentRole =>
                file is ExampleEndpointBundleV1.AgentFileName,
            ExampleEndpointBundleV1.MediaRole =>
                file is ExampleEndpointBundleV1.MediaFileName,
            ExampleEndpointBundleV1.DesktopWorkerRole =>
                file is ExampleEndpointBundleV1.DesktopWorkerFileName,
            _ => false,
        };
    }

    private static ExampleBuildEvidenceParseResult Failure()
    {
        return new ExampleBuildEvidenceParseResult(null, IsMalformed: true);
    }
}

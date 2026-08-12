using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ArtifactSigning.TestProfile;

internal enum ExampleManifestError
{
    None,
    Malformed,
    InvalidShape,
    InvalidValue,
}

internal sealed record ExampleUnsignedManifestParseResult(
    ExampleUnsignedManifest? Manifest,
    ExampleManifestError Error)
{
    internal bool IsSuccess =>
        Error is ExampleManifestError.None && Manifest is not null;
}

internal sealed record ExampleFinalizedManifestParseResult(
    ExampleFinalizedManifest? Manifest,
    ExampleManifestError Error)
{
    internal bool IsSuccess =>
        Error is ExampleManifestError.None && Manifest is not null;
}

internal static class ExampleManifestParser
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly HashSet<string> CommonRootProperties = new(
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
        ],
        StringComparer.Ordinal);

    private static readonly HashSet<string> UnsignedRootProperties =
        WithAdditionalProperty(
            CommonRootProperties,
            "ExpectedAuthenticodeSignerThumbprint");

    private static readonly HashSet<string> FinalizedRootProperties =
        WithAdditionalProperty(CommonRootProperties, "Authenticode");

    private static readonly HashSet<string> ArtifactProperties = new(
        ["Role", "File", "Sha256"],
        StringComparer.Ordinal);

    private static readonly HashSet<string> AuthenticodeProperties = new(
        ["SignerThumbprint", "Timestamped", "FinalizedAt"],
        StringComparer.Ordinal);

    internal static ExampleUnsignedManifestParseResult ParseUnsigned(
        ReadOnlyMemory<byte> manifestJson)
    {
        if (!CanParse(manifestJson))
        {
            return UnsignedFailure(ExampleManifestError.Malformed);
        }

        try
        {
            using JsonDocument document = ParseDocument(manifestJson);
            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object
                || !HasExactProperties(root, UnsignedRootProperties)
                || !TryParseCommon(root, out ParsedCommonManifest? common)
                || !TryGetString(
                    root,
                    "ExpectedAuthenticodeSignerThumbprint",
                    out string expectedSigner)
                || !IsUpperHexThumbprint(expectedSigner))
            {
                return UnsignedFailure(ExampleManifestError.InvalidShape);
            }

            return new ExampleUnsignedManifestParseResult(
                new ExampleUnsignedManifest(
                    common!.AgentVersion,
                    common.ProtocolVersion,
                    common.MinCompatibleAgentVersion,
                    common.Sha256,
                    common.DeploymentId,
                    common.BuildTimestamp,
                    common.BuildId,
                    common.ManifestSequence,
                    common.Channel,
                    common.ExpiresAt,
                    common.Target,
                    common.Hardened,
                    common.EnrollmentMode,
                    expectedSigner,
                    common.Artifact,
                    common.Artifacts),
                ExampleManifestError.None);
        }
        catch (JsonException)
        {
            return UnsignedFailure(ExampleManifestError.Malformed);
        }
    }

    internal static ExampleFinalizedManifestParseResult ParseFinalized(
        ReadOnlyMemory<byte> manifestJson)
    {
        if (!CanParse(manifestJson))
        {
            return FinalizedFailure(ExampleManifestError.Malformed);
        }

        try
        {
            using JsonDocument document = ParseDocument(manifestJson);
            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object
                || !HasExactProperties(root, FinalizedRootProperties)
                || !TryParseCommon(root, out ParsedCommonManifest? common)
                || !TryParseAuthenticode(
                    root,
                    out ExampleManifestAuthenticode? authenticode))
            {
                return FinalizedFailure(ExampleManifestError.InvalidShape);
            }

            return new ExampleFinalizedManifestParseResult(
                new ExampleFinalizedManifest(
                    common!.AgentVersion,
                    common.ProtocolVersion,
                    common.MinCompatibleAgentVersion,
                    common.Sha256,
                    common.DeploymentId,
                    common.BuildTimestamp,
                    common.BuildId,
                    common.ManifestSequence,
                    common.Channel,
                    common.ExpiresAt,
                    common.Target,
                    common.Hardened,
                    common.EnrollmentMode,
                    common.Artifact,
                    common.Artifacts,
                    authenticode!),
                ExampleManifestError.None);
        }
        catch (JsonException)
        {
            return FinalizedFailure(ExampleManifestError.Malformed);
        }
    }

    private static bool TryParseCommon(
        JsonElement root,
        out ParsedCommonManifest? common)
    {
        common = null;
        if (!TryGetString(root, "AgentVersion", out string agentVersion)
            || !TryGetInt32(root, "ProtocolVersion", out int protocolVersion)
            || !TryGetString(
                root,
                "MinCompatibleAgentVersion",
                out string minimumVersion)
            || !TryGetString(root, "Sha256", out string sha256)
            || !TryGetString(root, "DeploymentId", out string deploymentId)
            || !TryGetString(root, "BuildTimestamp", out string buildTimestampText)
            || !TryGetString(root, "BuildId", out string buildId)
            || !TryGetInt64(root, "ManifestSequence", out long manifestSequence)
            || !TryGetString(root, "Channel", out string channel)
            || !TryGetString(root, "ExpiresAt", out string expiresAtText)
            || !TryGetString(root, "Target", out string target)
            || !TryGetBoolean(root, "Hardened", out bool hardened)
            || !TryGetString(root, "EnrollmentMode", out string enrollmentMode)
            || !TryGetString(root, "Artifact", out string artifact)
            || !TryParseTimestamp(buildTimestampText, out DateTimeOffset buildTimestamp)
            || !TryParseTimestamp(expiresAtText, out DateTimeOffset expiresAt)
            || !IsLowerHexSha256(sha256)
            || !TryParseArtifacts(
                root,
                out IReadOnlyList<ExampleManifestArtifact>? artifacts))
        {
            return false;
        }

        common = new ParsedCommonManifest(
            agentVersion,
            protocolVersion,
            minimumVersion,
            sha256,
            deploymentId,
            buildTimestamp,
            buildId,
            manifestSequence,
            channel,
            expiresAt,
            target,
            hardened,
            enrollmentMode,
            artifact,
            artifacts!);
        return true;
    }

    private static bool TryParseAuthenticode(
        JsonElement root,
        out ExampleManifestAuthenticode? authenticode)
    {
        authenticode = null;
        if (!root.TryGetProperty("Authenticode", out JsonElement value)
            || value.ValueKind is not JsonValueKind.Object
            || !HasExactProperties(value, AuthenticodeProperties)
            || !TryGetString(value, "SignerThumbprint", out string signerThumbprint)
            || !TryGetBoolean(value, "Timestamped", out bool timestamped)
            || !TryGetString(value, "FinalizedAt", out string finalizedAtText)
            || !IsUpperHexThumbprint(signerThumbprint)
            || !TryParseTimestamp(finalizedAtText, out DateTimeOffset finalizedAt))
        {
            return false;
        }

        authenticode = new ExampleManifestAuthenticode(
            signerThumbprint,
            timestamped,
            finalizedAt);
        return true;
    }

    private static bool TryParseArtifacts(
        JsonElement root,
        out IReadOnlyList<ExampleManifestArtifact>? artifacts)
    {
        artifacts = null;
        if (!root.TryGetProperty("Artifacts", out JsonElement array)
            || array.ValueKind is not JsonValueKind.Array
            || array.GetArrayLength() is not 3)
        {
            return false;
        }

        List<ExampleManifestArtifact> parsed = new(3);
        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> files = new(StringComparer.Ordinal);
        foreach (JsonElement element in array.EnumerateArray())
        {
            if (element.ValueKind is not JsonValueKind.Object
                || !HasExactProperties(element, ArtifactProperties)
                || !TryGetString(element, "Role", out string role)
                || !TryGetString(element, "File", out string file)
                || !TryGetString(element, "Sha256", out string sha256)
                || !IsLowerHexSha256(sha256)
                || !roles.Add(role)
                || !files.Add(file)
                || !IsExpectedArtifact(role, file))
            {
                return false;
            }

            parsed.Add(new ExampleManifestArtifact(role, file, sha256));
        }

        if (!roles.SetEquals(
                [
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
        return !json.IsEmpty
            && json.Length <= ExampleEndpointBundleV1.MaximumManifestBytes
            && HasCanonicalEncodingAndPropertyNames(json.Span);
    }

    private static JsonDocument ParseDocument(ReadOnlyMemory<byte> json)
    {
        return JsonDocument.Parse(
            json,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 6,
            });
    }

    private static bool HasCanonicalEncodingAndPropertyNames(ReadOnlySpan<byte> json)
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
                    MaxDepth = 6,
                });
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName && reader.ValueIsEscaped)
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

    private static bool TryParseTimestamp(string value, out DateTimeOffset timestamp)
    {
        return DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);
    }

    private static bool IsLowerHexSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static bool IsUpperHexThumbprint(string value)
    {
        return value.Length is 40
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    private static bool IsExpectedArtifact(string role, string file)
    {
        return role switch
        {
            ExampleEndpointBundleV1.AgentRole =>
                file is ExampleEndpointBundleV1.AgentFileName,
            ExampleEndpointBundleV1.MediaRole =>
                file is ExampleEndpointBundleV1.MediaFileName,
            ExampleEndpointBundleV1.DesktopWorkerRole =>
                file is ExampleEndpointBundleV1.DesktopWorkerFileName,
            _ => false,
        };
    }

    private static HashSet<string> WithAdditionalProperty(
        IEnumerable<string> properties,
        string additionalProperty)
    {
        HashSet<string> result = new(properties, StringComparer.Ordinal)
        {
            additionalProperty,
        };
        return result;
    }

    private static ExampleUnsignedManifestParseResult UnsignedFailure(
        ExampleManifestError error)
    {
        return new ExampleUnsignedManifestParseResult(null, error);
    }

    private static ExampleFinalizedManifestParseResult FinalizedFailure(
        ExampleManifestError error)
    {
        return new ExampleFinalizedManifestParseResult(null, error);
    }

    private sealed record ParsedCommonManifest(
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
        IReadOnlyList<ExampleManifestArtifact> Artifacts);
}

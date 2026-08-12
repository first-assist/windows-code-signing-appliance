using System.Text.Json;

namespace ArtifactSigning.Protocol;

public enum RequestJsonError
{
    None,
    Empty,
    TooLarge,
    Malformed,
    NonCanonicalPropertyName,
    RootNotObject,
    UnknownProperty,
    DuplicateProperty,
    MissingProperty,
    InvalidPropertyType,
    InvalidPropertyValue,
    TooManyArtifacts,
    DuplicateArtifact,
}

public sealed record RequestJsonParseResult(
    ArtifactSigningRequestV1? Request,
    RequestJsonError Error)
{
    public bool IsSuccess => Error is RequestJsonError.None && Request is not null;
}

public static class ArtifactSigningRequestJsonParser
{
    public const int MaximumRequestJsonBytes = 64 * 1024;
    public const int MaximumArtifacts = 64;

    private const long MaximumArtifactBytes = 100L * 1024 * 1024;
    private const int MaximumIdentifierCharacters = 64;
    private const int MaximumSourceRepositoryCharacters = 128;
    private const int MaximumReleaseVersionCharacters = 64;
    private const int MaximumFileCharacters = 128;

    private static readonly HashSet<string> RequestProperties = new(StringComparer.Ordinal)
    {
        "Format",
        "RequestId",
        "ProjectId",
        "ProfileId",
        "ProfileVersion",
        "SourceRepository",
        "SourceCommit",
        "ReleaseVersion",
        "RequestedAt",
        "ExpiresAt",
        "Nonce",
        "SignerPolicyId",
        "TimestampPolicyId",
        "Artifacts",
    };

    private static readonly HashSet<string> ArtifactProperties = new(StringComparer.Ordinal)
    {
        "Role",
        "File",
        "Size",
        "Sha256",
    };

    public static RequestJsonParseResult Parse(ReadOnlyMemory<byte> requestJson)
    {
        if (requestJson.IsEmpty)
        {
            return Failure(RequestJsonError.Empty);
        }

        if (requestJson.Length > MaximumRequestJsonBytes)
        {
            return Failure(RequestJsonError.TooLarge);
        }

        StrictJsonError strictJsonError =
            StrictJsonRules.ValidateEncodingAndPropertyNames(requestJson.Span, maximumDepth: 8);
        if (strictJsonError is not StrictJsonError.None)
        {
            return Failure(MapStrictJsonError(strictJsonError));
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                requestJson,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8,
                });

            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object)
            {
                return Failure(RequestJsonError.RootNotObject);
            }

            StrictJsonError shapeError =
                StrictJsonRules.ValidateObjectShape(root, RequestProperties);
            if (shapeError is not StrictJsonError.None)
            {
                return Failure(MapStrictJsonError(shapeError));
            }

            if (!StrictJsonRules.TryGetString(root, "Format", out string? format)
                || !StrictJsonRules.TryGetString(root, "RequestId", out string? requestIdText)
                || !StrictJsonRules.TryGetString(root, "ProjectId", out string? projectId)
                || !StrictJsonRules.TryGetString(root, "ProfileId", out string? profileId)
                || !StrictJsonRules.TryGetInt32(root, "ProfileVersion", out int profileVersion)
                || !StrictJsonRules.TryGetString(
                    root,
                    "SourceRepository",
                    out string? sourceRepository)
                || !StrictJsonRules.TryGetString(root, "SourceCommit", out string? sourceCommit)
                || !StrictJsonRules.TryGetString(root, "ReleaseVersion", out string? releaseVersion)
                || !StrictJsonRules.TryGetString(root, "RequestedAt", out string? requestedAtText)
                || !StrictJsonRules.TryGetString(root, "ExpiresAt", out string? expiresAtText)
                || !StrictJsonRules.TryGetString(root, "Nonce", out string? nonce)
                || !StrictJsonRules.TryGetString(
                    root,
                    "SignerPolicyId",
                    out string? signerPolicyId)
                || !StrictJsonRules.TryGetString(
                    root,
                    "TimestampPolicyId",
                    out string? timestampPolicyId))
            {
                return Failure(RequestJsonError.InvalidPropertyType);
            }

            if (!string.Equals(format, ArtifactSigningRequestV1.FormatIdentifier, StringComparison.Ordinal)
                || !StrictJsonRules.TryParseCanonicalRequestId(requestIdText, out Guid requestId)
                || !StrictJsonRules.IsSafeIdentifier(projectId, MaximumIdentifierCharacters)
                || !StrictJsonRules.IsSafeIdentifier(profileId, MaximumIdentifierCharacters)
                || profileVersion <= 0
                || !StrictJsonRules.IsPrintableAscii(
                    sourceRepository,
                    MaximumSourceRepositoryCharacters)
                || !StrictJsonRules.IsCanonicalSourceCommit(sourceCommit)
                || !StrictJsonRules.IsPrintableAscii(
                    releaseVersion,
                    MaximumReleaseVersionCharacters)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    requestedAtText,
                    out DateTimeOffset requestedAt)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    expiresAtText,
                    out DateTimeOffset expiresAt)
                || expiresAt <= requestedAt
                || expiresAt - requestedAt > TimeSpan.FromMinutes(15)
                || !StrictJsonRules.IsCanonicalNonce(nonce)
                || !StrictJsonRules.IsSafeIdentifier(
                    signerPolicyId,
                    MaximumIdentifierCharacters)
                || !StrictJsonRules.IsSafeIdentifier(
                    timestampPolicyId,
                    MaximumIdentifierCharacters))
            {
                return Failure(RequestJsonError.InvalidPropertyValue);
            }

            ArtifactParseResult artifactsResult = ParseArtifacts(root);
            if (artifactsResult.Error is not RequestJsonError.None)
            {
                return Failure(artifactsResult.Error);
            }

            ArtifactSigningRequestV1 request = new(
                requestId,
                projectId,
                profileId,
                profileVersion,
                sourceRepository,
                sourceCommit,
                releaseVersion,
                requestedAt,
                expiresAt,
                nonce,
                signerPolicyId,
                timestampPolicyId,
                artifactsResult.Artifacts!);

            return new RequestJsonParseResult(request, RequestJsonError.None);
        }
        catch (JsonException)
        {
            return Failure(RequestJsonError.Malformed);
        }
    }

    private static ArtifactParseResult ParseArtifacts(JsonElement root)
    {
        if (!root.TryGetProperty("Artifacts", out JsonElement artifactsElement)
            || artifactsElement.ValueKind is not JsonValueKind.Array)
        {
            return ArtifactFailure(RequestJsonError.InvalidPropertyType);
        }

        int artifactCount = artifactsElement.GetArrayLength();
        if (artifactCount is 0)
        {
            return ArtifactFailure(RequestJsonError.InvalidPropertyValue);
        }

        if (artifactCount > MaximumArtifacts)
        {
            return ArtifactFailure(RequestJsonError.TooManyArtifacts);
        }

        List<RequestArtifactV1> artifacts = new(artifactCount);
        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> files = new(StringComparer.Ordinal);

        foreach (JsonElement artifactElement in artifactsElement.EnumerateArray())
        {
            if (artifactElement.ValueKind is not JsonValueKind.Object)
            {
                return ArtifactFailure(RequestJsonError.InvalidPropertyType);
            }

            StrictJsonError shapeError =
                StrictJsonRules.ValidateObjectShape(artifactElement, ArtifactProperties);
            if (shapeError is not StrictJsonError.None)
            {
                return ArtifactFailure(MapStrictJsonError(shapeError));
            }

            if (!StrictJsonRules.TryGetString(artifactElement, "Role", out string? role)
                || !StrictJsonRules.TryGetString(artifactElement, "File", out string? file)
                || !StrictJsonRules.TryGetInt64(artifactElement, "Size", out long size)
                || !StrictJsonRules.TryGetString(artifactElement, "Sha256", out string? sha256))
            {
                return ArtifactFailure(RequestJsonError.InvalidPropertyType);
            }

            if (!StrictJsonRules.IsSafeIdentifier(role, MaximumIdentifierCharacters)
                || !StrictJsonRules.IsCanonicalFileToken(file, MaximumFileCharacters)
                || size <= 0
                || size > MaximumArtifactBytes
                || !StrictJsonRules.IsLowerHex(sha256, 64))
            {
                return ArtifactFailure(RequestJsonError.InvalidPropertyValue);
            }

            if (!roles.Add(role) || !files.Add(file))
            {
                return ArtifactFailure(RequestJsonError.DuplicateArtifact);
            }

            artifacts.Add(new RequestArtifactV1(role, file, size, sha256));
        }

        return new ArtifactParseResult(artifacts.AsReadOnly(), RequestJsonError.None);
    }

    private static RequestJsonParseResult Failure(RequestJsonError error)
    {
        return new RequestJsonParseResult(null, error);
    }

    private static ArtifactParseResult ArtifactFailure(RequestJsonError error)
    {
        return new ArtifactParseResult(null, error);
    }

    private sealed record ArtifactParseResult(
        IReadOnlyList<RequestArtifactV1>? Artifacts,
        RequestJsonError Error);

    private static RequestJsonError MapStrictJsonError(StrictJsonError error)
    {
        return error switch
        {
            StrictJsonError.Malformed => RequestJsonError.Malformed,
            StrictJsonError.NonCanonicalPropertyName =>
                RequestJsonError.NonCanonicalPropertyName,
            StrictJsonError.UnknownProperty => RequestJsonError.UnknownProperty,
            StrictJsonError.DuplicateProperty => RequestJsonError.DuplicateProperty,
            StrictJsonError.MissingProperty => RequestJsonError.MissingProperty,
            _ => throw new ArgumentOutOfRangeException(nameof(error)),
        };
    }
}

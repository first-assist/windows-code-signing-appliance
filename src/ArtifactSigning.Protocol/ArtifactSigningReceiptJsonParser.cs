using System.Text.Json;

namespace ArtifactSigning.Protocol;

public enum ReceiptJsonError
{
    None,
    Empty,
    TooLarge,
    Invalid,
}

public sealed record ReceiptJsonParseResult(
    ArtifactSigningReceiptV1? Receipt,
    ReceiptJsonError Error)
{
    public bool IsSuccess =>
        Error is ReceiptJsonError.None
        && Receipt is not null;
}

public static class ArtifactSigningReceiptJsonParser
{
    private const int MaximumDepth = 8;

    private static readonly HashSet<string> ReceiptProperties =
        new(StringComparer.Ordinal)
        {
            "Format",
            "RequestId",
            "RequestDigest",
            "ProjectId",
            "ProfileId",
            "ProfileVersion",
            "SourceRepository",
            "SourceCommit",
            "ReleaseVersion",
            "SignerPolicyId",
            "TimestampPolicyId",
            "SubmitterSpkiSha256",
            "ApproverSpkiSha256",
            "ReceiptSignerSpkiSha256",
            "UnsignedArtifacts",
            "ResultArtifacts",
            "AuthenticodeArtifacts",
            "WorkerVersion",
            "SignToolSha256",
            "SigningAuditSequence",
            "CompletedAt",
        };

    private static readonly HashSet<string> ArtifactProperties =
        new(StringComparer.Ordinal)
        {
            "Role",
            "File",
            "Size",
            "Sha256",
        };

    private static readonly HashSet<string>
        AuthenticodeProperties =
            new(StringComparer.Ordinal)
            {
                "Role",
                "File",
                "UnsignedSha256",
                "SignedSha256",
                "SignerThumbprint",
                "TimestampAuthorityThumbprint",
                "TimestampedAt",
            };

    public static ReceiptJsonParseResult Parse(
        ReadOnlyMemory<byte> receiptJson)
    {
        if (receiptJson.IsEmpty)
        {
            return Failure(ReceiptJsonError.Empty);
        }

        if (receiptJson.Length
            > ArtifactSigningReceiptJsonSerializer
                .MaximumReceiptJsonBytes)
        {
            return Failure(ReceiptJsonError.TooLarge);
        }

        if (StrictJsonRules.ValidateEncodingAndPropertyNames(
                receiptJson.Span,
                MaximumDepth) is not StrictJsonError.None)
        {
            return Failure(ReceiptJsonError.Invalid);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                receiptJson,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = MaximumDepth,
                });
            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object
                || StrictJsonRules.ValidateObjectShape(
                    root,
                    ReceiptProperties) is not StrictJsonError.None
                || !TryReadIdentity(
                    root,
                    out ReceiptIdentity? identity)
                || !TryReadArtifacts(
                    root,
                    "UnsignedArtifacts",
                    out IReadOnlyList<ReceiptArtifactV1>?
                        unsignedArtifacts)
                || !TryReadArtifacts(
                    root,
                    "ResultArtifacts",
                    out IReadOnlyList<ReceiptArtifactV1>?
                        resultArtifacts)
                || !TryReadAuthenticodeArtifacts(
                    root,
                    out IReadOnlyList<
                        ReceiptAuthenticodeArtifactV1>?
                        authenticodeArtifacts)
                || identity is null
                || unsignedArtifacts is null
                || resultArtifacts is null
                || authenticodeArtifacts is null)
            {
                return Failure(ReceiptJsonError.Invalid);
            }

            ArtifactSigningReceiptV1 receipt = new(
                identity.RequestId,
                identity.RequestDigest,
                identity.ProjectId,
                identity.ProfileId,
                identity.ProfileVersion,
                identity.SourceRepository,
                identity.SourceCommit,
                identity.ReleaseVersion,
                identity.SignerPolicyId,
                identity.TimestampPolicyId,
                identity.SubmitterSpkiSha256,
                identity.ApproverSpkiSha256,
                identity.ReceiptSignerSpkiSha256,
                unsignedArtifacts,
                resultArtifacts,
                authenticodeArtifacts,
                identity.WorkerVersion,
                identity.SignToolSha256,
                identity.SigningAuditSequence,
                identity.CompletedAt);
            byte[] canonical =
                ArtifactSigningReceiptJsonSerializer.Serialize(
                    receipt);
            return canonical.AsSpan().SequenceEqual(
                    receiptJson.Span)
                ? new ReceiptJsonParseResult(
                    receipt,
                    ReceiptJsonError.None)
                : Failure(ReceiptJsonError.Invalid);
        }
        catch (Exception exception)
            when (exception is JsonException
                or ArgumentException
                or InvalidOperationException
                or OverflowException)
        {
            return Failure(ReceiptJsonError.Invalid);
        }
    }

    private static bool TryReadIdentity(
        JsonElement root,
        out ReceiptIdentity? identity)
    {
        identity = null;
        if (!StrictJsonRules.TryGetString(
                root,
                "Format",
                out string format)
            || !string.Equals(
                format,
                ArtifactSigningReceiptV1.FormatIdentifier,
                StringComparison.Ordinal)
            || !StrictJsonRules.TryGetString(
                root,
                "RequestId",
                out string requestIdText)
            || !StrictJsonRules.TryParseCanonicalRequestId(
                requestIdText,
                out Guid requestId)
            || !StrictJsonRules.TryGetString(
                root,
                "RequestDigest",
                out string requestDigest)
            || !StrictJsonRules.TryGetString(
                root,
                "ProjectId",
                out string projectId)
            || !StrictJsonRules.TryGetString(
                root,
                "ProfileId",
                out string profileId)
            || !StrictJsonRules.TryGetInt32(
                root,
                "ProfileVersion",
                out int profileVersion)
            || !StrictJsonRules.TryGetString(
                root,
                "SourceRepository",
                out string sourceRepository)
            || !StrictJsonRules.TryGetString(
                root,
                "SourceCommit",
                out string sourceCommit)
            || !StrictJsonRules.TryGetString(
                root,
                "ReleaseVersion",
                out string releaseVersion)
            || !StrictJsonRules.TryGetString(
                root,
                "SignerPolicyId",
                out string signerPolicyId)
            || !StrictJsonRules.TryGetString(
                root,
                "TimestampPolicyId",
                out string timestampPolicyId)
            || !StrictJsonRules.TryGetString(
                root,
                "SubmitterSpkiSha256",
                out string submitterSpkiSha256)
            || !StrictJsonRules.TryGetString(
                root,
                "ApproverSpkiSha256",
                out string approverSpkiSha256)
            || !StrictJsonRules.TryGetString(
                root,
                "ReceiptSignerSpkiSha256",
                out string receiptSignerSpkiSha256)
            || !StrictJsonRules.TryGetString(
                root,
                "WorkerVersion",
                out string workerVersion)
            || !StrictJsonRules.TryGetString(
                root,
                "SignToolSha256",
                out string signToolSha256)
            || !TryGetUInt64(
                root,
                "SigningAuditSequence",
                out ulong signingAuditSequence)
            || !StrictJsonRules.TryGetString(
                root,
                "CompletedAt",
                out string completedAtText)
            || !StrictJsonRules.TryParseWholeSecondUtc(
                completedAtText,
                out DateTimeOffset completedAt))
        {
            return false;
        }

        identity = new ReceiptIdentity(
            requestId,
            requestDigest,
            projectId,
            profileId,
            profileVersion,
            sourceRepository,
            sourceCommit,
            releaseVersion,
            signerPolicyId,
            timestampPolicyId,
            submitterSpkiSha256,
            approverSpkiSha256,
            receiptSignerSpkiSha256,
            workerVersion,
            signToolSha256,
            signingAuditSequence,
            completedAt);
        return true;
    }

    private static bool TryReadArtifacts(
        JsonElement root,
        string propertyName,
        out IReadOnlyList<ReceiptArtifactV1>? artifacts)
    {
        artifacts = null;
        if (!root.TryGetProperty(
                propertyName,
                out JsonElement array)
            || array.ValueKind is not JsonValueKind.Array
            || array.GetArrayLength() is 0
                or > ArtifactSigningRequestJsonParser
                    .MaximumArtifacts)
        {
            return false;
        }

        List<ReceiptArtifactV1> parsed =
            new(array.GetArrayLength());
        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.ValueKind is not JsonValueKind.Object
                || StrictJsonRules.ValidateObjectShape(
                    item,
                    ArtifactProperties) is not StrictJsonError.None
                || !StrictJsonRules.TryGetString(
                    item,
                    "Role",
                    out string role)
                || !StrictJsonRules.TryGetString(
                    item,
                    "File",
                    out string file)
                || !StrictJsonRules.TryGetInt64(
                    item,
                    "Size",
                    out long size)
                || !StrictJsonRules.TryGetString(
                    item,
                    "Sha256",
                    out string sha256))
            {
                return false;
            }

            parsed.Add(new ReceiptArtifactV1(
                role,
                file,
                size,
                sha256));
        }

        artifacts = parsed.AsReadOnly();
        return true;
    }

    private static bool TryReadAuthenticodeArtifacts(
        JsonElement root,
        out IReadOnlyList<ReceiptAuthenticodeArtifactV1>?
            artifacts)
    {
        artifacts = null;
        if (!root.TryGetProperty(
                "AuthenticodeArtifacts",
                out JsonElement array)
            || array.ValueKind is not JsonValueKind.Array
            || array.GetArrayLength() is 0
                or > ArtifactSigningRequestJsonParser
                    .MaximumArtifacts)
        {
            return false;
        }

        List<ReceiptAuthenticodeArtifactV1> parsed =
            new(array.GetArrayLength());
        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.ValueKind is not JsonValueKind.Object
                || StrictJsonRules.ValidateObjectShape(
                    item,
                    AuthenticodeProperties) is not
                    StrictJsonError.None
                || !StrictJsonRules.TryGetString(
                    item,
                    "Role",
                    out string role)
                || !StrictJsonRules.TryGetString(
                    item,
                    "File",
                    out string file)
                || !StrictJsonRules.TryGetString(
                    item,
                    "UnsignedSha256",
                    out string unsignedSha256)
                || !StrictJsonRules.TryGetString(
                    item,
                    "SignedSha256",
                    out string signedSha256)
                || !StrictJsonRules.TryGetString(
                    item,
                    "SignerThumbprint",
                    out string signerThumbprint)
                || !StrictJsonRules.TryGetString(
                    item,
                    "TimestampAuthorityThumbprint",
                    out string timestampAuthorityThumbprint)
                || !StrictJsonRules.TryGetString(
                    item,
                    "TimestampedAt",
                    out string timestampedAtText)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    timestampedAtText,
                    out DateTimeOffset timestampedAt))
            {
                return false;
            }

            parsed.Add(new ReceiptAuthenticodeArtifactV1(
                role,
                file,
                unsignedSha256,
                signedSha256,
                signerThumbprint,
                timestampAuthorityThumbprint,
                timestampedAt));
        }

        artifacts = parsed.AsReadOnly();
        return true;
    }

    private static bool TryGetUInt64(
        JsonElement root,
        string propertyName,
        out ulong value)
    {
        if (root.TryGetProperty(
                propertyName,
                out JsonElement property)
            && property.ValueKind is JsonValueKind.Number
            && property.TryGetUInt64(out value))
        {
            return true;
        }

        value = 0;
        return false;
    }

    private static ReceiptJsonParseResult Failure(
        ReceiptJsonError error)
    {
        return new ReceiptJsonParseResult(null, error);
    }

    private sealed record ReceiptIdentity(
        Guid RequestId,
        string RequestDigest,
        string ProjectId,
        string ProfileId,
        int ProfileVersion,
        string SourceRepository,
        string SourceCommit,
        string ReleaseVersion,
        string SignerPolicyId,
        string TimestampPolicyId,
        string SubmitterSpkiSha256,
        string ApproverSpkiSha256,
        string ReceiptSignerSpkiSha256,
        string WorkerVersion,
        string SignToolSha256,
        ulong SigningAuditSequence,
        DateTimeOffset CompletedAt);
}

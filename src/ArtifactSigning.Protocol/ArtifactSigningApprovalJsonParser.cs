using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

public enum ApprovalJsonError
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
}

public sealed record ApprovalJsonParseResult(
    ArtifactSigningApprovalV1? Approval,
    ApprovalJsonError Error)
{
    public bool IsSuccess => Error is ApprovalJsonError.None && Approval is not null;
}

public static class ArtifactSigningApprovalJsonParser
{
    public const int MaximumApprovalJsonBytes = 16 * 1024;
    public const int MaximumReasonUtf8Bytes = 512;

    private static readonly HashSet<string> ApprovalProperties = new(StringComparer.Ordinal)
    {
        "Format",
        "RequestId",
        "RequestDigest",
        "Decision",
        "Reason",
        "ApprovedAt",
        "ExpiresAt",
        "Nonce",
    };

    public static ApprovalJsonParseResult Parse(ReadOnlyMemory<byte> approvalJson)
    {
        if (approvalJson.IsEmpty)
        {
            return Failure(ApprovalJsonError.Empty);
        }

        if (approvalJson.Length > MaximumApprovalJsonBytes)
        {
            return Failure(ApprovalJsonError.TooLarge);
        }

        StrictJsonError strictJsonError =
            StrictJsonRules.ValidateEncodingAndPropertyNames(approvalJson.Span, maximumDepth: 2);
        if (strictJsonError is not StrictJsonError.None)
        {
            return Failure(MapStrictJsonError(strictJsonError));
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                approvalJson,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 2,
                });

            JsonElement root = document.RootElement;
            if (root.ValueKind is not JsonValueKind.Object)
            {
                return Failure(ApprovalJsonError.RootNotObject);
            }

            StrictJsonError shapeError =
                StrictJsonRules.ValidateObjectShape(root, ApprovalProperties);
            if (shapeError is not StrictJsonError.None)
            {
                return Failure(MapStrictJsonError(shapeError));
            }

            if (!StrictJsonRules.TryGetString(root, "Format", out string format)
                || !StrictJsonRules.TryGetString(root, "RequestId", out string requestIdText)
                || !StrictJsonRules.TryGetString(root, "RequestDigest", out string requestDigest)
                || !StrictJsonRules.TryGetString(root, "Decision", out string decisionText)
                || !StrictJsonRules.TryGetString(root, "Reason", out string reason)
                || !StrictJsonRules.TryGetString(root, "ApprovedAt", out string approvedAtText)
                || !StrictJsonRules.TryGetString(root, "ExpiresAt", out string expiresAtText)
                || !StrictJsonRules.TryGetString(root, "Nonce", out string nonce))
            {
                return Failure(ApprovalJsonError.InvalidPropertyType);
            }

            if (!string.Equals(
                    format,
                    ArtifactSigningApprovalV1.FormatIdentifier,
                    StringComparison.Ordinal)
                || !StrictJsonRules.TryParseCanonicalRequestId(requestIdText, out Guid requestId)
                || !StrictJsonRules.IsLowerHex(requestDigest, 64)
                || !TryParseDecision(decisionText, out ApprovalDecision decision)
                || !IsValidReason(reason)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    approvedAtText,
                    out DateTimeOffset approvedAt)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    expiresAtText,
                    out DateTimeOffset expiresAt)
                || expiresAt <= approvedAt
                || expiresAt - approvedAt > TimeSpan.FromMinutes(5)
                || !StrictJsonRules.IsCanonicalNonce(nonce))
            {
                return Failure(ApprovalJsonError.InvalidPropertyValue);
            }

            ArtifactSigningApprovalV1 approval = new(
                requestId,
                requestDigest,
                decision,
                reason,
                approvedAt,
                expiresAt,
                nonce);

            return new ApprovalJsonParseResult(approval, ApprovalJsonError.None);
        }
        catch (JsonException)
        {
            return Failure(ApprovalJsonError.Malformed);
        }
    }

    private static bool IsValidReason(string reason)
    {
        return reason.Length > 0
            && !char.IsWhiteSpace(reason[0])
            && !char.IsWhiteSpace(reason[^1])
            && Encoding.UTF8.GetByteCount(reason) <= MaximumReasonUtf8Bytes
            && reason.EnumerateRunes().All(rune =>
                Rune.GetUnicodeCategory(rune) is not UnicodeCategory.Control
                    and not UnicodeCategory.Format
                    and not UnicodeCategory.LineSeparator
                    and not UnicodeCategory.ParagraphSeparator);
    }

    private static bool TryParseDecision(string value, out ApprovalDecision decision)
    {
        switch (value)
        {
            case nameof(ApprovalDecision.Approve):
                decision = ApprovalDecision.Approve;
                return true;
            case nameof(ApprovalDecision.Reject):
                decision = ApprovalDecision.Reject;
                return true;
            default:
                decision = default;
                return false;
        }
    }

    private static ApprovalJsonParseResult Failure(ApprovalJsonError error)
    {
        return new ApprovalJsonParseResult(null, error);
    }

    private static ApprovalJsonError MapStrictJsonError(StrictJsonError error)
    {
        return error switch
        {
            StrictJsonError.Malformed => ApprovalJsonError.Malformed,
            StrictJsonError.NonCanonicalPropertyName =>
                ApprovalJsonError.NonCanonicalPropertyName,
            StrictJsonError.UnknownProperty => ApprovalJsonError.UnknownProperty,
            StrictJsonError.DuplicateProperty => ApprovalJsonError.DuplicateProperty,
            StrictJsonError.MissingProperty => ApprovalJsonError.MissingProperty,
            _ => throw new ArgumentOutOfRangeException(nameof(error)),
        };
    }
}

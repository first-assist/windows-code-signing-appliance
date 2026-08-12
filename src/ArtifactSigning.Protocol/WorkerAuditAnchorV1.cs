using System.Globalization;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

public sealed record WorkerAuditAnchorV1
{
    public const string FormatIdentifier =
        "ArtifactSigningWorkerAuditAnchorV1";

    public WorkerAuditAnchorV1(
        ulong workerSequence,
        string workerEventDigest,
        string workerVersion,
        bool workerReady,
        bool timestampDependencyReady,
        DateTimeOffset publishedAt,
        DateTimeOffset expiresAt,
        string receiptSignerSpkiSha256)
    {
        ArgumentNullException.ThrowIfNull(workerEventDigest);
        ArgumentNullException.ThrowIfNull(workerVersion);
        ArgumentNullException.ThrowIfNull(
            receiptSignerSpkiSha256);
        if (!StrictJsonRules.IsLowerHex(
                workerEventDigest,
                64)
            || workerSequence is 0
                && !string.Equals(
                    workerEventDigest,
                    AuditEventDigest
                        .GenesisPreviousEventDigest,
                    StringComparison.Ordinal)
            || !IsSemanticVersion(workerVersion)
            || !StrictJsonRules.IsLowerHex(
                receiptSignerSpkiSha256,
                64)
            || !IsWholeSecondUtc(publishedAt)
            || !IsWholeSecondUtc(expiresAt)
            || expiresAt <= publishedAt
            || expiresAt - publishedAt
                > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentException(
                "Worker audit anchor is invalid.");
        }

        WorkerSequence = workerSequence;
        WorkerEventDigest = workerEventDigest;
        WorkerVersion = workerVersion;
        WorkerReady = workerReady;
        TimestampDependencyReady =
            timestampDependencyReady;
        PublishedAt = publishedAt;
        ExpiresAt = expiresAt;
        ReceiptSignerSpkiSha256 =
            receiptSignerSpkiSha256;
    }

    public ulong WorkerSequence { get; }

    public string WorkerEventDigest { get; }

    public string WorkerVersion { get; }

    public bool WorkerReady { get; }

    public bool TimestampDependencyReady { get; }

    public DateTimeOffset PublishedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public string ReceiptSignerSpkiSha256 { get; }

    private static bool IsWholeSecondUtc(
        DateTimeOffset value)
    {
        return value.Offset == TimeSpan.Zero
            && value.Ticks
                % TimeSpan.TicksPerSecond is 0;
    }

    private static bool IsSemanticVersion(string value)
    {
        return value.Length is > 0 and <= 32
            && Version.TryParse(value, out Version? parsed)
            && parsed is
            {
                Major: >= 0,
                Minor: >= 0,
                Build: >= 0,
                Revision: -1,
            }
            && string.Equals(
                value,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{parsed.Major}.{parsed.Minor}.{parsed.Build}"),
                StringComparison.Ordinal);
    }
}

public enum WorkerAuditAnchorJsonError
{
    None,
    Empty,
    TooLarge,
    Invalid,
}

public sealed record WorkerAuditAnchorJsonParseResult(
    WorkerAuditAnchorV1? Anchor,
    WorkerAuditAnchorJsonError Error)
{
    public bool IsSuccess =>
        Error is WorkerAuditAnchorJsonError.None
        && Anchor is not null;
}

public static class WorkerAuditAnchorJson
{
    public const int MaximumAnchorJsonBytes = 4096;

    public static byte[] Serialize(
        WorkerAuditAnchorV1 anchor)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "Format",
                WorkerAuditAnchorV1.FormatIdentifier);
            writer.WriteNumber(
                "WorkerSequence",
                anchor.WorkerSequence);
            writer.WriteString(
                "WorkerEventDigest",
                anchor.WorkerEventDigest);
            writer.WriteString(
                "WorkerVersion",
                anchor.WorkerVersion);
            writer.WriteBoolean(
                "WorkerReady",
                anchor.WorkerReady);
            writer.WriteBoolean(
                "TimestampDependencyReady",
                anchor.TimestampDependencyReady);
            writer.WriteString(
                "PublishedAt",
                FormatTimestamp(anchor.PublishedAt));
            writer.WriteString(
                "ExpiresAt",
                FormatTimestamp(anchor.ExpiresAt));
            writer.WriteString(
                "ReceiptSignerSpkiSha256",
                anchor.ReceiptSignerSpkiSha256);
            writer.WriteEndObject();
        }

        byte[] json = output.ToArray();
        if (json.Length > MaximumAnchorJsonBytes)
        {
            throw new InvalidOperationException(
                "Worker audit anchor exceeds its bound.");
        }

        return json;
    }

    public static WorkerAuditAnchorJsonParseResult Parse(
        ReadOnlyMemory<byte> json)
    {
        if (json.IsEmpty)
        {
            return Failure(WorkerAuditAnchorJsonError.Empty);
        }

        if (json.Length > MaximumAnchorJsonBytes)
        {
            return Failure(
                WorkerAuditAnchorJsonError.TooLarge);
        }

        if (StrictJsonRules.ValidateEncodingAndPropertyNames(
                json.Span,
                maximumDepth: 2) is not StrictJsonError.None)
        {
            return Failure(
                WorkerAuditAnchorJsonError.Invalid);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 2,
                });
            JsonElement root = document.RootElement;
            HashSet<string> properties =
            [
                "Format",
                "WorkerSequence",
                "WorkerEventDigest",
                "WorkerVersion",
                "WorkerReady",
                "TimestampDependencyReady",
                "PublishedAt",
                "ExpiresAt",
                "ReceiptSignerSpkiSha256",
            ];
            if (root.ValueKind is not JsonValueKind.Object
                || StrictJsonRules.ValidateObjectShape(
                    root,
                    properties) is not StrictJsonError.None
                || !StrictJsonRules.TryGetString(
                    root,
                    "Format",
                    out string format)
                || !string.Equals(
                    format,
                    WorkerAuditAnchorV1.FormatIdentifier,
                    StringComparison.Ordinal)
                || !root.TryGetProperty(
                    "WorkerSequence",
                    out JsonElement sequenceElement)
                || !sequenceElement.TryGetUInt64(
                    out ulong workerSequence)
                || !StrictJsonRules.TryGetString(
                    root,
                    "WorkerEventDigest",
                    out string workerEventDigest)
                || !StrictJsonRules.TryGetString(
                    root,
                    "WorkerVersion",
                    out string workerVersion)
                || !root.TryGetProperty(
                    "WorkerReady",
                    out JsonElement readyElement)
                || readyElement.ValueKind is not (
                    JsonValueKind.True
                    or JsonValueKind.False)
                || !root.TryGetProperty(
                    "TimestampDependencyReady",
                    out JsonElement timestampElement)
                || timestampElement.ValueKind is not (
                    JsonValueKind.True
                    or JsonValueKind.False)
                || !StrictJsonRules.TryGetString(
                    root,
                    "PublishedAt",
                    out string publishedAtText)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    publishedAtText,
                    out DateTimeOffset publishedAt)
                || !StrictJsonRules.TryGetString(
                    root,
                    "ExpiresAt",
                    out string expiresAtText)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    expiresAtText,
                    out DateTimeOffset expiresAt)
                || !StrictJsonRules.TryGetString(
                    root,
                    "ReceiptSignerSpkiSha256",
                    out string receiptSignerSpkiSha256))
            {
                return Failure(
                    WorkerAuditAnchorJsonError.Invalid);
            }

            WorkerAuditAnchorV1 anchor = new(
                workerSequence,
                workerEventDigest,
                workerVersion,
                readyElement.GetBoolean(),
                timestampElement.GetBoolean(),
                publishedAt,
                expiresAt,
                receiptSignerSpkiSha256);
            byte[] canonical = Serialize(anchor);
            if (!json.Span.SequenceEqual(canonical))
            {
                return Failure(
                    WorkerAuditAnchorJsonError.Invalid);
            }

            return new WorkerAuditAnchorJsonParseResult(
                anchor,
                WorkerAuditAnchorJsonError.None);
        }
        catch (Exception exception)
            when (exception is JsonException
                or ArgumentException
                or InvalidOperationException)
        {
            return Failure(
                WorkerAuditAnchorJsonError.Invalid);
        }
    }

    private static string FormatTimestamp(
        DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }

    private static WorkerAuditAnchorJsonParseResult Failure(
        WorkerAuditAnchorJsonError error)
    {
        return new WorkerAuditAnchorJsonParseResult(
            null,
            error);
    }
}

public static class WorkerAuditAnchorFiles
{
    public const string FilePrefix =
        "worker-audit-anchor-";
    public const string JsonSuffix = ".json";
    public const string SignatureSuffix = ".p7s";
    public const int MaximumRetainedAnchors = 4;
    public const int MaximumSignatureBytes = 64 * 1024;

    public static string GetJsonFileName(
        string anchorJsonSha256)
    {
        ValidateDigest(anchorJsonSha256);
        return string.Concat(
            FilePrefix,
            anchorJsonSha256,
            JsonSuffix);
    }

    public static string GetSignatureFileName(
        string anchorJsonSha256)
    {
        ValidateDigest(anchorJsonSha256);
        return string.Concat(
            FilePrefix,
            anchorJsonSha256,
            SignatureSuffix);
    }

    public static bool TryParseJsonFileName(
        string fileName,
        out string anchorJsonSha256)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return TryParse(
            fileName,
            JsonSuffix,
            out anchorJsonSha256);
    }

    public static bool TryParseSignatureFileName(
        string fileName,
        out string anchorJsonSha256)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return TryParse(
            fileName,
            SignatureSuffix,
            out anchorJsonSha256);
    }

    private static bool TryParse(
        string fileName,
        string suffix,
        out string anchorJsonSha256)
    {
        anchorJsonSha256 = string.Empty;
        if (!fileName.StartsWith(
                FilePrefix,
                StringComparison.Ordinal)
            || !fileName.EndsWith(
                suffix,
                StringComparison.Ordinal)
            || fileName.Length
                != FilePrefix.Length + 64 + suffix.Length)
        {
            return false;
        }

        string digest = fileName.Substring(
            FilePrefix.Length,
            64);
        if (!StrictJsonRules.IsLowerHex(digest, 64))
        {
            return false;
        }

        anchorJsonSha256 = digest;
        return true;
    }

    private static void ValidateDigest(string digest)
    {
        ArgumentNullException.ThrowIfNull(digest);
        if (!StrictJsonRules.IsLowerHex(digest, 64))
        {
            throw new ArgumentException(
                "Anchor digest is invalid.",
                nameof(digest));
        }
    }
}

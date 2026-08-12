using System.Text.Json;

namespace ArtifactSigning.Protocol;

public sealed record WorkerTerminalStatusV1
{
    public const string FormatIdentifier =
        "ArtifactSigningWorkerTerminalStatusV1";

    public WorkerTerminalStatusV1(
        Guid requestId,
        string requestDigest,
        RequestState state,
        string resultCode,
        string? evidenceDigest,
        DateTimeOffset updatedAt)
    {
        ArgumentNullException.ThrowIfNull(requestDigest);
        ArgumentNullException.ThrowIfNull(resultCode);
        if (requestId == Guid.Empty
            || !StrictJsonRules.IsLowerHex(
                requestDigest,
                64)
            || state is not (
                RequestState.Signed
                or RequestState.Failed
                or RequestState.Quarantined)
            || !StrictJsonRules.IsSafeIdentifier(
                resultCode,
                64)
            || state is RequestState.Signed
                && (evidenceDigest is null
                    || !StrictJsonRules.IsLowerHex(
                        evidenceDigest,
                        64))
            || state is not RequestState.Signed
                && evidenceDigest is not null
            || updatedAt.Offset != TimeSpan.Zero
            || updatedAt.Ticks
                % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Worker terminal status is invalid.");
        }

        RequestId = requestId;
        RequestDigest = requestDigest;
        State = state;
        ResultCode = resultCode;
        EvidenceDigest = evidenceDigest;
        UpdatedAt = updatedAt;
    }

    public Guid RequestId { get; }

    public string RequestDigest { get; }

    public RequestState State { get; }

    public string ResultCode { get; }

    public string? EvidenceDigest { get; }

    public DateTimeOffset UpdatedAt { get; }
}

public enum WorkerTerminalStatusJsonError
{
    None,
    Empty,
    TooLarge,
    Invalid,
}

public sealed record WorkerTerminalStatusJsonParseResult(
    WorkerTerminalStatusV1? Status,
    WorkerTerminalStatusJsonError Error)
{
    public bool IsSuccess =>
        Error is WorkerTerminalStatusJsonError.None
        && Status is not null;
}

public static class WorkerTerminalStatusJson
{
    public const int MaximumStatusJsonBytes = 4096;

    public static byte[] Serialize(
        WorkerTerminalStatusV1 status)
    {
        ArgumentNullException.ThrowIfNull(status);
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "Format",
                WorkerTerminalStatusV1.FormatIdentifier);
            writer.WriteString(
                "RequestId",
                status.RequestId.ToString("D"));
            writer.WriteString(
                "RequestDigest",
                status.RequestDigest);
            writer.WriteString(
                "State",
                status.State.ToString());
            writer.WriteString(
                "ResultCode",
                status.ResultCode);
            if (status.EvidenceDigest is null)
            {
                writer.WriteNull("EvidenceDigest");
            }
            else
            {
                writer.WriteString(
                    "EvidenceDigest",
                    status.EvidenceDigest);
            }

            writer.WriteString(
                "UpdatedAt",
                status.UpdatedAt.ToString(
                    "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    System.Globalization.CultureInfo
                        .InvariantCulture));
            writer.WriteEndObject();
        }

        byte[] json = output.ToArray();
        if (json.Length > MaximumStatusJsonBytes)
        {
            throw new InvalidOperationException(
                "Worker terminal status exceeds its bound.");
        }

        return json;
    }

    public static WorkerTerminalStatusJsonParseResult Parse(
        ReadOnlyMemory<byte> json)
    {
        if (json.IsEmpty)
        {
            return Failure(
                WorkerTerminalStatusJsonError.Empty);
        }

        if (json.Length > MaximumStatusJsonBytes)
        {
            return Failure(
                WorkerTerminalStatusJsonError.TooLarge);
        }

        if (StrictJsonRules.ValidateEncodingAndPropertyNames(
                json.Span,
                maximumDepth: 2) is not StrictJsonError.None)
        {
            return Failure(
                WorkerTerminalStatusJsonError.Invalid);
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
                "RequestId",
                "RequestDigest",
                "State",
                "ResultCode",
                "EvidenceDigest",
                "UpdatedAt",
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
                    WorkerTerminalStatusV1.FormatIdentifier,
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
                    "State",
                    out string stateText)
                || !Enum.TryParse(
                    stateText,
                    ignoreCase: false,
                    out RequestState state)
                || !StrictJsonRules.TryGetString(
                    root,
                    "ResultCode",
                    out string resultCode)
                || !TryGetNullableString(
                    root,
                    "EvidenceDigest",
                    out string? evidenceDigest)
                || !StrictJsonRules.TryGetString(
                    root,
                    "UpdatedAt",
                    out string updatedAtText)
                || !StrictJsonRules.TryParseWholeSecondUtc(
                    updatedAtText,
                    out DateTimeOffset updatedAt))
            {
                return Failure(
                    WorkerTerminalStatusJsonError.Invalid);
            }

            return new WorkerTerminalStatusJsonParseResult(
                new WorkerTerminalStatusV1(
                    requestId,
                    requestDigest,
                    state,
                    resultCode,
                    evidenceDigest,
                    updatedAt),
                WorkerTerminalStatusJsonError.None);
        }
        catch (Exception exception)
            when (exception is JsonException
                or ArgumentException)
        {
            return Failure(
                WorkerTerminalStatusJsonError.Invalid);
        }
    }

    private static bool TryGetNullableString(
        JsonElement root,
        string name,
        out string? value)
    {
        JsonElement element = root.GetProperty(name);
        if (element.ValueKind is JsonValueKind.Null)
        {
            value = null;
            return true;
        }

        if (element.ValueKind is JsonValueKind.String)
        {
            value = element.GetString();
            return value is not null;
        }

        value = null;
        return false;
    }

    private static WorkerTerminalStatusJsonParseResult Failure(
        WorkerTerminalStatusJsonError error)
    {
        return new WorkerTerminalStatusJsonParseResult(
            null,
            error);
    }
}

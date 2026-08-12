using System.Buffers;
using System.Globalization;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

public static class ArtifactSigningApprovalJsonSerializer
{
    public static byte[] Serialize(
        ArtifactSigningApprovalV1 approval)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(
                   buffer,
                   new JsonWriterOptions
                   {
                       Indented = true,
                       NewLine = "\n",
                       SkipValidation = false,
                   }))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "Format",
                ArtifactSigningApprovalV1
                    .FormatIdentifier);
            writer.WriteString(
                "RequestId",
                approval.RequestId.ToString("D"));
            writer.WriteString(
                "RequestDigest",
                approval.RequestDigest);
            writer.WriteString(
                "Decision",
                approval.Decision.ToString());
            writer.WriteString("Reason", approval.Reason);
            writer.WriteString(
                "ApprovedAt",
                FormatTimestamp(approval.ApprovedAt));
            writer.WriteString(
                "ExpiresAt",
                FormatTimestamp(approval.ExpiresAt));
            writer.WriteString("Nonce", approval.Nonce);
            writer.WriteEndObject();
        }

        if (buffer.WrittenCount + 1
            > ArtifactSigningApprovalJsonParser
                .MaximumApprovalJsonBytes)
        {
            throw new InvalidOperationException(
                "Serialized signing approval exceeds its protocol bound.");
        }

        byte[] result =
            new byte[buffer.WrittenCount + 1];
        buffer.WrittenSpan.CopyTo(result);
        result[^1] = (byte)'\n';
        ApprovalJsonParseResult parsed =
            ArtifactSigningApprovalJsonParser.Parse(result);
        if (!parsed.IsSuccess)
        {
            throw new ArgumentException(
                "Signing approval is invalid.",
                nameof(approval));
        }

        return result;
    }

    private static string FormatTimestamp(
        DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }
}

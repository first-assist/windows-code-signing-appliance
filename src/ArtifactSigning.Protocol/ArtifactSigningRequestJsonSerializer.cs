using System.Buffers;
using System.Globalization;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

public static class ArtifactSigningRequestJsonSerializer
{
    public static byte[] Serialize(
        ArtifactSigningRequestV1 request)
    {
        ArgumentNullException.ThrowIfNull(request);
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
                ArtifactSigningRequestV1.FormatIdentifier);
            writer.WriteString(
                "RequestId",
                request.RequestId.ToString("D"));
            writer.WriteString("ProjectId", request.ProjectId);
            writer.WriteString("ProfileId", request.ProfileId);
            writer.WriteNumber(
                "ProfileVersion",
                request.ProfileVersion);
            writer.WriteString(
                "SourceRepository",
                request.SourceRepository);
            writer.WriteString(
                "SourceCommit",
                request.SourceCommit);
            writer.WriteString(
                "ReleaseVersion",
                request.ReleaseVersion);
            writer.WriteString(
                "RequestedAt",
                FormatTimestamp(request.RequestedAt));
            writer.WriteString(
                "ExpiresAt",
                FormatTimestamp(request.ExpiresAt));
            writer.WriteString("Nonce", request.Nonce);
            writer.WriteString(
                "SignerPolicyId",
                request.SignerPolicyId);
            writer.WriteString(
                "TimestampPolicyId",
                request.TimestampPolicyId);
            writer.WriteStartArray("Artifacts");
            foreach (RequestArtifactV1 artifact
                     in request.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("Role", artifact.Role);
                writer.WriteString("File", artifact.File);
                writer.WriteNumber("Size", artifact.Size);
                writer.WriteString("Sha256", artifact.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        if (buffer.WrittenCount + 1
            > ArtifactSigningRequestJsonParser
                .MaximumRequestJsonBytes)
        {
            throw new InvalidOperationException(
                "Serialized signing request exceeds its protocol bound.");
        }

        byte[] result =
            new byte[buffer.WrittenCount + 1];
        buffer.WrittenSpan.CopyTo(result);
        result[^1] = (byte)'\n';
        RequestJsonParseResult parsed =
            ArtifactSigningRequestJsonParser.Parse(result);
        if (!parsed.IsSuccess)
        {
            throw new ArgumentException(
                "Signing request is invalid.",
                nameof(request));
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

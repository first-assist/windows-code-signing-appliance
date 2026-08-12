using System.Buffers;
using System.Globalization;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

public static class ArtifactSigningReceiptJsonSerializer
{
    public const int MaximumReceiptJsonBytes = 128 * 1024;

    public static byte[] Serialize(ArtifactSigningReceiptV1 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);

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
                ArtifactSigningReceiptV1.FormatIdentifier);
            writer.WriteString(
                "RequestId",
                receipt.RequestId.ToString("D"));
            writer.WriteString("RequestDigest", receipt.RequestDigest);
            writer.WriteString("ProjectId", receipt.ProjectId);
            writer.WriteString("ProfileId", receipt.ProfileId);
            writer.WriteNumber("ProfileVersion", receipt.ProfileVersion);
            writer.WriteString(
                "SourceRepository",
                receipt.SourceRepository);
            writer.WriteString("SourceCommit", receipt.SourceCommit);
            writer.WriteString("ReleaseVersion", receipt.ReleaseVersion);
            writer.WriteString("SignerPolicyId", receipt.SignerPolicyId);
            writer.WriteString(
                "TimestampPolicyId",
                receipt.TimestampPolicyId);
            writer.WriteString(
                "SubmitterSpkiSha256",
                receipt.SubmitterSpkiSha256);
            writer.WriteString(
                "ApproverSpkiSha256",
                receipt.ApproverSpkiSha256);
            writer.WriteString(
                "ReceiptSignerSpkiSha256",
                receipt.ReceiptSignerSpkiSha256);
            WriteArtifacts(
                writer,
                "UnsignedArtifacts",
                receipt.UnsignedArtifacts);
            WriteArtifacts(
                writer,
                "ResultArtifacts",
                receipt.ResultArtifacts);
            writer.WriteStartArray("AuthenticodeArtifacts");
            foreach (ReceiptAuthenticodeArtifactV1 artifact
                     in receipt.AuthenticodeArtifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("Role", artifact.Role);
                writer.WriteString("File", artifact.File);
                writer.WriteString(
                    "UnsignedSha256",
                    artifact.UnsignedSha256);
                writer.WriteString(
                    "SignedSha256",
                    artifact.SignedSha256);
                writer.WriteString(
                    "SignerThumbprint",
                    artifact.SignerThumbprint);
                writer.WriteString(
                    "TimestampAuthorityThumbprint",
                    artifact.TimestampAuthorityThumbprint);
                writer.WriteString(
                    "TimestampedAt",
                    FormatTimestamp(artifact.TimestampedAt));
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteString("WorkerVersion", receipt.WorkerVersion);
            writer.WriteString("SignToolSha256", receipt.SignToolSha256);
            writer.WriteNumber(
                "SigningAuditSequence",
                receipt.SigningAuditSequence);
            writer.WriteString(
                "CompletedAt",
                FormatTimestamp(receipt.CompletedAt));
            writer.WriteEndObject();
        }

        if (buffer.WrittenCount + 1 > MaximumReceiptJsonBytes)
        {
            throw new InvalidOperationException(
                "Serialized signing receipt exceeds its protocol bound.");
        }

        byte[] result = new byte[buffer.WrittenCount + 1];
        buffer.WrittenSpan.CopyTo(result);
        result[^1] = (byte)'\n';
        return result;
    }

    private static void WriteArtifacts(
        Utf8JsonWriter writer,
        string propertyName,
        IEnumerable<ReceiptArtifactV1> artifacts)
    {
        writer.WriteStartArray(propertyName);
        foreach (ReceiptArtifactV1 artifact in artifacts)
        {
            writer.WriteStartObject();
            writer.WriteString("Role", artifact.Role);
            writer.WriteString("File", artifact.File);
            writer.WriteNumber("Size", artifact.Size);
            writer.WriteString("Sha256", artifact.Sha256);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }
}

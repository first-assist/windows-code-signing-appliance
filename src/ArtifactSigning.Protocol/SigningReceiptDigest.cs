using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Protocol;

public static class SigningReceiptDigest
{
    public const string AlgorithmIdentifier =
        "ArtifactSigningReceiptDigestV1";

    private static readonly byte[] DomainBytes =
        Encoding.ASCII.GetBytes(AlgorithmIdentifier);

    public static string ComputeHex(ReadOnlySpan<byte> receiptJson)
    {
        if (receiptJson.IsEmpty
            || receiptJson.Length
                > ArtifactSigningReceiptJsonSerializer.MaximumReceiptJsonBytes)
        {
            throw new ArgumentException(
                "Receipt bytes are empty or exceed the protocol bound.",
                nameof(receiptJson));
        }

        Span<byte> domainLength = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(
            domainLength,
            checked((uint)DomainBytes.Length));

        Span<byte> receiptLength = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(
            receiptLength,
            checked((ulong)receiptJson.Length));

        using IncrementalHash hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domainLength);
        hash.AppendData(DomainBytes);
        hash.AppendData(receiptLength);
        hash.AppendData(receiptJson);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}

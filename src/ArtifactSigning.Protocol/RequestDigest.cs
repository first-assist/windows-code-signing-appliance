using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Protocol;

public static class RequestDigest
{
    public const string AlgorithmIdentifier = "ArtifactSigningRequestDigestV1";

    private static readonly byte[] DomainBytes = Encoding.ASCII.GetBytes(AlgorithmIdentifier);

    public static string ComputeHex(ReadOnlySpan<byte> requestJson)
    {
        Span<byte> domainLength = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(domainLength, checked((uint)DomainBytes.Length));

        Span<byte> requestLength = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(requestLength, checked((ulong)requestJson.Length));

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domainLength);
        hash.AppendData(DomainBytes);
        hash.AppendData(requestLength);
        hash.AppendData(requestJson);

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}

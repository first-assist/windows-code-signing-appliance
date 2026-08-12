using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Protocol;

public static class AuditEventDigest
{
    public const string AlgorithmIdentifier = "ArtifactSigningAuditEventDigestV1";

    public const string GenesisPreviousEventDigest =
        "0000000000000000000000000000000000000000000000000000000000000000";

    private const int MaximumIdentifierCharacters = 64;

    private static readonly byte[] DomainBytes = Encoding.ASCII.GetBytes(AlgorithmIdentifier);

    public static string ComputeHex(AuditEventV1 auditEvent)
    {
        Validate(auditEvent);

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendLengthPrefixed(hash, DomainBytes);
        AppendHexDigest(hash, auditEvent.PreviousEventDigest);

        Span<byte> sequence = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(sequence, auditEvent.Sequence);
        hash.AppendData(sequence);

        AppendAscii(
            hash,
            auditEvent.OccurredAt.ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture));
        AppendAscii(hash, auditEvent.Component.ToString());
        AppendAscii(hash, auditEvent.EventType);
        AppendAscii(hash, auditEvent.RequestId?.ToString("D"));
        AppendOptionalHexDigest(hash, auditEvent.RequestDigest);
        AppendAscii(hash, auditEvent.State?.ToString());
        AppendAscii(hash, auditEvent.ResultCode);
        AppendOptionalHexDigest(hash, auditEvent.EvidenceDigest);

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void Validate(AuditEventV1 auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        if (auditEvent.Sequence is 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(auditEvent),
                "Audit sequence must be positive.");
        }

        if (auditEvent.OccurredAt.Offset != TimeSpan.Zero
            || auditEvent.OccurredAt.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentException(
                "Audit timestamp must be UTC with whole-second precision.",
                nameof(auditEvent));
        }

        if (!Enum.IsDefined(auditEvent.Component))
        {
            throw new ArgumentException("Audit component is not defined.", nameof(auditEvent));
        }

        if (!StrictJsonRules.IsSafeIdentifier(
                auditEvent.EventType,
                MaximumIdentifierCharacters))
        {
            throw new ArgumentException("Audit event type is invalid.", nameof(auditEvent));
        }

        if (!StrictJsonRules.IsLowerHex(auditEvent.PreviousEventDigest, 64))
        {
            throw new ArgumentException(
                "Previous audit event digest is invalid.",
                nameof(auditEvent));
        }

        if (auditEvent.RequestId is Guid requestId && requestId == Guid.Empty)
        {
            throw new ArgumentException("Audit request identifier is invalid.", nameof(auditEvent));
        }

        ValidateOptionalDigest(auditEvent.RequestDigest, "Request digest", auditEvent);

        if (auditEvent.State is RequestState state && !Enum.IsDefined(state))
        {
            throw new ArgumentException("Audit request state is not defined.", nameof(auditEvent));
        }

        if (auditEvent.ResultCode is not null
            && !StrictJsonRules.IsSafeIdentifier(
                auditEvent.ResultCode,
                MaximumIdentifierCharacters))
        {
            throw new ArgumentException("Audit result code is invalid.", nameof(auditEvent));
        }

        ValidateOptionalDigest(auditEvent.EvidenceDigest, "Evidence digest", auditEvent);
    }

    private static void ValidateOptionalDigest(
        string? digest,
        string fieldName,
        AuditEventV1 auditEvent)
    {
        if (digest is not null && !StrictJsonRules.IsLowerHex(digest, 64))
        {
            throw new ArgumentException($"{fieldName} is invalid.", nameof(auditEvent));
        }
    }

    private static void AppendAscii(IncrementalHash hash, string? value)
    {
        AppendLengthPrefixed(
            hash,
            value is null ? ReadOnlySpan<byte>.Empty : Encoding.ASCII.GetBytes(value));
    }

    private static void AppendOptionalHexDigest(IncrementalHash hash, string? digest)
    {
        if (digest is null)
        {
            AppendLengthPrefixed(hash, ReadOnlySpan<byte>.Empty);
            return;
        }

        AppendHexDigest(hash, digest);
    }

    private static void AppendHexDigest(IncrementalHash hash, string digest)
    {
        AppendLengthPrefixed(hash, Convert.FromHexString(digest));
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }
}

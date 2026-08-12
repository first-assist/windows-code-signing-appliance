namespace ArtifactSigning.Protocol;

public enum AuditComponent
{
    Gateway,
    Worker,
}

public sealed record AuditEventV1(
    ulong Sequence,
    DateTimeOffset OccurredAt,
    AuditComponent Component,
    string EventType,
    string PreviousEventDigest,
    Guid? RequestId,
    string? RequestDigest,
    RequestState? State,
    string? ResultCode,
    string? EvidenceDigest);

public sealed record AuditHeadV1
{
    public AuditHeadV1(
        ulong sequence,
        string eventDigest)
    {
        ArgumentNullException.ThrowIfNull(eventDigest);
        if (!StrictJsonRules.IsLowerHex(
                eventDigest,
                64)
            || sequence is 0
                && !string.Equals(
                    eventDigest,
                    AuditEventDigest
                        .GenesisPreviousEventDigest,
                    StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Audit head is invalid.");
        }

        Sequence = sequence;
        EventDigest = eventDigest;
    }

    public ulong Sequence { get; }

    public string EventDigest { get; }
}

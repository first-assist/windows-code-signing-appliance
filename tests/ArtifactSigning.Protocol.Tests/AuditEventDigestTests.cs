using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class AuditEventDigestTests
{
    private const string PreviousDigest =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string RequestDigest =
        "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";

    private const string EvidenceDigest =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    [Fact]
    public void AlgorithmIdentifierHasPinnedAsciiLength()
    {
        Assert.Equal(33, Encoding.ASCII.GetByteCount(AuditEventDigest.AlgorithmIdentifier));
    }

    [Fact]
    public void ComputeHexMatchesGenesisEventVector()
    {
        AuditEventV1 auditEvent = new(
            1,
            new DateTimeOffset(2026, 7, 27, 10, 0, 0, TimeSpan.Zero),
            AuditComponent.Gateway,
            "RequestReceived",
            AuditEventDigest.GenesisPreviousEventDigest,
            null,
            null,
            null,
            null,
            null);

        string actual = AuditEventDigest.ComputeHex(auditEvent);

        Assert.Equal(
            "debc4d8c74474d021c5d050a33d5ff8b0e7fb31247564200a26d82fabcb6cc5b",
            actual);
    }

    [Fact]
    public void ComputeHexMatchesCompleteEventVector()
    {
        AuditEventV1 auditEvent = CompleteEvent();

        string actual = AuditEventDigest.ComputeHex(auditEvent);

        Assert.Equal(
            "3eaa6b40c4ab5f6dfea8446b2bddf2f411f58b546e72c3b81a170ea76f3b2fd8",
            actual);
    }

    [Fact]
    public void ComputeHexBindsPreviousDigestAndEveryEventField()
    {
        AuditEventV1 original = CompleteEvent();
        string originalDigest = AuditEventDigest.ComputeHex(original);

        AuditEventV1[] changedEvents =
        [
            original with { Sequence = 43 },
            original with { OccurredAt = original.OccurredAt.AddSeconds(1) },
            original with { Component = AuditComponent.Gateway },
            original with { EventType = "SigningFailed" },
            original with { PreviousEventDigest = EvidenceDigest },
            original with { RequestId = Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abd") },
            original with { RequestDigest = EvidenceDigest },
            original with { State = RequestState.Quarantined },
            original with { ResultCode = "TimestampFailed" },
            original with { EvidenceDigest = RequestDigest },
        ];

        Assert.All(
            changedEvents,
            changed => Assert.NotEqual(originalDigest, AuditEventDigest.ComputeHex(changed)));
    }

    [Fact]
    public void ComputeHexBindsAbsentAndPresentOptionalValues()
    {
        AuditEventV1 withoutOptionals = CompleteEvent() with
        {
            RequestId = null,
            RequestDigest = null,
            State = null,
            ResultCode = null,
            EvidenceDigest = null,
        };

        Assert.NotEqual(
            AuditEventDigest.ComputeHex(CompleteEvent()),
            AuditEventDigest.ComputeHex(withoutOptionals));
    }

    [Fact]
    public void ComputeHexRejectsInvalidAuditValues()
    {
        AuditEventV1 auditEvent = CompleteEvent() with { Sequence = 0 };

        Assert.Throws<ArgumentOutOfRangeException>(
            () => AuditEventDigest.ComputeHex(auditEvent));
    }

    [Fact]
    public void ComputeHexRejectsNonCanonicalTimestamp()
    {
        AuditEventV1 offsetEvent = CompleteEvent() with
        {
            OccurredAt = new DateTimeOffset(2026, 7, 27, 11, 5, 0, TimeSpan.FromHours(1)),
        };

        Assert.Throws<ArgumentException>(() => AuditEventDigest.ComputeHex(offsetEvent));
    }

    private static AuditEventV1 CompleteEvent()
    {
        return new AuditEventV1(
            42,
            new DateTimeOffset(2026, 7, 27, 10, 5, 0, TimeSpan.Zero),
            AuditComponent.Worker,
            "SigningCompleted",
            PreviousDigest,
            Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
            RequestDigest,
            RequestState.Signed,
            "TimestampVerified",
            EvidenceDigest);
    }
}

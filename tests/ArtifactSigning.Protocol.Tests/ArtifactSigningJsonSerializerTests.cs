using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ArtifactSigningJsonSerializerTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 19, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RequestSerializerProducesCanonicalParseableBytes()
    {
        ArtifactSigningRequestV1 request = new(
            Guid.Parse(
                "018f84a7-2f4c-7d8e-a123-123456789abc"),
            "example-project",
            "ExampleProfileV1",
            1,
            "example/project",
            new string('1', 40),
            "1.2.3",
            Now,
            Now.AddMinutes(15),
            CanonicalNonce(0x11),
            "ExampleSignerV1",
            "ExampleTimestampV1",
            [
                new RequestArtifactV1(
                    "Agent",
                    "agent.exe",
                    12,
                    new string('a', 64)),
            ]);

        byte[] first =
            ArtifactSigningRequestJsonSerializer.Serialize(
                request);
        byte[] second =
            ArtifactSigningRequestJsonSerializer.Serialize(
                request);
        RequestJsonParseResult parsed =
            ArtifactSigningRequestJsonParser.Parse(first);

        Assert.Equal(first, second);
        Assert.EndsWith(
            "\n",
            Encoding.UTF8.GetString(first),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "\r",
            Encoding.UTF8.GetString(first),
            StringComparison.Ordinal);
        Assert.True(parsed.IsSuccess);
        Assert.Equal(request.RequestId, parsed.Request?.RequestId);
        Assert.Equal(
            request.Artifacts,
            parsed.Request?.Artifacts);
    }

    [Fact]
    public void ApprovalSerializerProducesCanonicalParseableBytes()
    {
        ArtifactSigningApprovalV1 approval = new(
            Guid.Parse(
                "018f84a7-2f4c-7d8e-a123-123456789abc"),
            new string('b', 64),
            ApprovalDecision.Approve,
            "Reviewed release accepted",
            Now,
            Now.AddMinutes(5),
            CanonicalNonce(0x22));

        byte[] first =
            ArtifactSigningApprovalJsonSerializer.Serialize(
                approval);
        byte[] second =
            ArtifactSigningApprovalJsonSerializer.Serialize(
                approval);
        ApprovalJsonParseResult parsed =
            ArtifactSigningApprovalJsonParser.Parse(first);

        Assert.Equal(first, second);
        Assert.DoesNotContain(
            "\r",
            Encoding.UTF8.GetString(first),
            StringComparison.Ordinal);
        Assert.True(parsed.IsSuccess);
        Assert.Equal(approval, parsed.Approval);
    }

    [Fact]
    public void SerializersRejectInvalidModels()
    {
        ArtifactSigningRequestV1 invalidRequest = new(
            Guid.Empty,
            "example-project",
            "ExampleProfileV1",
            1,
            "example/project",
            new string('1', 40),
            "1.2.3",
            Now,
            Now.AddMinutes(15),
            CanonicalNonce(0x33),
            "ExampleSignerV1",
            "ExampleTimestampV1",
            [
                new RequestArtifactV1(
                    "Agent",
                    "agent.exe",
                    12,
                    new string('a', 64)),
            ]);

        Assert.Throws<ArgumentException>(
            () => ArtifactSigningRequestJsonSerializer
                .Serialize(invalidRequest));
    }

    private static string CanonicalNonce(byte value)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(value, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

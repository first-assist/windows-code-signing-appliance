using System.Text;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerNotificationProtocolTests
{
    [Fact]
    public void RoundTripsOnlyCanonicalLowercaseRequestId()
    {
        Guid expected = Guid.Parse(
            "018f84a7-2f4c-7d8e-a123-123456789abc");
        byte[] encoded = WorkerNotificationProtocol.Encode(expected);

        bool accepted = WorkerNotificationProtocol.TryDecode(
            encoded,
            out Guid actual);

        Assert.True(accepted);
        Assert.Equal(expected, actual);
        Assert.Equal(
            WorkerNotificationProtocol.RequestIdMessageBytes,
            encoded.Length);
    }

    [Theory]
    [InlineData("018F84A7-2F4C-7D8E-A123-123456789ABC")]
    [InlineData("{018f84a7-2f4c-7d8e-a123-123456789abc}")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("018f84a7-2f4c-7d8e-a123-123456789ab")]
    [InlineData("018f84a7-2f4c-7d8e-a123-123456789abcd")]
    public void RejectsNoncanonicalMessages(string message)
    {
        Assert.False(WorkerNotificationProtocol.TryDecode(
            Encoding.ASCII.GetBytes(message),
            out _));
    }

    [Fact]
    public void EncodeRejectsEmptyRequestId()
    {
        Assert.Throws<ArgumentException>(
            () => WorkerNotificationProtocol.Encode(Guid.Empty));
    }
}

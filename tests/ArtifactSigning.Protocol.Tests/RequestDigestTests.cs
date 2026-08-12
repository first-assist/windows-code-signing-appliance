using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class RequestDigestTests
{
    [Fact]
    public void AlgorithmIdentifierHasPinnedAsciiLength()
    {
        Assert.Equal(30, Encoding.ASCII.GetByteCount(RequestDigest.AlgorithmIdentifier));
    }

    [Fact]
    public void ComputeHexMatchesEmptyRequestVector()
    {
        const string expected = "ee4629c5aff6fae13160c3b7560325f5fe8aefe2305746a822920f7e52445041";

        string actual = RequestDigest.ComputeHex([]);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ComputeHexMatchesEmptyObjectVector()
    {
        const string expected = "af0cd964a7ac88d625e3a981e72809b7d19c9b52a876aeed5a6a20a825ab8e69";
        byte[] requestJson = "{}"u8.ToArray();

        string actual = RequestDigest.ComputeHex(requestJson);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ComputeHexBindsExactRequestBytes()
    {
        byte[] compact = "{}"u8.ToArray();
        byte[] trailingNewline = "{}\n"u8.ToArray();

        string compactDigest = RequestDigest.ComputeHex(compact);
        string trailingNewlineDigest = RequestDigest.ComputeHex(trailingNewline);

        Assert.NotEqual(compactDigest, trailingNewlineDigest);
    }
}

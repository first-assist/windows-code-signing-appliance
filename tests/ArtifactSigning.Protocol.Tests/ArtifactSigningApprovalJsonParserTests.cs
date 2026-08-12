using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ArtifactSigningApprovalJsonParserTests
{
    private const string ValidJson = """
        {
          "Format": "ArtifactSigningApprovalV1",
          "RequestId": "018f84a7-2f4c-7d8e-a123-123456789abc",
          "RequestDigest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "Decision": "Approve",
          "Reason": "Project release candidate accepted",
          "ApprovedAt": "2026-07-27T10:01:00Z",
          "ExpiresAt": "2026-07-27T10:06:00Z",
          "Nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        }
        """;

    [Fact]
    public void ParseAcceptsValidClosedApproval()
    {
        ApprovalJsonParseResult result = Parse(ValidJson);

        Assert.True(result.IsSuccess);
        Assert.Equal(ApprovalJsonError.None, result.Error);
        Assert.NotNull(result.Approval);
        Assert.Equal(ApprovalDecision.Approve, result.Approval.Decision);
        Assert.Equal(
            new DateTimeOffset(2026, 7, 27, 10, 6, 0, TimeSpan.Zero),
            result.Approval.ExpiresAt);
    }

    [Fact]
    public void ParseAcceptsExplicitRejection()
    {
        string json = ValidJson.Replace(
            "\"Decision\": \"Approve\"",
            "\"Decision\": \"Reject\"",
            StringComparison.Ordinal);

        ApprovalJsonParseResult result = Parse(json);

        Assert.True(result.IsSuccess);
        Assert.Equal(ApprovalDecision.Reject, result.Approval?.Decision);
    }

    [Theory]
    [InlineData("\"Decision\": \"Approve\",", "\"Decision\": \"Approve\", \"Decision\": \"Reject\",", ApprovalJsonError.DuplicateProperty)]
    [InlineData("\"Decision\": \"Approve\",", "\"Decision\": \"Approve\", \"Command\": \"sign\",", ApprovalJsonError.UnknownProperty)]
    [InlineData("  \"Reason\": \"Project release candidate accepted\",\n", "", ApprovalJsonError.MissingProperty)]
    [InlineData("\"RequestId\"", "\"Request\\u0049d\"", ApprovalJsonError.NonCanonicalPropertyName)]
    public void ParseRejectsNonClosedObjectShape(
        string oldValue,
        string newValue,
        ApprovalJsonError expected)
    {
        AssertError(ValidJson.Replace(oldValue, newValue, StringComparison.Ordinal), expected);
    }

    [Fact]
    public void ParseRejectsInvalidUtf8()
    {
        byte[] invalid = [0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d];

        ApprovalJsonParseResult result = ArtifactSigningApprovalJsonParser.Parse(invalid);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApprovalJsonError.Malformed, result.Error);
    }

    [Theory]
    [InlineData(
        "018F84A7-2F4C-7D8E-A123-123456789ABC",
        "018f84a7-2f4c-7d8e-a123-123456789abc")]
    [InlineData(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void ParseRejectsNonCanonicalIdentifier(string replacement, string original)
    {
        AssertError(
            ValidJson.Replace(original, replacement, StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Theory]
    [InlineData("approve")]
    [InlineData("Approved")]
    [InlineData("")]
    public void ParseRejectsUnknownDecision(string decision)
    {
        AssertError(
            ValidJson.Replace(
                "\"Decision\": \"Approve\"",
                $"\"Decision\": \"{decision}\"",
                StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Theory]
    [InlineData(" Project release candidate accepted")]
    [InlineData("Project release candidate accepted ")]
    [InlineData("Project\\nrelease candidate accepted")]
    [InlineData("Project \u202eaccepted")]
    public void ParseRejectsUnsafeReason(string reason)
    {
        AssertError(
            ValidJson.Replace(
                "Project release candidate accepted",
                reason,
                StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsReasonOverUtf8ByteLimit()
    {
        string reason = new('é', (ArtifactSigningApprovalJsonParser.MaximumReasonUtf8Bytes / 2) + 1);
        string json = ValidJson.Replace(
            "Project release candidate accepted",
            reason,
            StringComparison.Ordinal);

        AssertError(json, ApprovalJsonError.InvalidPropertyValue);
    }

    [Theory]
    [InlineData("2026-07-27T10:01:00.000Z")]
    [InlineData("2026-07-27T11:01:00+01:00")]
    public void ParseRejectsNonCanonicalApprovalTime(string approvedAt)
    {
        AssertError(
            ValidJson.Replace(
                "2026-07-27T10:01:00Z",
                approvedAt,
                StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsApprovalWindowOverFiveMinutes()
    {
        AssertError(
            ValidJson.Replace(
                "2026-07-27T10:06:00Z",
                "2026-07-27T10:06:01Z",
                StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsNonCanonicalNonce()
    {
        AssertError(
            ValidJson.Replace(
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh_",
                StringComparison.Ordinal),
            ApprovalJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsOversizedJsonBeforeParsing()
    {
        byte[] oversized = new byte[
            ArtifactSigningApprovalJsonParser.MaximumApprovalJsonBytes + 1];
        Array.Fill(oversized, (byte)' ');

        ApprovalJsonParseResult result = ArtifactSigningApprovalJsonParser.Parse(oversized);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApprovalJsonError.TooLarge, result.Error);
    }

    private static ApprovalJsonParseResult Parse(string json)
    {
        return ArtifactSigningApprovalJsonParser.Parse(Encoding.UTF8.GetBytes(json));
    }

    private static void AssertError(string json, ApprovalJsonError expected)
    {
        ApprovalJsonParseResult result = Parse(json);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Approval);
        Assert.Equal(expected, result.Error);
    }
}

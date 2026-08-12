using System.Text;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class ArtifactSigningRequestJsonParserTests
{
    private const string ValidJson = """
        {
          "Format": "ArtifactSigningRequestV1",
          "RequestId": "018f84a7-2f4c-7d8e-a123-123456789abc",
          "ProjectId": "example-endpoint",
          "ProfileId": "ExampleEndpointBundleV1",
          "ProfileVersion": 1,
          "SourceRepository": "example/endpoint",
          "SourceCommit": "0123456789abcdef0123456789abcdef01234567",
          "ReleaseVersion": "5.9.1",
          "RequestedAt": "2026-07-27T10:00:00Z",
          "ExpiresAt": "2026-07-27T10:15:00Z",
          "Nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
          "SignerPolicyId": "LabAuthenticodeV1",
          "TimestampPolicyId": "DigiCertRfc3161V1",
          "Artifacts": [
            {
              "Role": "Manifest",
              "File": "release-manifest.json",
              "Size": 1,
              "Sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            {
              "Role": "Agent",
              "File": "example-agent.exe",
              "Size": 32,
              "Sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }
          ]
        }
        """;

    [Fact]
    public void ParseAcceptsValidClosedRequest()
    {
        RequestJsonParseResult result = Parse(ValidJson);

        Assert.True(result.IsSuccess);
        Assert.Equal(RequestJsonError.None, result.Error);
        Assert.NotNull(result.Request);
        Assert.Equal("example-endpoint", result.Request.ProjectId);
        Assert.Equal(2, result.Request.Artifacts.Count);
        Assert.Equal(
            new DateTimeOffset(2026, 7, 27, 10, 15, 0, TimeSpan.Zero),
            result.Request.ExpiresAt);
    }

    [Fact]
    public void ParseRejectsDuplicateRootProperty()
    {
        string json = ValidJson.Replace(
            "\"ProjectId\": \"example-endpoint\",",
            "\"ProjectId\": \"example-endpoint\", \"ProjectId\": \"other\",",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.DuplicateProperty);
    }

    [Fact]
    public void ParseRejectsUnknownRootProperty()
    {
        string json = ValidJson.Replace(
            "\"ProfileVersion\": 1,",
            "\"ProfileVersion\": 1, \"Command\": \"anything\",",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.UnknownProperty);
    }

    [Fact]
    public void ParseRejectsMissingRootProperty()
    {
        string json = ValidJson.Replace(
            "  \"TimestampPolicyId\": \"DigiCertRfc3161V1\",\n",
            string.Empty,
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.MissingProperty);
    }

    [Fact]
    public void ParseRejectsEscapedPropertyName()
    {
        string json = ValidJson.Replace("\"ProjectId\"", "\"Pro\\u006AectId\"", StringComparison.Ordinal);

        AssertError(json, RequestJsonError.NonCanonicalPropertyName);
    }

    [Fact]
    public void ParseRejectsNonCanonicalUuid()
    {
        string json = ValidJson.Replace(
            "018f84a7-2f4c-7d8e-a123-123456789abc",
            "018F84A7-2F4C-7D8E-A123-123456789ABC",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsNonCanonicalCommit()
    {
        string json = ValidJson.Replace(
            "0123456789abcdef0123456789abcdef01234567",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseClassifiesNonPositiveProfileVersionAsInvalidValue()
    {
        string json = ValidJson.Replace(
            "\"ProfileVersion\": 1",
            "\"ProfileVersion\": 0",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Theory]
    [InlineData("2026-07-27T10:00:00.000Z")]
    [InlineData("2026-07-27T20:00:00+10:00")]
    public void ParseRejectsTimestampThatIsNotWholeSecondUtc(string requestedAt)
    {
        string json = ValidJson.Replace(
            "2026-07-27T10:00:00Z",
            requestedAt,
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsRequestWindowOverFifteenMinutes()
    {
        string json = ValidJson.Replace(
            "2026-07-27T10:15:00Z",
            "2026-07-27T10:15:01Z",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsNonCanonicalNonce()
    {
        string json = ValidJson.Replace(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh_",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsDuplicateArtifactFile()
    {
        string json = ValidJson.Replace(
            "\"File\": \"example-agent.exe\"",
            "\"File\": \"release-manifest.json\"",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.DuplicateArtifact);
    }

    [Fact]
    public void ParseClassifiesNonPositiveArtifactSizeAsInvalidValue()
    {
        string json = ValidJson.Replace("\"Size\": 32", "\"Size\": 0", StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsPathLikeArtifactFile()
    {
        string json = ValidJson.Replace(
            "\"File\": \"example-agent.exe\"",
            "\"File\": \"../example-agent.exe\"",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.InvalidPropertyValue);
    }

    [Fact]
    public void ParseRejectsArtifactWithUnknownProperty()
    {
        string json = ValidJson.Replace(
            "\"Size\": 32,",
            "\"Size\": 32, \"OutputPath\": \"C:\\\\temp\",",
            StringComparison.Ordinal);

        AssertError(json, RequestJsonError.UnknownProperty);
    }

    [Fact]
    public void ParseRejectsMoreThanMaximumArtifactCount()
    {
        const string artifact = """
            {
              "Role": "Role{0}",
              "File": "file{0}.exe",
              "Size": 1,
              "Sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
            """;

        string artifacts = string.Join(
            ",",
            Enumerable.Range(0, ArtifactSigningRequestJsonParser.MaximumArtifacts + 1)
                .Select(index => artifact.Replace(
                    "{0}",
                    index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    StringComparison.Ordinal)));

        int arrayStart = ValidJson.IndexOf("\"Artifacts\": [", StringComparison.Ordinal);
        string prefix = ValidJson[..arrayStart];
        string json = $"{prefix}\"Artifacts\": [{artifacts}]}}";

        AssertError(json, RequestJsonError.TooManyArtifacts);
    }

    [Fact]
    public void ParseRejectsOversizedJsonBeforeParsing()
    {
        byte[] oversized = new byte[ArtifactSigningRequestJsonParser.MaximumRequestJsonBytes + 1];
        Array.Fill(oversized, (byte)' ');

        RequestJsonParseResult result = ArtifactSigningRequestJsonParser.Parse(oversized);

        Assert.False(result.IsSuccess);
        Assert.Equal(RequestJsonError.TooLarge, result.Error);
    }

    [Fact]
    public void ParseRejectsInvalidUtf8()
    {
        byte[] invalid = [0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d];

        RequestJsonParseResult result = ArtifactSigningRequestJsonParser.Parse(invalid);

        Assert.False(result.IsSuccess);
        Assert.Equal(RequestJsonError.Malformed, result.Error);
    }

    private static RequestJsonParseResult Parse(string json)
    {
        return ArtifactSigningRequestJsonParser.Parse(Encoding.UTF8.GetBytes(json));
    }

    private static void AssertError(string json, RequestJsonError expected)
    {
        RequestJsonParseResult result = Parse(json);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Request);
        Assert.Equal(expected, result.Error);
    }
}

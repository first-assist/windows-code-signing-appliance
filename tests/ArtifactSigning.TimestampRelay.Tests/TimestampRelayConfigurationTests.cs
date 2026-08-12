using Xunit;

namespace ArtifactSigning.TimestampRelay.Tests;

public sealed class TimestampRelayConfigurationTests
{
    [Fact]
    public void ParsesClosedProductionConfiguration()
    {
        TimestampRelayConfiguration configuration =
            TimestampRelayConfiguration.Parse(
                ValidConfiguration());

        Assert.Equal(
            TimestampRelayDeploymentMode.Production,
            configuration.Mode);
        Assert.Equal(
            "10.20.30.40",
            configuration.BindAddress.ToString());
        Assert.Equal(8080, configuration.BindPort);
        Assert.Equal(
            "https://timestamp.example.test/timestamp",
            configuration.UpstreamUrl.AbsoluteUri);
        Assert.Equal(2, configuration.RequestsPerMinute);
    }

    [Theory]
    [InlineData(
        "\"Mode\":\"Production\"",
        "\"Mode\":\"Laboratory\"")]
    [InlineData(
        "https://timestamp.example.test/timestamp",
        "http://timestamp.example.test/timestamp")]
    [InlineData(
        "\"BindAddress\":\"10.20.30.40\"",
        "\"BindAddress\":\"203.0.113.20\"")]
    [InlineData(
        "\"RequestsPerMinute\":2",
        "\"RequestsPerMinute\":31")]
    public void RejectsInvalidProductionPolicy(
        string oldValue,
        string newValue)
    {
        byte[] invalid = System.Text.Encoding.UTF8.GetBytes(
            System.Text.Encoding.UTF8.GetString(
                    ValidConfiguration())
                .Replace(
                    oldValue,
                    newValue,
                    StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(() =>
            TimestampRelayConfiguration.Parse(invalid));
    }

    [Fact]
    public void RejectsDuplicateAndUnknownProperties()
    {
        string valid =
            System.Text.Encoding.UTF8.GetString(
                ValidConfiguration());
        string duplicate = valid.Replace(
            "\"Mode\":\"Production\",",
            "\"Mode\":\"Production\",\"Mode\":\"Production\",",
            StringComparison.Ordinal);
        string unknown = valid.Replace(
            "\"BindPort\":8080,",
            "\"BindPort\":8080,\"ProxyUrl\":\"https://example.test/\",",
            StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(() =>
            TimestampRelayConfiguration.Parse(
                System.Text.Encoding.UTF8.GetBytes(
                    duplicate)));
        Assert.Throws<InvalidDataException>(() =>
            TimestampRelayConfiguration.Parse(
                System.Text.Encoding.UTF8.GetBytes(
                    unknown)));
    }

    [Fact]
    public void ProtectedLoadRequiresOwnerOnlyMode()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        string directory = Path.Combine(
            Path.GetTempPath(),
            $"timestamp-relay-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(
            directory,
            "timestamp-relay.json");
        try
        {
            File.WriteAllBytes(
                path,
                ValidConfiguration());
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite);
            _ = TimestampRelayConfiguration
                .LoadProtected(path);

            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead);
            Assert.Throws<UnauthorizedAccessException>(() =>
                TimestampRelayConfiguration
                    .LoadProtected(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    internal static byte[] ValidConfiguration(
        int requestsPerMinute = 2)
    {
        return System.Text.Encoding.UTF8.GetBytes(
            $$"""
            {"Format":"ArtifactSigningTimestampRelayConfigurationV1","Mode":"Production","BindAddress":"10.20.30.40","BindPort":8080,"AllowedClientAddresses":["10.20.30.41"],"UpstreamUrl":"https://timestamp.example.test/timestamp","UpstreamAddresses":["203.0.113.10"],"ConnectTimeoutSeconds":2,"TotalTimeoutSeconds":5,"RequestsPerMinute":{{requestsPerMinute}}}
            """);
    }
}

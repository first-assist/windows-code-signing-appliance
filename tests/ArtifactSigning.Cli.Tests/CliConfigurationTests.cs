using ArtifactSigning.Protocol;
using ArtifactSigning.TestProfile;
using Xunit;

namespace ArtifactSigning.Cli.Tests;

public sealed class CliConfigurationTests
{
    [Fact]
    public void ParsesStrictPemConfiguration()
    {
        CliConfiguration configuration =
            CliConfiguration.Parse(ValidJson());

        Assert.Equal(
            new Uri("https://10.20.30.20:7443/"),
            configuration.ServiceUri);
        Assert.Equal(
            CliIdentityProvider.PemFiles,
            configuration.ClientIdentity.Provider);
    }

    [Fact]
    public void RejectsUnknownPropertiesAndHttpService()
    {
        string valid = System.Text.Encoding.UTF8
            .GetString(ValidJson());
        byte[] unknown = System.Text.Encoding.UTF8.GetBytes(
            valid.Replace(
            "\"Format\":",
            "\"Unknown\":1,\"Format\":",
            StringComparison.Ordinal));
        byte[] http = System.Text.Encoding.UTF8.GetBytes(
            valid.Replace(
                "https://",
                "http://",
                StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(
            () => CliConfiguration.Parse(unknown));
        Assert.Throws<InvalidDataException>(
            () => CliConfiguration.Parse(http));
        byte[] unsafeProduction =
            System.Text.Encoding.UTF8.GetBytes(
                valid.Replace(
                    "\"Mode\":\"DisposableTest\"",
                    "\"Mode\":\"Production\"",
                    StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(
            () => CliConfiguration.Parse(
                unsafeProduction));
    }

    [Fact]
    public void ParsesRetainedLabOnlyWithExactCertificatePins()
    {
        string retained = System.Text.Encoding.UTF8.GetString(ValidJson())
            .Replace(
                "\"Mode\":\"DisposableTest\"",
                "\"Mode\":\"RetainedLab\"",
                StringComparison.Ordinal)
            .Replace(
                "\"RevocationPolicy\":\"DisposableTestNoCheck\"",
                "\"RevocationPolicy\":\"RetainedLabPinned\"",
                StringComparison.Ordinal)
            .Replace(
                "\"ExpectedSignerCertificateSha256\":null",
                "\"ExpectedSignerCertificateSha256\":\"" +
                    new string('e', 64) + "\"",
                StringComparison.Ordinal);

        CliConfiguration configuration = CliConfiguration.Parse(
            System.Text.Encoding.UTF8.GetBytes(retained));

        Assert.Equal(CliDeploymentMode.RetainedLab, configuration.Mode);
        Assert.Equal(
            new string('e', 64),
            configuration.SubmitterTrust.ExpectedSignerCertificateSha256);
        Assert.Equal(
            CmsRevocationPolicy.RetainedLabPinned,
            configuration.ReceiptTrust.RevocationPolicy);
    }

    [Theory]
    [InlineData("Production", "RetainedLabPinned", true)]
    [InlineData("DisposableTest", "RetainedLabPinned", true)]
    [InlineData("RetainedLab", "Online", false)]
    [InlineData("Production", "Online", true)]
    [InlineData("DisposableTest", "DisposableTestNoCheck", true)]
    [InlineData("RetainedLab", "RetainedLabPinned", false)]
    public void RejectsCrossModeRevocationAndPinCombinations(
        string mode,
        string revocationPolicy,
        bool includeCertificatePin)
    {
        string value = System.Text.Encoding.UTF8.GetString(ValidJson())
            .Replace(
                "\"Mode\":\"DisposableTest\"",
                $"\"Mode\":\"{mode}\"",
                StringComparison.Ordinal)
            .Replace(
                "\"RevocationPolicy\":\"DisposableTestNoCheck\"",
                $"\"RevocationPolicy\":\"{revocationPolicy}\"",
                StringComparison.Ordinal);
        if (includeCertificatePin)
        {
            value = value.Replace(
                "\"ExpectedSignerCertificateSha256\":null",
                "\"ExpectedSignerCertificateSha256\":\"" +
                    new string('e', 64) + "\"",
                StringComparison.Ordinal);
        }

        Assert.Throws<InvalidDataException>(() => CliConfiguration.Parse(
            System.Text.Encoding.UTF8.GetBytes(value)));
    }

    [Theory]
    [InlineData("\"Mode\":\"DisposableTest\"", "\"Mode\":\"1\"")]
    [InlineData("\"Mode\":\"DisposableTest\"", "\"Mode\":\"42\"")]
    [InlineData("\"Mode\":\"DisposableTest\"", "\"Mode\":\"2\"")]
    [InlineData("\"Provider\":\"PemFiles\"", "\"Provider\":\"0\"")]
    [InlineData(
        "\"RevocationPolicy\":\"DisposableTestNoCheck\"",
        "\"RevocationPolicy\":\"2\"")]
    public void RejectsNumericEnumAliases(
        string expected,
        string replacement)
    {
        string valid = System.Text.Encoding.UTF8
            .GetString(ValidJson());
        byte[] numeric = System.Text.Encoding.UTF8.GetBytes(
            valid.Replace(
                expected,
                replacement,
                StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(
            () => CliConfiguration.Parse(numeric));
    }

    [Fact]
    public async Task EmptyCommandReturnsStableUsageError()
    {
        using StringWriter output = new();
        using StringWriter error = new();
        using StringReader input = new(string.Empty);

        int exitCode = await CliApplication.RunAsync(
            [],
            output,
            error,
            input,
            TimeProvider.System,
            ExampleProfilePackage.CreatePackageSet(),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            CliApplication.UsageError,
            exitCode);
        Assert.Equal(string.Empty, output.ToString());
        Assert.DoesNotContain(
            "/",
            error.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task VersionIsMachineReadableAndRequiresNoConfiguration()
    {
        using StringWriter output = new();
        using StringWriter error = new();
        using StringReader input = new(string.Empty);

        int exitCode = await CliApplication.RunAsync(
            ["--version"],
            output,
            error,
            input,
            TimeProvider.System,
            TestContext.Current.CancellationToken);

        Assert.Equal(CliApplication.Success, exitCode);
        Assert.Equal("0.5.1", output.ToString().Trim());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public void UnixConfigurationMustBeOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string directory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signctl-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(
            directory,
            "client.json");
        try
        {
            File.WriteAllBytes(path, ValidJson());
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite);
            _ = CliConfiguration.Load(path);
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead);

            Assert.Throws<UnauthorizedAccessException>(
                () => CliConfiguration.Load(path));
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static byte[] ValidJson()
    {
        return System.Text.Encoding.UTF8.GetBytes(
            $$"""
            {
              "Format":"ArtifactSigningCliConfigurationV1",
              "Mode":"DisposableTest",
              "ServiceUri":"https://10.20.30.20:7443/",
              "ServerCertificateSha256":"{{new string('a', 64)}}",
              "ServerSpkiSha256":"{{new string('b', 64)}}",
              "ClientIdentity":{
                "Provider":"PemFiles",
                "CertificatePath":{{JsonPath("client-cert.pem")}},
                "PrivateKeyPath":{{JsonPath("client-key.pem")}},
                "PrivateKeyPasswordFile":null,
                "CertificateThumbprint":null
              },
              "SubmitterTrust":{
                "ExpectedSignerSpkiSha256":"{{new string('c', 64)}}",
                "ExpectedSignerCertificateSha256":null,
                "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                "TrustedRootCertificatePaths":[{{JsonPath("root.cer")}}],
                "ExtraCertificatePaths":[],
                "RevocationPolicy":"DisposableTestNoCheck",
                "UrlRetrievalTimeoutSeconds":1
              },
              "ReceiptTrust":{
                "ExpectedSignerSpkiSha256":"{{new string('d', 64)}}",
                "ExpectedSignerCertificateSha256":null,
                "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                "TrustedRootCertificatePaths":[{{JsonPath("receipt-root.cer")}}],
                "ExtraCertificatePaths":[],
                "RevocationPolicy":"DisposableTestNoCheck",
                "UrlRetrievalTimeoutSeconds":1
              }
            }
            """);
    }

    private static string JsonPath(string fileName)
    {
        return System.Text.Json.JsonSerializer.Serialize(
            Path.Combine(Path.GetTempPath(), fileName));
    }
}

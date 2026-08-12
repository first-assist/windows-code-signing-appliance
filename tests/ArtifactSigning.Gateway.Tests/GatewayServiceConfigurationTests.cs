using System.Text;
using ArtifactSigning.TestProfile;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayServiceConfigurationTests
{
    [Fact]
    public void ParsesClosedDisposableConfiguration()
    {
        GatewayServiceConfiguration configuration =
            GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    ConfigurationJson(
                        "DisposableTest",
                        "127.0.0.1",
                        "DisposableTestNoCheck")));

        Assert.Equal(
            GatewayDeploymentMode.DisposableTest,
            configuration.Mode);
        Assert.Equal(
            "127.0.0.1",
            configuration.ListenAddress.ToString());
        Assert.Equal(7443, configuration.ListenPort);
        Assert.Single(configuration.AuthorizationPolicies);
        Assert.Empty(configuration.Auditors);
        Assert.Equal(ProfileSetSha256, configuration.ProfileSetSha256);
    }

    [Fact]
    public void ProductionRequiresPrivateAddressOnlineRevocationAndDualControl()
    {
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    ConfigurationJson(
                        "Production",
                        "127.0.0.1",
                        "Online"))));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    ConfigurationJson(
                        "Production",
                        "10.20.30.40",
                        "DisposableTestNoCheck"))));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    ConfigurationJson(
                        "Production",
                        "10.20.30.40",
                        "Online",
                        requireDistinct: false))));
    }

    [Fact]
    public void RetainedLabRequiresPrivateListenerDualControlAndExactPins()
    {
        GatewayServiceConfiguration configuration =
            GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(RetainedConfigurationJson()));

        Assert.Equal(GatewayDeploymentMode.RetainedLab, configuration.Mode);
        Assert.Equal(
            new string('1', 64),
            configuration.AuthorizationPolicies[0]
                .SubmitterTrust.ExpectedSignerCertificateSha256);
        Assert.Equal(
            new string('3', 64),
            configuration.ReceiptTrust.ExpectedSignerCertificateSha256);

        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfigurationJson().Replace(
                        "\"ListenAddress\":\"10.20.30.40\"",
                        "\"ListenAddress\":\"127.0.0.1\"",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfigurationJson().Replace(
                        "RetainedLabPinned",
                        "Online",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfigurationJson().Replace(
                        "\"RequireDistinctSubmitterAndApprover\":true",
                        "\"RequireDistinctSubmitterAndApprover\":false",
                        StringComparison.Ordinal))));
    }

    [Fact]
    public void RejectsUnknownDuplicateAndIdentityMismatch()
    {
        string unknown = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                "\"Format\":",
                "\"Unknown\":true,\"Format\":",
                StringComparison.Ordinal);
        string duplicate = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                "\"ListenPort\":7443",
                "\"ListenPort\":7443,\"ListenPort\":7443",
                StringComparison.Ordinal);
        string mismatch = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                $"\"ExpectedSignerSpkiSha256\":\"{new string('a', 64)}\"",
                $"\"ExpectedSignerSpkiSha256\":\"{new string('e', 64)}\"",
                StringComparison.Ordinal);
        string numericMode = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                "\"Mode\":\"DisposableTest\"",
                "\"Mode\":\"1\"",
                StringComparison.Ordinal);
        string numericRevocation = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                "DisposableTestNoCheck",
                "2",
                StringComparison.Ordinal);
        string disposablePin = ConfigurationJson(
                "DisposableTest",
                "127.0.0.1",
                "DisposableTestNoCheck")
            .Replace(
                $"\"ExpectedSignerSpkiSha256\":\"{new string('a', 64)}\",",
                $"\"ExpectedSignerSpkiSha256\":\"{new string('a', 64)}\",\"ExpectedSignerCertificateSha256\":null,",
                StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(unknown)));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(duplicate)));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(mismatch)));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(numericMode)));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(numericRevocation)));
        Assert.Throws<InvalidDataException>(
            () => GatewayServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(disposablePin)));
    }

    private static string ConfigurationJson(
        string mode,
        string address,
        string revocationPolicy,
        bool requireDistinct = true)
    {
        return $$"""
            {
              "Format":"ArtifactSigningGatewayConfigurationV2",
              "Mode":"{{mode}}",
              "ProfileSetSha256":"{{ProfileSetSha256}}",
              "GatewayServiceSid":"S-1-5-80-1-2-3-4-5",
              "WorkerServiceSid":"S-1-5-80-6-7-8-9-10",
              "ListenAddress":"{{address}}",
              "ListenPort":7443,
              "ServerCertificateThumbprint":"{{new string('B', 40)}}",
              "AuthorizationPolicies":[
                {
                  "ProjectId":"example-endpoint",
                  "ProfileId":"ExampleEndpointBundleV1",
                  "ProfileVersion":2,
                  "SubmitterClient":{
                    "CertificateSha256":"{{new string('1', 64)}}",
                    "SubjectPublicKeyInfoSha256":"{{new string('a', 64)}}"
                  },
                  "SubmitterTrust":{
                    "ExpectedSignerSpkiSha256":"{{new string('a', 64)}}",
                    "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                    "TrustedRootThumbprints":["{{new string('C', 40)}}"],
                    "ExtraCertificateThumbprints":[],
                    "RevocationPolicy":"{{revocationPolicy}}",
                    "UrlRetrievalTimeoutSeconds":1
                  },
                  "ApproverClient":{
                    "CertificateSha256":"{{new string('2', 64)}}",
                    "SubjectPublicKeyInfoSha256":"{{new string('b', 64)}}"
                  },
                  "ApproverTrust":{
                    "ExpectedSignerSpkiSha256":"{{new string('b', 64)}}",
                    "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                    "TrustedRootThumbprints":["{{new string('C', 40)}}"],
                    "ExtraCertificateThumbprints":[],
                    "RevocationPolicy":"{{revocationPolicy}}",
                    "UrlRetrievalTimeoutSeconds":1
                  },
                  "RequireDistinctSubmitterAndApprover":{{(requireDistinct ? "true" : "false")}}
                }
              ],
              "Auditors":[],
              "ReceiptTrust":{
                "ExpectedSignerSpkiSha256":"{{new string('d', 64)}}",
                "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                "TrustedRootThumbprints":["{{new string('C', 40)}}"],
                "ExtraCertificateThumbprints":[],
                "RevocationPolicy":"{{revocationPolicy}}",
                "UrlRetrievalTimeoutSeconds":1
              }
            }
            """;
    }

    private static string RetainedConfigurationJson()
    {
        return ConfigurationJson(
                "RetainedLab",
                "10.20.30.40",
                "RetainedLabPinned")
            .Replace(
                $"\"ExpectedSignerSpkiSha256\":\"{new string('a', 64)}\",",
                $"\"ExpectedSignerSpkiSha256\":\"{new string('a', 64)}\",\"ExpectedSignerCertificateSha256\":\"{new string('1', 64)}\",",
                StringComparison.Ordinal)
            .Replace(
                $"\"ExpectedSignerSpkiSha256\":\"{new string('b', 64)}\",",
                $"\"ExpectedSignerSpkiSha256\":\"{new string('b', 64)}\",\"ExpectedSignerCertificateSha256\":\"{new string('2', 64)}\",",
                StringComparison.Ordinal)
            .Replace(
                $"\"ExpectedSignerSpkiSha256\":\"{new string('d', 64)}\",",
                $"\"ExpectedSignerSpkiSha256\":\"{new string('d', 64)}\",\"ExpectedSignerCertificateSha256\":\"{new string('3', 64)}\",",
                StringComparison.Ordinal);
    }

    private static string ProfileSetSha256 =>
            ExampleProfilePackage.CreatePackageSet().PackageSetSha256;
}

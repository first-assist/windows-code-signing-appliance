using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using ArtifactSigning.Protocol;
using ArtifactSigning.TestProfile;
using ArtifactSigning.Windows;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerServiceConfigurationTests
{
    [Fact]
    public void ParsesClosedProductionConfiguration()
    {
        WorkerServiceConfiguration configuration =
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(ValidConfiguration));

        Assert.Equal(
            WorkerDeploymentMode.Production,
            configuration.Mode);
        WorkerAuthorizationConfiguration authorization =
            Assert.Single(configuration.AuthorizationPolicies);
        Assert.True(
            authorization.RequireDistinctSubmitterAndApprover);
        Assert.NotEqual(
            authorization.SubmitterTrust
                .ExpectedSignerSpkiSha256,
            authorization.ApproverTrust
                .ExpectedSignerSpkiSha256);
        WorkerSigningConfiguration signing =
            Assert.Single(configuration.SigningPolicies);
        WorkerLocalMachineCertificateSigningConfiguration local =
            Assert.IsType<WorkerLocalMachineCertificateSigningConfiguration>(
                signing.ProviderConfiguration);
        Assert.Equal(
            WindowsTrustRevocationPolicy.Online,
            local.AuthenticodeRevocationPolicy);
        Assert.Equal(
            CmsRevocationPolicy.Online,
            configuration.Receipt.Trust.RevocationPolicy);
        Assert.Equal(ProfileSetSha256, configuration.ProfileSetSha256);
    }

    [Fact]
    public void ParsesClosedMicrosoftArtifactSigningProvider()
    {
        WorkerServiceConfiguration configuration =
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(CreateManagedConfiguration()));

        WorkerSigningConfiguration signing =
            Assert.Single(configuration.SigningPolicies);
        Assert.Equal(
            WorkerSigningProvider.MicrosoftArtifactSigning,
            signing.Provider);
        WorkerMicrosoftArtifactSigningConfiguration managed =
            Assert.IsType<WorkerMicrosoftArtifactSigningConfiguration>(
                signing.ProviderConfiguration);
        Assert.Equal(
            MicrosoftArtifactSigningRegion.JapanEast,
            managed.Region);
        Assert.Equal("example-signing-account", managed.CodeSigningAccountName);
        Assert.Equal("Example-PublicTrust", managed.CertificateProfileName);
        Assert.Equal(
            "1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699",
            managed.RequiredPublisherEnhancedKeyUsageOid);
        Assert.Equal(
            WindowsTrustRevocationPolicy.Online,
            managed.AuthenticodeRevocationPolicy);
    }

    [Fact]
    public void PublicTrustTestRequiresDisposableModeAndTestEku()
    {
        string production = CreateManagedConfiguration();
        string disposable = production
            .Replace(
                "\"Mode\":\"Production\"",
                "\"Mode\":\"DisposableTest\"",
                StringComparison.Ordinal)
            .Replace(
                "\"CertificateProfileName\":\"Example-PublicTrust\"",
                "\"CertificateProfileName\":\"Example-PublicTrust-Test\"",
                StringComparison.Ordinal)
            .Replace(
                "1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699",
                "1.3.6.1.4.1.311.97.1.2.102758219.576488180.915968236.896939699",
                StringComparison.Ordinal)
            .Replace(
                "\"RevocationPolicy\":\"Online\"",
                "\"RevocationPolicy\":\"DisposableTestNoCheck\"",
                StringComparison.Ordinal)
            .Replace(
                "\"AuthenticodeRevocationPolicy\":\"Online\"",
                "\"AuthenticodeRevocationPolicy\":\"DisposableTestNoCheck\"",
                StringComparison.Ordinal);

        WorkerServiceConfiguration configuration =
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(disposable));
        WorkerMicrosoftArtifactSigningConfiguration managed =
            Assert.IsType<WorkerMicrosoftArtifactSigningConfiguration>(
                Assert.Single(configuration.SigningPolicies)
                    .ProviderConfiguration);
        Assert.StartsWith(
            "1.3.6.1.4.1.311.97.1.2.",
            managed.RequiredPublisherEnhancedKeyUsageOid,
            StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(() =>
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    disposable.Replace(
                        "\"Mode\":\"DisposableTest\"",
                        "\"Mode\":\"Production\"",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() =>
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    production.Replace(
                        "\"Mode\":\"Production\"",
                        "\"Mode\":\"DisposableTest\"",
                        StringComparison.Ordinal))));
    }

    [Fact]
    public void MicrosoftProviderRejectsAmbiguousOrRetainedConfiguration()
    {
        string valid = CreateManagedConfiguration();
        Assert.Throws<InvalidDataException>(() =>
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    valid.Replace(
                        "\"MicrosoftArtifactSigning\":{",
                        "\"LocalMachineCertificate\":null,\"MicrosoftArtifactSigning\":{",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() =>
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    valid.Replace(
                        "\"Mode\":\"Production\"",
                        "\"Mode\":\"RetainedLab\"",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() =>
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    valid.Replace(
                        "\"AuthenticodeRevocationPolicy\":\"Online\"",
                        "\"AuthenticodeRevocationPolicy\":\"OfflineCache\"",
                        StringComparison.Ordinal))));
    }

    [Theory]
    [InlineData(
        "\"Format\":\"ArtifactSigningWorkerConfigurationV2\",",
        "\"Format\":\"ArtifactSigningWorkerConfigurationV2\",\"Format\":\"ArtifactSigningWorkerConfigurationV2\",")]
    [InlineData(
        "\"Mode\":\"Production\",",
        "\"Mode\":\"Production\",\"Unexpected\":true,")]
    [InlineData(
        "\"Mode\":\"Production\",",
        "\"mode\":\"Production\",")]
    [InlineData(
        "\"Mode\":\"Production\",",
        "\"Mode\":\"0\",")]
    [InlineData(
        "\"WorkerServiceSid\":\"S-1-5-80-100-200-300-400-500\",",
        "\"WorkerServiceSid\":\"S-1-5-18\",")]
    [InlineData(
        "\"SignToolPath\":\"C:\\\\Program Files\\\\Windows Kits\\\\10\\\\bin\\\\signtool.exe\",",
        "\"SignToolPath\":\"cmd.exe /c signtool.exe\",")]
    [InlineData(
        "\"RevocationPolicy\":\"Online\",",
        "\"RevocationPolicy\":\"DisposableTestNoCheck\",")]
    [InlineData(
        "\"RevocationPolicy\":\"Online\",",
        "\"RevocationPolicy\":\"0\",")]
    [InlineData(
        "\"AuthenticodeRevocationPolicy\":\"Online\"",
        "\"AuthenticodeRevocationPolicy\":\"DisposableTestNoCheck\"")]
    [InlineData(
        "\"AuthenticodeRevocationPolicy\":\"Online\"",
        "\"AuthenticodeRevocationPolicy\":\"0\"")]
    public void RejectsNonclosedOrUnsafeConfiguration(
        string expected,
        string replacement)
    {
        string altered = ValidConfiguration.Replace(
            expected,
            replacement,
            StringComparison.Ordinal);
        Assert.NotEqual(ValidConfiguration, altered);

        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(altered)));
    }

    [Fact]
    public void ProductionRequiresDistinctDualControl()
    {
        string altered = ValidConfiguration
            .Replace(
                new string('e', 64),
                new string('d', 64),
                StringComparison.Ordinal)
            .Replace(
                "\"RequireDistinctSubmitterAndApprover\":true",
                "\"RequireDistinctSubmitterAndApprover\":false",
                StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(altered)));
    }

    [Fact]
    public void RetainedLabRequiresExactCmsAndAuthenticodePins()
    {
        WorkerServiceConfiguration configuration =
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(RetainedConfiguration));

        Assert.Equal(WorkerDeploymentMode.RetainedLab, configuration.Mode);
        WorkerSigningConfiguration signing =
            Assert.Single(configuration.SigningPolicies);
        WorkerLocalMachineCertificateSigningConfiguration local =
            Assert.IsType<WorkerLocalMachineCertificateSigningConfiguration>(
                signing.ProviderConfiguration);
        Assert.Equal(
            new string('1', 64),
            local.SignerCertificateSha256);
        Assert.Equal(
            new string('2', 64),
            local.SignerSubjectPublicKeyInfoSha256);
        Assert.Equal(
            WindowsTrustRevocationPolicy.RetainedLabPinned,
            local.AuthenticodeRevocationPolicy);

        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfiguration.Replace(
                        "\"SignerCertificateSha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
                        string.Empty,
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfiguration.Replace(
                        "RetainedLabPinned",
                        "Online",
                        StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    RetainedConfiguration.Replace(
                        "\"RequireDistinctSubmitterAndApprover\":true",
                        "\"RequireDistinctSubmitterAndApprover\":false",
                        StringComparison.Ordinal))));
    }

    [Fact]
    public void ParsesClosedDisposableConfiguration()
    {
        WorkerServiceConfiguration configuration =
            WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(
                    ValidConfiguration
                        .Replace(
                            "\"Mode\":\"Production\"",
                            "\"Mode\":\"DisposableTest\"",
                            StringComparison.Ordinal)
                        .Replace(
                            "\"RevocationPolicy\":\"Online\"",
                            "\"RevocationPolicy\":\"DisposableTestNoCheck\"",
                            StringComparison.Ordinal)
                        .Replace(
                            "\"AuthenticodeRevocationPolicy\":\"Online\"",
                            "\"AuthenticodeRevocationPolicy\":\"DisposableTestNoCheck\"",
                            StringComparison.Ordinal)));

        Assert.Equal(WorkerDeploymentMode.DisposableTest, configuration.Mode);
        Assert.Equal(
            CmsRevocationPolicy.DisposableTestNoCheck,
            configuration.Receipt.Trust.RevocationPolicy);
        Assert.Equal(
            WindowsTrustRevocationPolicy.DisposableTestNoCheck,
            Assert.IsType<WorkerLocalMachineCertificateSigningConfiguration>(
                Assert.Single(configuration.SigningPolicies)
                    .ProviderConfiguration)
                .AuthenticodeRevocationPolicy);
    }

    [Fact]
    public void RetainedSignerIdentityMismatchFailsBeforeSigning()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable retained identity mismatch",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        WorkerLocalMachineCertificateSigningConfiguration signing = new(
            "C:\\Program Files\\Windows Kits\\10\\bin\\signtool.exe",
            new string('a', 64),
            new Version(10, 0, 0, 0),
            new string('B', 40),
            new string('c', 64),
            new string('d', 64),
            new Uri("http://127.0.0.1:31880/"),
            120,
            WindowsTrustRevocationPolicy.RetainedLabPinned);

        Assert.Throws<InvalidOperationException>(
            () => WorkerRuntimeFactory.ValidateRetainedSignerIdentity(
                WorkerDeploymentMode.RetainedLab,
                signing,
                certificate,
                new string('e', 64)));
    }

    [Fact]
    public void NonRetainedModesRejectSignerPinsEvenWhenNull()
    {
        string configuration = ValidConfiguration.Replace(
            "\"SignerCertificateThumbprint\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",",
            "\"SignerCertificateThumbprint\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"SignerCertificateSha256\":null,",
            StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(
            () => WorkerServiceConfiguration.Parse(
                Encoding.UTF8.GetBytes(configuration)));
    }

    private static readonly string ValidConfiguration =
        $$"""
        {
          "Format":"ArtifactSigningWorkerConfigurationV2",
          "Mode":"Production",
          "ProfileSetSha256":"{{ProfileSetSha256}}",
          "WorkerServiceSid":"S-1-5-80-100-200-300-400-500",
          "GatewayServiceSid":"S-1-5-80-101-201-301-401-501",
          "AuthorizationPolicies":[
            {
              "ProjectId":"example-endpoint",
              "ProfileId":"ExampleEndpointBundleV1",
              "ProfileVersion":2,
              "SubmitterTrust":{
                "ExpectedSignerSpkiSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                "TrustedRootThumbprints":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
                "ExtraCertificateThumbprints":[],
                "RevocationPolicy":"Online",
                "UrlRetrievalTimeoutSeconds":5
              },
              "ApproverTrust":{
                "ExpectedSignerSpkiSha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
                "TrustedRootThumbprints":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
                "ExtraCertificateThumbprints":[],
                "RevocationPolicy":"Online",
                "UrlRetrievalTimeoutSeconds":5
              },
              "RequireDistinctSubmitterAndApprover":true
            }
          ],
          "SigningPolicies":[
            {
              "SignerPolicyId":"LabAuthenticodeV1",
              "TimestampPolicyId":"DigiCertRfc3161V1",
              "SignToolPath":"C:\\Program Files\\Windows Kits\\10\\bin\\signtool.exe",
              "SignToolSha256":"1111111111111111111111111111111111111111111111111111111111111111",
              "SignToolFileVersion":"10.0.0.0",
              "SignerCertificateThumbprint":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
              "TimestampUrl":"http://127.0.0.1:31880/",
              "SignToolTimeoutSeconds":120,
              "AuthenticodeRevocationPolicy":"Online"
            }
          ],
          "Receipt":{
            "CertificateThumbprint":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "Trust":{
              "ExpectedSignerSpkiSha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              "RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2",
              "TrustedRootThumbprints":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
              "ExtraCertificateThumbprints":[],
              "RevocationPolicy":"Online",
              "UrlRetrievalTimeoutSeconds":5
            }
          }
        }
        """;

    private static readonly string RetainedConfiguration =
        ValidConfiguration
            .Replace("\"Mode\":\"Production\"", "\"Mode\":\"RetainedLab\"", StringComparison.Ordinal)
            .Replace("\"RevocationPolicy\":\"Online\"", "\"RevocationPolicy\":\"RetainedLabPinned\"", StringComparison.Ordinal)
            .Replace("\"AuthenticodeRevocationPolicy\":\"Online\"", "\"AuthenticodeRevocationPolicy\":\"RetainedLabPinned\"", StringComparison.Ordinal)
            .Replace("\"ExpectedSignerSpkiSha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",", "\"ExpectedSignerSpkiSha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"ExpectedSignerCertificateSha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",", StringComparison.Ordinal)
            .Replace("\"ExpectedSignerSpkiSha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",", "\"ExpectedSignerSpkiSha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"ExpectedSignerCertificateSha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",", StringComparison.Ordinal)
            .Replace("\"ExpectedSignerSpkiSha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",", "\"ExpectedSignerSpkiSha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"ExpectedSignerCertificateSha256\":\"5555555555555555555555555555555555555555555555555555555555555555\",", StringComparison.Ordinal)
            .Replace("\"SignerCertificateThumbprint\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",", "\"SignerCertificateThumbprint\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"SignerCertificateSha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"SignerSubjectPublicKeyInfoSha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",", StringComparison.Ordinal);

    private static string CreateManagedConfiguration()
    {
        JsonObject root = JsonNode.Parse(ValidConfiguration)!.AsObject();
        root["Format"] = WorkerServiceConfiguration.FormatIdentifier;
        root["SigningPolicies"] = JsonNode.Parse(
            """
            [
              {
                "SignerPolicyId":"MicrosoftPublicTrustV1",
                "TimestampPolicyId":"MicrosoftRfc3161V1",
                "Provider":"MicrosoftArtifactSigning",
                "MicrosoftArtifactSigning":{
                  "Region":"JapanEast",
                  "CodeSigningAccountName":"example-signing-account",
                  "CertificateProfileName":"Example-PublicTrust",
                  "SignToolPath":"C:\\Program Files\\Windows Kits\\10\\bin\\signtool.exe",
                  "SignToolSha256":"1111111111111111111111111111111111111111111111111111111111111111",
                  "SignToolFileVersion":"10.0.26100.4188",
                  "DlibPath":"C:\\Program Files\\ArtifactSigning\\Tools\\Azure.CodeSigning.Dlib.dll",
                  "DlibSha256":"2222222222222222222222222222222222222222222222222222222222222222",
                  "DlibFileVersion":"1.0.128.0",
                  "ClientToolsInventorySha256":"3333333333333333333333333333333333333333333333333333333333333333",
                  "ExpectedPublisherSubjectNameSha256":"4444444444444444444444444444444444444444444444444444444444444444",
                  "RequiredPublisherEnhancedKeyUsageOid":"1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699",
                  "TrustedPublisherRootThumbprints":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
                  "SignToolTimeoutSeconds":120,
                  "AuthenticodeRevocationPolicy":"Online"
                }
              }
            ]
            """);
        return root.ToJsonString();
    }

    private static string ProfileSetSha256 =>
        ExampleProfilePackage.CreatePackageSet().PackageSetSha256;
}

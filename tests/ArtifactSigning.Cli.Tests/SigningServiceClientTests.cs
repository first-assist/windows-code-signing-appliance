using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.TestProfile;
using Xunit;

namespace ArtifactSigning.Cli.Tests;

public sealed class SigningServiceClientTests
{
    [Fact]
    public void RequiresOnlineTlsRevocationOnlyInProduction()
    {
        Assert.True(
            SigningServiceClient
                .RequiresTlsCertificateRevocationCheck(
                    CliDeploymentMode.Production));
        Assert.False(
            SigningServiceClient
                .RequiresTlsCertificateRevocationCheck(
                    CliDeploymentMode.DisposableTest));
        Assert.False(
            SigningServiceClient
                .RequiresTlsCertificateRevocationCheck(
                    CliDeploymentMode.RetainedLab));
        Assert.Throws<InvalidDataException>(() =>
            SigningServiceClient
                .RequiresTlsCertificateRevocationCheck(
                    (CliDeploymentMode)(-1)));
    }

    [Fact]
    public void RetainedLabTlsStillRequiresOsValidationAndExactPins()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Retained CLI TLS Test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        CliConfiguration configuration = RetainedConfiguration(certificate);

        Assert.True(SigningServiceClient.ValidateServerCertificate(
            certificate,
            SslPolicyErrors.None,
            configuration));
        Assert.False(SigningServiceClient.ValidateServerCertificate(
            certificate,
            SslPolicyErrors.RemoteCertificateNameMismatch,
            configuration));

        using RSA otherKey = RSA.Create(2048);
        CertificateRequest otherRequest = new(
            "CN=Different Retained CLI TLS Test",
            otherKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 otherCertificate =
            otherRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        Assert.False(SigningServiceClient.ValidateServerCertificate(
            otherCertificate,
            SslPolicyErrors.None,
            configuration));

        CertificateRequest reissuedRequest = new(
            "CN=Reissued Retained CLI TLS Test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 reissuedCertificate =
            reissuedRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        Assert.Equal(
            CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(
                certificate),
            CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(
                reissuedCertificate));
        Assert.False(SigningServiceClient.ValidateServerCertificate(
            reissuedCertificate,
            SslPolicyErrors.None,
            configuration));
    }

    [Fact]
    public async Task AcceptsJsonCharsetButRejectsUnsafePublicFields()
    {
        CliConfiguration configuration =
            CliConfiguration.Parse(ConfigurationJson());
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new(
            "CN=Disposable CLI HTTP Test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate =
            certificateRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        using FixedHandler validHandler = new(
            ProfilesResponseJson("example-endpoint"));
        using SigningServiceClient validClient = new(
            configuration,
            certificate,
            validHandler);

        IReadOnlyList<CliVisibleProfile> profiles =
            await validClient.GetProfilesAsync(
                TestContext.Current.CancellationToken);

        Assert.Single(profiles);
        using FixedHandler unsafeHandler = new(
            ProfilesResponseJson("example\nendpoint"));
        using SigningServiceClient unsafeClient = new(
            configuration,
            certificate,
            unsafeHandler);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => unsafeClient.GetProfilesAsync(
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public void RejectsProfilePackageMismatchBeforeRequestSubmission()
    {
        SigningProfilePackageSet packages =
            ExampleProfilePackage.CreatePackageSet();
        CliProfileRegistry registry = new(packages);
        CliVisibleProfile valid = CreateVisibleProfile(
            packages,
            "example-endpoint");

        registry.RequireServerMatch(
            valid.ProjectId,
            valid.ProfileId,
            [valid]);

        CliVisibleProfile drifted = valid with
        {
            PackageSha256 = new string('b', 64),
        };
        Assert.Throws<InvalidDataException>(
            () => registry.RequireServerMatch(
                valid.ProjectId,
                valid.ProfileId,
                [drifted]));
    }

    private static string ProfilesResponseJson(string projectId)
    {
        SigningProfilePackageSet packages =
            ExampleProfilePackage.CreatePackageSet();
        CliVisibleProfile profile = CreateVisibleProfile(packages, projectId);
        return JsonSerializer.Serialize(new
        {
            Format = "ArtifactSigningProfilesResponseV2",
            Profiles = new[] { profile },
        });
    }

    private static CliVisibleProfile CreateVisibleProfile(
        SigningProfilePackageSet packages,
        string projectId)
    {
        SigningProfilePackageDescriptor package =
            packages.ResolvePackage(
                ExampleEndpointBundleV1.ProfileId,
                ExampleEndpointBundleV1.ProfileVersion)
            ?? throw new InvalidOperationException("Example package is absent.");
        return new CliVisibleProfile(
            projectId,
            ExampleEndpointBundleV1.ProfileId,
            ExampleEndpointBundleV1.ProfileVersion,
            "ArtifactSigningRequestV1",
            ExampleEndpointBundleV1.MaximumRequestBytes,
            packages.PackageSetSha256,
            package.PackageId,
            package.PackageVersion,
            package.PackageSha256,
            package.AssemblySha256,
            package.DescriptorSha256);
    }

    private static byte[] ConfigurationJson()
    {
        return Encoding.UTF8.GetBytes(
            $$"""
            {
              "Format":"ArtifactSigningCliConfigurationV1",
              "Mode":"DisposableTest",
              "ServiceUri":"https://10.20.30.20:7443/",
              "ServerCertificateSha256":"{{new string('a', 64)}}",
              "ServerSpkiSha256":"{{new string('b', 64)}}",
              "ClientIdentity":{"Provider":"PemFiles","CertificatePath":{{JsonPath("client-cert.pem")}},"PrivateKeyPath":{{JsonPath("client-key.pem")}},"PrivateKeyPasswordFile":null,"CertificateThumbprint":null},
              "SubmitterTrust":{"ExpectedSignerSpkiSha256":"{{new string('c', 64)}}","ExpectedSignerCertificateSha256":null,"RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2","TrustedRootCertificatePaths":[{{JsonPath("root.cer")}}],"ExtraCertificatePaths":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1},
              "ReceiptTrust":{"ExpectedSignerSpkiSha256":"{{new string('d', 64)}}","ExpectedSignerCertificateSha256":null,"RequiredEnhancedKeyUsageOid":"1.3.6.1.5.5.7.3.2","TrustedRootCertificatePaths":[{{JsonPath("receipt-root.cer")}}],"ExtraCertificatePaths":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1}
            }
            """);
    }

    private static CliConfiguration RetainedConfiguration(
        X509Certificate2 certificate)
    {
        string json = Encoding.UTF8.GetString(ConfigurationJson())
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
                StringComparison.Ordinal)
            .Replace(
                new string('a', 64),
                CertificateIdentity.ComputeCertificateSha256(certificate),
                StringComparison.Ordinal)
            .Replace(
                new string('b', 64),
                CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(
                    certificate),
                StringComparison.Ordinal);
        return CliConfiguration.Parse(Encoding.UTF8.GetBytes(json));
    }

    private static string JsonPath(string fileName)
    {
        return System.Text.Json.JsonSerializer.Serialize(
            Path.Combine(Path.GetTempPath(), fileName));
    }

    private sealed class FixedHandler(string json) :
        HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HttpResponseMessage response = new(
                HttpStatusCode.OK)
            {
                Content = new StringContent(
                    json,
                    Encoding.UTF8,
                    "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}

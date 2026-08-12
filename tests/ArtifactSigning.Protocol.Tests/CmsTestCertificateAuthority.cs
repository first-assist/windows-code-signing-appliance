using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol.Tests;

internal sealed class CmsTestCertificateAuthority : IDisposable
{
    private readonly RSA _signer;

    private CmsTestCertificateAuthority(RSA signer, X509Certificate2 certificate)
    {
        _signer = signer;
        Certificate = certificate;
    }

    public X509Certificate2 Certificate { get; }

    public static CmsTestCertificateAuthority Create(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        RSA signer = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable CMS Protocol Test Root",
            signer,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notAfter);
        return new CmsTestCertificateAuthority(signer, certificate);
    }

    public X509Certificate2 ExportPublicCertificate()
    {
        return X509CertificateLoader.LoadCertificate(Certificate.RawData);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        _signer.Dispose();
    }
}

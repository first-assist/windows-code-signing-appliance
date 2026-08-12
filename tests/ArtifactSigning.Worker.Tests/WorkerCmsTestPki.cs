using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Worker.Tests;

internal sealed class WorkerCmsTestCertificateAuthority : IDisposable
{
    private readonly RSA _signer;

    private WorkerCmsTestCertificateAuthority(
        RSA signer,
        X509Certificate2 certificate)
    {
        _signer = signer;
        Certificate = certificate;
    }

    internal X509Certificate2 Certificate { get; }

    internal static WorkerCmsTestCertificateAuthority Create(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        RSA signer = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable Worker CMS Test Root",
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
                X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign,
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        X509Certificate2 certificate =
            request.CreateSelfSigned(notBefore, notAfter);
        return new WorkerCmsTestCertificateAuthority(
            signer,
            certificate);
    }

    internal X509Certificate2 ExportPublicCertificate()
    {
        return X509CertificateLoader.LoadCertificate(
            Certificate.RawData);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        _signer.Dispose();
    }
}

internal sealed class WorkerCmsTestIdentity : IDisposable
{
    private readonly RSA _signer;

    private WorkerCmsTestIdentity(
        RSA signer,
        X509Certificate2 certificate)
    {
        _signer = signer;
        Certificate = certificate;
    }

    internal X509Certificate2 Certificate { get; }

    internal string SubjectPublicKeyInfoSha256 =>
        Protocol.CertificateIdentity
            .ComputeSubjectPublicKeyInfoSha256(Certificate);

    internal static WorkerCmsTestIdentity CreateIssued(
        WorkerCmsTestCertificateAuthority authority,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string enhancedKeyUsageOid)
    {
        RSA signer = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable Worker CMS Test Identity",
            signer,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        OidCollection usages = new();
        usages.Add(new Oid(enhancedKeyUsageOid));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(usages, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        using X509Certificate2 publicCertificate = request.Create(
            authority.Certificate,
            notBefore,
            notAfter,
            RandomNumberGenerator.GetBytes(16));
        X509Certificate2 certificate =
            publicCertificate.CopyWithPrivateKey(signer);
        return new WorkerCmsTestIdentity(signer, certificate);
    }

    internal byte[] Sign(
        ReadOnlySpan<byte> content,
        bool detached)
    {
        SignedCms signedCms = new(
            new ContentInfo(content.ToArray()),
            detached);
        CmsSigner signer = new(
            SubjectIdentifierType.SubjectKeyIdentifier,
            Certificate)
        {
            DigestAlgorithm =
                new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signedCms.ComputeSignature(signer, silent: true);
        return signedCms.Encode();
    }

    public void Dispose()
    {
        Certificate.Dispose();
        _signer.Dispose();
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol.Tests;

internal sealed class CmsTestIdentity : IDisposable
{
    private readonly RSA _signer;

    private CmsTestIdentity(RSA signer, X509Certificate2 certificate)
    {
        _signer = signer;
        Certificate = certificate;
    }

    public X509Certificate2 Certificate { get; }

    public string SubjectPublicKeyInfoSha256 =>
        CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(Certificate);

    public string CertificateSha256 =>
        CertificateIdentity.ComputeCertificateSha256(Certificate);

    public static CmsTestIdentity Create(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature,
        string? enhancedKeyUsageOid = null)
    {
        RSA signer = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable CMS Protocol Test",
            signer,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        if (enhancedKeyUsageOid is not null)
        {
            OidCollection usages = new();
            usages.Add(new Oid(enhancedKeyUsageOid));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(usages, critical: true));
        }

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notAfter);
        return new CmsTestIdentity(signer, certificate);
    }

    public static CmsTestIdentity CreateIssued(
        X509Certificate2 issuerCertificate,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string? enhancedKeyUsageOid)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);

        RSA signer = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Disposable Issued CMS Protocol Test",
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
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        if (enhancedKeyUsageOid is not null)
        {
            OidCollection usages = new();
            usages.Add(new Oid(enhancedKeyUsageOid));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(usages, critical: true));
        }

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        using X509Certificate2 publicCertificate = request.Create(
            issuerCertificate,
            notBefore,
            notAfter,
            serialNumber);
        X509Certificate2 certificate = publicCertificate.CopyWithPrivateKey(signer);
        return new CmsTestIdentity(signer, certificate);
    }

    public byte[] Sign(
        ReadOnlySpan<byte> content,
        bool detached = true,
        Oid? digestAlgorithm = null)
    {
        SignedCms signedCms = new(new ContentInfo(content.ToArray()), detached);
        AddSignature(signedCms, digestAlgorithm);
        return signedCms.Encode();
    }

    public X509Certificate2 Reissue(
        X509Certificate2 issuerCertificate,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string enhancedKeyUsageOid)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(enhancedKeyUsageOid);

        CertificateRequest request = new(
            "CN=Disposable Reissued CMS Protocol Test",
            _signer,
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
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(enhancedKeyUsageOid) },
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        using X509Certificate2 publicCertificate = request.Create(
            issuerCertificate,
            notBefore,
            notAfter,
            RandomNumberGenerator.GetBytes(16));
        return publicCertificate.CopyWithPrivateKey(_signer);
    }

    public static byte[] SignWithCertificate(
        ReadOnlySpan<byte> content,
        X509Certificate2 certificate,
        bool detached)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        SignedCms signedCms = new(
            new ContentInfo(content.ToArray()),
            detached);
        CmsSigner signer = new(
            SubjectIdentifierType.SubjectKeyIdentifier,
            certificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signedCms.ComputeSignature(signer, silent: true);
        return signedCms.Encode();
    }

    public void AddSignature(SignedCms signedCms, Oid? digestAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(signedCms);

        CmsSigner signer = new(SubjectIdentifierType.SubjectKeyIdentifier, Certificate)
        {
            DigestAlgorithm = digestAlgorithm ?? new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signedCms.ComputeSignature(signer, silent: true);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        _signer.Dispose();
    }
}

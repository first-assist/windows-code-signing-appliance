using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public static class CertificateIdentity
{
    public static string ComputeCertificateSha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexStringLower(SHA256.HashData(certificate.RawData));
    }

    public static string ComputeSubjectPublicKeyInfoSha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        byte[] subjectPublicKeyInfo = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        return Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo));
    }
}

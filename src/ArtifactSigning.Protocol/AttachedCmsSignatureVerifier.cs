using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public enum AttachedCmsError
{
    None,
    SignatureSizeInvalid,
    ContentSizeInvalid,
    ExpectedSignerInvalid,
    Malformed,
    DetachedContent,
    ContentTypeNotAllowed,
    SignerCountInvalid,
    CounterSignatureNotAllowed,
    DigestAlgorithmNotAllowed,
    SignerCertificateMissing,
    CertificateCountInvalid,
    SignerMismatch,
    CertificateNotValidAtVerificationTime,
    KeyUsageInvalid,
    InvalidSignature,
}

public sealed class AttachedCmsVerificationResult
{
    private readonly byte[]? _content;

    internal AttachedCmsVerificationResult(
        byte[]? content,
        CmsSignerIdentity? signer,
        AttachedCmsError error)
    {
        _content = content;
        Signer = signer;
        Error = error;
    }

    public CmsSignerIdentity? Signer { get; }

    public AttachedCmsError Error { get; }

    public bool IsSuccess =>
        Error is AttachedCmsError.None
        && Signer is not null
        && _content is not null;

    public byte[] GetContentBytes()
    {
        if (!IsSuccess)
        {
            throw new InvalidOperationException(
                "A failed attached CMS verification has no content.");
        }

        return _content!.ToArray();
    }
}

public static class AttachedCmsSignatureVerifier
{
    public static AttachedCmsVerificationResult Verify(
        ReadOnlyMemory<byte> signature,
        string expectedSignerSpkiSha256,
        DateTimeOffset verificationTime,
        int maximumContentBytes)
    {
        if (signature.IsEmpty
            || signature.Length > DetachedCmsSignatureVerifier.MaximumSignatureBytes)
        {
            return Failure(AttachedCmsError.SignatureSizeInvalid);
        }

        if (maximumContentBytes <= 0
            || maximumContentBytes > DetachedCmsSignatureVerifier.MaximumContentBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumContentBytes));
        }

        if (string.IsNullOrEmpty(expectedSignerSpkiSha256)
            || !StrictJsonRules.IsLowerHex(expectedSignerSpkiSha256, 64))
        {
            return Failure(AttachedCmsError.ExpectedSignerInvalid);
        }

        if (verificationTime.Offset != TimeSpan.Zero
            || verificationTime.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Verification time must be UTC with whole-second precision.",
                nameof(verificationTime));
        }

        SignedCms signedCms = new();
        try
        {
            signedCms.Decode(signature.Span);
        }
        catch (CryptographicException)
        {
            return Failure(AttachedCmsError.Malformed);
        }

        byte[] content = signedCms.ContentInfo.Content;
        if (content.Length is 0)
        {
            return Failure(AttachedCmsError.DetachedContent);
        }

        if (!string.Equals(
                signedCms.ContentInfo.ContentType.Value,
                "1.2.840.113549.1.7.1",
                StringComparison.Ordinal))
        {
            return Failure(AttachedCmsError.ContentTypeNotAllowed);
        }

        if (content.Length > maximumContentBytes)
        {
            return Failure(AttachedCmsError.ContentSizeInvalid);
        }

        if (signedCms.SignerInfos.Count is not 1)
        {
            return Failure(AttachedCmsError.SignerCountInvalid);
        }

        if (signedCms.Certificates.Count is < 1 or > 8)
        {
            return Failure(AttachedCmsError.CertificateCountInvalid);
        }

        SignerInfo signerInfo = signedCms.SignerInfos[0];
        if (signerInfo.CounterSignerInfos.Count is not 0)
        {
            return Failure(AttachedCmsError.CounterSignatureNotAllowed);
        }

        if (!string.Equals(
                signerInfo.DigestAlgorithm.Value,
                CmsSignatureRules.Sha256Oid,
                StringComparison.Ordinal))
        {
            return Failure(AttachedCmsError.DigestAlgorithmNotAllowed);
        }

        X509Certificate2? signerCertificate = signerInfo.Certificate;
        if (signerCertificate is null)
        {
            return Failure(AttachedCmsError.SignerCertificateMissing);
        }

        string actualSpkiSha256 =
            CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(signerCertificate);
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualSpkiSha256),
                Convert.FromHexString(expectedSignerSpkiSha256)))
        {
            return Failure(AttachedCmsError.SignerMismatch);
        }

        DateTime verificationUtc = verificationTime.UtcDateTime;
        if (verificationUtc < signerCertificate.NotBefore.ToUniversalTime()
            || verificationUtc > signerCertificate.NotAfter.ToUniversalTime())
        {
            return Failure(
                AttachedCmsError.CertificateNotValidAtVerificationTime);
        }

        X509KeyUsageExtension[] keyUsageExtensions = signerCertificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .ToArray();
        if (keyUsageExtensions.Length > 1
            || keyUsageExtensions.Length is 1
                && !keyUsageExtensions[0].KeyUsages.HasFlag(
                    X509KeyUsageFlags.DigitalSignature))
        {
            return Failure(AttachedCmsError.KeyUsageInvalid);
        }

        try
        {
            signerInfo.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException)
        {
            return Failure(AttachedCmsError.InvalidSignature);
        }

        CmsSignerIdentity identity = new(
            CertificateIdentity.ComputeCertificateSha256(signerCertificate),
            actualSpkiSha256);
        return new AttachedCmsVerificationResult(
            content.ToArray(),
            identity,
            AttachedCmsError.None);
    }

    private static AttachedCmsVerificationResult Failure(
        AttachedCmsError error)
    {
        return new AttachedCmsVerificationResult(null, null, error);
    }
}

internal static class CmsSignatureRules
{
    internal const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
}

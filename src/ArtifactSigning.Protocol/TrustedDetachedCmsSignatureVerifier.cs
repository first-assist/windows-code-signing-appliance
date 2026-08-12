using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public enum TrustedDetachedCmsError
{
    None,
    DetachedSignatureInvalid,
    SignerCertificateProfileInvalid,
    RequiredEnhancedKeyUsageMissing,
    CertificateNotValid,
    SignerCertificateMismatch,
    CertificateRevoked,
    RevocationUncertain,
    ChainInvalid,
}

public sealed record TrustedDetachedCmsVerificationResult(
    CmsSignerIdentity? Signer,
    TrustedDetachedCmsError Error,
    DetachedCmsError DetachedSignatureError)
{
    public bool IsSuccess =>
        Error is TrustedDetachedCmsError.None
        && DetachedSignatureError is DetachedCmsError.None
        && Signer is not null;
}

public static class TrustedDetachedCmsSignatureVerifier
{
    public static TrustedDetachedCmsVerificationResult Verify(
        ReadOnlyMemory<byte> content,
        ReadOnlyMemory<byte> signature,
        CmsTrustPolicy trustPolicy,
        DateTimeOffset verificationTime)
    {
        ArgumentNullException.ThrowIfNull(trustPolicy);

        DetachedCmsVerificationResult detachedResult = DetachedCmsSignatureVerifier.Verify(
            content,
            signature,
            trustPolicy.ExpectedSignerSpkiSha256,
            verificationTime);
        if (!detachedResult.IsSuccess)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                detachedResult.Error);
        }

        SignedCms signedCms = new(new ContentInfo(content.ToArray()), detached: true);
        try
        {
            signedCms.Decode(signature.Span);
        }
        catch (CryptographicException)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                DetachedCmsError.Malformed);
        }

        X509Certificate2? signerCertificate = signedCms.SignerInfos[0].Certificate;
        if (signerCertificate is null)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                DetachedCmsError.SignerCertificateMissing);
        }

        TrustedDetachedCmsError chainError =
            TrustedCmsCertificateValidator.Validate(
            signerCertificate,
            signedCms.Certificates,
            trustPolicy,
            verificationTime);
        if (chainError is not TrustedDetachedCmsError.None)
        {
            return Failure(chainError);
        }

        return new TrustedDetachedCmsVerificationResult(
            detachedResult.Signer,
            TrustedDetachedCmsError.None,
            DetachedCmsError.None);
    }

    private static TrustedDetachedCmsVerificationResult Failure(
        TrustedDetachedCmsError error,
        DetachedCmsError detachedSignatureError = DetachedCmsError.None)
    {
        return new TrustedDetachedCmsVerificationResult(
            null,
            error,
            detachedSignatureError);
    }
}

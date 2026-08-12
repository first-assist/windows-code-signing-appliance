using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public enum DetachedCmsError
{
    None,
    ContentSizeInvalid,
    SignatureSizeInvalid,
    ExpectedSignerInvalid,
    Malformed,
    AttachedContent,
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

public sealed record CmsSignerIdentity(
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256);

public sealed record DetachedCmsVerificationResult(
    CmsSignerIdentity? Signer,
    DetachedCmsError Error)
{
    public bool IsSuccess => Error is DetachedCmsError.None && Signer is not null;
}

public static class DetachedCmsSignatureVerifier
{
    public const int MaximumContentBytes =
        ArtifactSigningReceiptJsonSerializer
            .MaximumReceiptJsonBytes;
    public const int MaximumSignatureBytes = 256 * 1024;

    private const string CmsSignedDataOid = "1.2.840.113549.1.7.2";
    private const string CmsDataOid = "1.2.840.113549.1.7.1";

    public static DetachedCmsVerificationResult Verify(
        ReadOnlyMemory<byte> content,
        ReadOnlyMemory<byte> signature,
        string expectedSignerSpkiSha256,
        DateTimeOffset verificationTime)
    {
        if (content.IsEmpty || content.Length > MaximumContentBytes)
        {
            return Failure(DetachedCmsError.ContentSizeInvalid);
        }

        if (signature.IsEmpty || signature.Length > MaximumSignatureBytes)
        {
            return Failure(DetachedCmsError.SignatureSizeInvalid);
        }

        if (string.IsNullOrEmpty(expectedSignerSpkiSha256)
            || !StrictJsonRules.IsLowerHex(expectedSignerSpkiSha256, 64))
        {
            return Failure(DetachedCmsError.ExpectedSignerInvalid);
        }

        if (verificationTime.Offset != TimeSpan.Zero
            || verificationTime.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Verification time must be UTC with whole-second precision.",
                nameof(verificationTime));
        }

        DetachedContentInspection contentInspection = InspectDetachedContent(signature);
        if (contentInspection is DetachedContentInspection.Malformed)
        {
            return Failure(DetachedCmsError.Malformed);
        }

        if (contentInspection is DetachedContentInspection.Attached)
        {
            return Failure(DetachedCmsError.AttachedContent);
        }

        SignedCms signedCms = new(new ContentInfo(content.ToArray()), detached: true);
        try
        {
            signedCms.Decode(signature.Span);
        }
        catch (CryptographicException)
        {
            return Failure(DetachedCmsError.Malformed);
        }

        if (signedCms.SignerInfos.Count is not 1)
        {
            return Failure(DetachedCmsError.SignerCountInvalid);
        }

        if (signedCms.Certificates.Count is < 1 or > 8)
        {
            return Failure(DetachedCmsError.CertificateCountInvalid);
        }

        SignerInfo signerInfo = signedCms.SignerInfos[0];
        if (signerInfo.CounterSignerInfos.Count is not 0)
        {
            return Failure(DetachedCmsError.CounterSignatureNotAllowed);
        }

        if (!string.Equals(
                signerInfo.DigestAlgorithm.Value,
                CmsSignatureRules.Sha256Oid,
                StringComparison.Ordinal))
        {
            return Failure(DetachedCmsError.DigestAlgorithmNotAllowed);
        }

        X509Certificate2? signerCertificate = signerInfo.Certificate;
        if (signerCertificate is null)
        {
            return Failure(DetachedCmsError.SignerCertificateMissing);
        }

        string actualSpkiSha256 =
            CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(signerCertificate);
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualSpkiSha256),
                Convert.FromHexString(expectedSignerSpkiSha256)))
        {
            return Failure(DetachedCmsError.SignerMismatch);
        }

        DateTime verificationUtc = verificationTime.UtcDateTime;
        if (verificationUtc < signerCertificate.NotBefore.ToUniversalTime()
            || verificationUtc > signerCertificate.NotAfter.ToUniversalTime())
        {
            return Failure(DetachedCmsError.CertificateNotValidAtVerificationTime);
        }

        X509KeyUsageExtension[] keyUsageExtensions = signerCertificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .ToArray();
        if (keyUsageExtensions.Length > 1
            || keyUsageExtensions.Length is 1
                && !keyUsageExtensions[0].KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
        {
            return Failure(DetachedCmsError.KeyUsageInvalid);
        }

        try
        {
            signerInfo.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException)
        {
            return Failure(DetachedCmsError.InvalidSignature);
        }

        CmsSignerIdentity identity = new(
            CertificateIdentity.ComputeCertificateSha256(signerCertificate),
            actualSpkiSha256);
        return new DetachedCmsVerificationResult(identity, DetachedCmsError.None);
    }

    private static DetachedContentInspection InspectDetachedContent(ReadOnlyMemory<byte> signature)
    {
        try
        {
            AsnReader outerReader = new(signature, AsnEncodingRules.BER);
            AsnReader contentInfo = outerReader.ReadSequence();
            if (!string.Equals(
                    contentInfo.ReadObjectIdentifier(),
                    CmsSignedDataOid,
                    StringComparison.Ordinal))
            {
                return DetachedContentInspection.Malformed;
            }

            Asn1Tag signedDataTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
            AsnReader signedDataWrapper = contentInfo.ReadSequence(signedDataTag);
            AsnReader signedData = signedDataWrapper.ReadSequence();
            _ = signedData.ReadInteger();
            _ = signedData.ReadSetOf();

            AsnReader encapsulatedContentInfo = signedData.ReadSequence();
            if (!string.Equals(
                    encapsulatedContentInfo.ReadObjectIdentifier(),
                    CmsDataOid,
                    StringComparison.Ordinal))
            {
                return DetachedContentInspection.Malformed;
            }

            bool isDetached = !encapsulatedContentInfo.HasData;
            signedDataWrapper.ThrowIfNotEmpty();
            contentInfo.ThrowIfNotEmpty();
            outerReader.ThrowIfNotEmpty();

            return isDetached
                ? DetachedContentInspection.Detached
                : DetachedContentInspection.Attached;
        }
        catch (AsnContentException)
        {
            return DetachedContentInspection.Malformed;
        }
    }

    private static DetachedCmsVerificationResult Failure(DetachedCmsError error)
    {
        return new DetachedCmsVerificationResult(null, error);
    }

    private enum DetachedContentInspection
    {
        Detached,
        Attached,
        Malformed,
    }
}

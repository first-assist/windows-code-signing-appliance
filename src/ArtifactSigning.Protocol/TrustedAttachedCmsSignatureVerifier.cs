using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public sealed class TrustedAttachedCmsVerificationResult
{
    private readonly byte[]? _content;

    internal TrustedAttachedCmsVerificationResult(
        byte[]? content,
        CmsSignerIdentity? signer,
        TrustedDetachedCmsError error,
        AttachedCmsError attachedSignatureError)
    {
        _content = content;
        Signer = signer;
        Error = error;
        AttachedSignatureError = attachedSignatureError;
    }

    public CmsSignerIdentity? Signer { get; }

    public TrustedDetachedCmsError Error { get; }

    public AttachedCmsError AttachedSignatureError { get; }

    public bool IsSuccess =>
        Error is TrustedDetachedCmsError.None
        && AttachedSignatureError is AttachedCmsError.None
        && Signer is not null
        && _content is not null;

    public byte[] GetContentBytes()
    {
        if (!IsSuccess)
        {
            throw new InvalidOperationException(
                "A failed trusted attached CMS verification has no content.");
        }

        return _content!.ToArray();
    }
}

public static class TrustedAttachedCmsSignatureVerifier
{
    public static TrustedAttachedCmsVerificationResult Verify(
        ReadOnlyMemory<byte> signature,
        CmsTrustPolicy trustPolicy,
        DateTimeOffset verificationTime,
        int maximumContentBytes)
    {
        ArgumentNullException.ThrowIfNull(trustPolicy);

        AttachedCmsVerificationResult attached =
            AttachedCmsSignatureVerifier.Verify(
                signature,
                trustPolicy.ExpectedSignerSpkiSha256,
                verificationTime,
                maximumContentBytes);
        if (!attached.IsSuccess)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                attachedSignatureError: attached.Error);
        }

        SignedCms signedCms = new();
        try
        {
            signedCms.Decode(signature.Span);
        }
        catch (CryptographicException)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                attachedSignatureError: AttachedCmsError.Malformed);
        }

        X509Certificate2? signerCertificate = signedCms.SignerInfos[0].Certificate;
        if (signerCertificate is null)
        {
            return Failure(
                TrustedDetachedCmsError.DetachedSignatureInvalid,
                attachedSignatureError:
                    AttachedCmsError.SignerCertificateMissing);
        }

        TrustedDetachedCmsError trustError =
            TrustedCmsCertificateValidator.Validate(
                signerCertificate,
                signedCms.Certificates,
                trustPolicy,
                verificationTime);
        if (trustError is not TrustedDetachedCmsError.None)
        {
            return Failure(trustError);
        }

        return new TrustedAttachedCmsVerificationResult(
            attached.GetContentBytes(),
            attached.Signer,
            TrustedDetachedCmsError.None,
            AttachedCmsError.None);
    }

    private static TrustedAttachedCmsVerificationResult Failure(
        TrustedDetachedCmsError error,
        AttachedCmsError attachedSignatureError = AttachedCmsError.None)
    {
        return new TrustedAttachedCmsVerificationResult(
            null,
            null,
            error,
            attachedSignatureError);
    }
}

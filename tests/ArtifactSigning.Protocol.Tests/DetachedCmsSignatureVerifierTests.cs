using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class DetachedCmsSignatureVerifierTests
{
    private static readonly DateTimeOffset VerificationTime =
        new(2026, 7, 27, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void VerifyAcceptsDetachedSha256SignatureFromExactExpectedSigner()
    {
        using CmsTestIdentity identity = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        byte[] signature = identity.Sign(content);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signature,
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        Assert.True(result.IsSuccess);
        Assert.Equal(DetachedCmsError.None, result.Error);
        Assert.NotNull(result.Signer);
        Assert.Equal(identity.SubjectPublicKeyInfoSha256, result.Signer.SubjectPublicKeyInfoSha256);
        Assert.Equal(
            CertificateIdentity.ComputeCertificateSha256(identity.Certificate),
            result.Signer.CertificateSha256);
    }

    [Fact]
    public void VerifyRejectsContentSubstitution()
    {
        using CmsTestIdentity identity = CreateValidIdentity();
        byte[] signature = identity.Sign("original request"u8);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            "altered request"u8.ToArray(),
            signature,
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.InvalidSignature);
    }

    [Fact]
    public void VerifyRejectsAttachedCms()
    {
        using CmsTestIdentity identity = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        byte[] signature = identity.Sign(content, detached: false);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signature,
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.AttachedContent);
    }

    [Fact]
    public void VerifyRejectsUnexpectedSigner()
    {
        using CmsTestIdentity signer = CreateValidIdentity();
        using CmsTestIdentity expected = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        byte[] signature = signer.Sign(content);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signature,
            expected.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.SignerMismatch);
    }

    [Fact]
    public void VerifyRejectsMultipleSigners()
    {
        using CmsTestIdentity first = CreateValidIdentity();
        using CmsTestIdentity second = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        SignedCms signedCms = new(new ContentInfo(content), detached: true);
        first.AddSignature(signedCms);
        second.AddSignature(signedCms);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signedCms.Encode(),
            first.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.SignerCountInvalid);
    }

    [Fact]
    public void VerifyRejectsCounterSignature()
    {
        using CmsTestIdentity signer = CreateValidIdentity();
        using CmsTestIdentity counterSigner = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        SignedCms signedCms = new(new ContentInfo(content), detached: true);
        signer.AddSignature(signedCms);
        CmsSigner counterSignature = new(
            SubjectIdentifierType.SubjectKeyIdentifier,
            counterSigner.Certificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signedCms.SignerInfos[0].ComputeCounterSignature(counterSignature);

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signedCms.Encode(),
            signer.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.CounterSignatureNotAllowed);
    }

    [Fact]
    public void VerifyRejectsCertificateOutsideValidityWindow()
    {
        using CmsTestIdentity identity = CmsTestIdentity.Create(
            VerificationTime.AddHours(-2),
            VerificationTime.AddHours(-1));
        byte[] content = "signed request"u8.ToArray();

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            identity.Sign(content),
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.CertificateNotValidAtVerificationTime);
    }

    [Fact]
    public void VerifyRejectsCertificateWithoutDigitalSignatureUsage()
    {
        using CmsTestIdentity identity = CmsTestIdentity.Create(
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1),
            X509KeyUsageFlags.KeyEncipherment);
        byte[] content = "signed request"u8.ToArray();

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            identity.Sign(content),
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.KeyUsageInvalid);
    }

    [Fact]
    public void VerifyRejectsDigestAlgorithmOtherThanSha256()
    {
        using CmsTestIdentity identity = CreateValidIdentity();
        byte[] content = "signed request"u8.ToArray();
        byte[] signature = identity.Sign(content, digestAlgorithm: new Oid("2.16.840.1.101.3.4.2.2"));

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            content,
            signature,
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.DigestAlgorithmNotAllowed);
    }

    [Fact]
    public void VerifyRejectsMalformedCmsWithoutLeakingDecoderException()
    {
        using CmsTestIdentity identity = CreateValidIdentity();

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            "signed request"u8.ToArray(),
            "not cms"u8.ToArray(),
            identity.SubjectPublicKeyInfoSha256,
            VerificationTime);

        AssertError(result, DetachedCmsError.Malformed);
    }

    [Fact]
    public void VerifyRejectsOversizedCmsBeforeDecoding()
    {
        byte[] oversized = new byte[DetachedCmsSignatureVerifier.MaximumSignatureBytes + 1];

        DetachedCmsVerificationResult result = DetachedCmsSignatureVerifier.Verify(
            "signed request"u8.ToArray(),
            oversized,
            new string('0', 64),
            VerificationTime);

        AssertError(result, DetachedCmsError.SignatureSizeInvalid);
    }

    private static CmsTestIdentity CreateValidIdentity()
    {
        return CmsTestIdentity.Create(
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1));
    }

    private static void AssertError(
        DetachedCmsVerificationResult result,
        DetachedCmsError expected)
    {
        Assert.False(result.IsSuccess);
        Assert.Null(result.Signer);
        Assert.Equal(expected, result.Error);
    }
}

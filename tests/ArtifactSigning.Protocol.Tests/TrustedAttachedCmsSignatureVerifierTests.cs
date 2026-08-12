using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class TrustedAttachedCmsSignatureVerifierTests
{
    private const string RequiredEkuOid = "1.3.6.1.5.5.7.3.2";

    private static readonly DateTimeOffset VerificationTime =
        new(2026, 7, 29, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void VerifyReturnsExactContentForTrustedAttachedSigner()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot);
        byte[] content = "exact approval bytes"u8.ToArray();

        TrustedAttachedCmsVerificationResult result =
            TrustedAttachedCmsSignatureVerifier.Verify(
                identity.Sign(content, detached: false),
                policy,
                VerificationTime,
                ArtifactSigningApprovalJsonParser.MaximumApprovalJsonBytes);

        Assert.True(result.IsSuccess);
        Assert.Equal(content, result.GetContentBytes());
        Assert.Equal(
            identity.SubjectPublicKeyInfoSha256,
            result.Signer?.SubjectPublicKeyInfoSha256);
    }

    [Fact]
    public void VerifyRejectsDetachedContent()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot);
        byte[] content = "approval"u8.ToArray();

        TrustedAttachedCmsVerificationResult result =
            TrustedAttachedCmsSignatureVerifier.Verify(
                identity.Sign(content, detached: true),
                policy,
                VerificationTime,
                ArtifactSigningApprovalJsonParser.MaximumApprovalJsonBytes);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            TrustedDetachedCmsError.DetachedSignatureInvalid,
            result.Error);
        Assert.Equal(
            AttachedCmsError.DetachedContent,
            result.AttachedSignatureError);
    }

    [Fact]
    public void VerifyRejectsContentBeyondCallerBound()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot);
        byte[] content = new byte[257];

        TrustedAttachedCmsVerificationResult result =
            TrustedAttachedCmsSignatureVerifier.Verify(
                identity.Sign(content, detached: false),
                policy,
                VerificationTime,
                maximumContentBytes: 256);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            AttachedCmsError.ContentSizeInvalid,
            result.AttachedSignatureError);
    }

    [Fact]
    public void VerifyRejectsWrongAllowlistedSigner()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity signer = CreateIdentity(authority);
        using CmsTestIdentity expected = CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(expected, publicRoot);

        TrustedAttachedCmsVerificationResult result =
            TrustedAttachedCmsSignatureVerifier.Verify(
                signer.Sign("approval"u8, detached: false),
                policy,
                VerificationTime,
                ArtifactSigningApprovalJsonParser.MaximumApprovalJsonBytes);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            AttachedCmsError.SignerMismatch,
            result.AttachedSignatureError);
    }

    [Fact]
    public void VerifyRetainedLabPinnedRejectsReissuedCertificateForSameKey()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        using X509Certificate2 reissued = identity.Reissue(
            authority.Certificate,
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1),
            RequiredEkuOid);
        CmsTrustPolicy policy = new(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [publicRoot],
            CmsRevocationPolicy.RetainedLabPinned,
            TimeSpan.FromSeconds(1),
            expectedSignerCertificateSha256: identity.CertificateSha256);

        TrustedAttachedCmsVerificationResult result =
            TrustedAttachedCmsSignatureVerifier.Verify(
                CmsTestIdentity.SignWithCertificate(
                    "approval"u8,
                    reissued,
                    detached: false),
                policy,
                VerificationTime,
                ArtifactSigningApprovalJsonParser.MaximumApprovalJsonBytes);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            TrustedDetachedCmsError.SignerCertificateMismatch,
            result.Error);
    }

    private static CmsTestCertificateAuthority CreateAuthority()
    {
        return CmsTestCertificateAuthority.Create(
            VerificationTime.AddDays(-1),
            VerificationTime.AddDays(1));
    }

    private static CmsTestIdentity CreateIdentity(
        CmsTestCertificateAuthority authority)
    {
        return CmsTestIdentity.CreateIssued(
            authority.Certificate,
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1),
            RequiredEkuOid);
    }

    private static CmsTrustPolicy CreatePolicy(
        CmsTestIdentity identity,
        X509Certificate2 publicRoot)
    {
        return new CmsTrustPolicy(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [publicRoot],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
    }
}

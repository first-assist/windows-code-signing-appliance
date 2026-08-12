using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class TrustedDetachedCmsSignatureVerifierTests
{
    private const string RequiredEkuOid = "1.3.6.1.5.5.7.3.2";

    private static readonly DateTimeOffset VerificationTime =
        new(2026, 7, 27, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void VerifyAcceptsExactSignerWithConfiguredChainAndEku()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(
            identity,
            publicRoot,
            CmsRevocationPolicy.RetainedLabPinned,
            identity.CertificateSha256);
        byte[] content = "signed request"u8.ToArray();

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                content,
                identity.Sign(content),
                policy,
                VerificationTime);

        Assert.True(result.IsSuccess);
        Assert.Equal(TrustedDetachedCmsError.None, result.Error);
        Assert.Equal(DetachedCmsError.None, result.DetachedSignatureError);
        Assert.Equal(identity.SubjectPublicKeyInfoSha256, result.Signer?.SubjectPublicKeyInfoSha256);
    }

    [Fact]
    public void VerifyPreservesSafeDetachedSignatureFailure()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot);
        byte[] signature = identity.Sign("original request"u8);

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                "altered request"u8.ToArray(),
                signature,
                policy,
                VerificationTime);

        AssertError(
            result,
            TrustedDetachedCmsError.DetachedSignatureInvalid,
            DetachedCmsError.InvalidSignature);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1.3.6.1.5.5.7.3.3")]
    public void VerifyRejectsSignerWithoutRequiredEku(string? enhancedKeyUsageOid)
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, enhancedKeyUsageOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot);
        byte[] content = "signed request"u8.ToArray();

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                content,
                identity.Sign(content),
                policy,
                VerificationTime);

        AssertError(result, TrustedDetachedCmsError.RequiredEnhancedKeyUsageMissing);
    }

    [Fact]
    public void VerifyRejectsUntrustedIssuer()
    {
        using CmsTestCertificateAuthority signerAuthority = CreateAuthority();
        using CmsTestCertificateAuthority trustedAuthority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(signerAuthority, RequiredEkuOid);
        using X509Certificate2 trustedRoot = trustedAuthority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, trustedRoot);
        byte[] content = "signed request"u8.ToArray();

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                content,
                identity.Sign(content),
                policy,
                VerificationTime);

        AssertError(result, TrustedDetachedCmsError.ChainInvalid);
    }

    [Theory]
    [InlineData(CmsRevocationPolicy.Online)]
    [InlineData(CmsRevocationPolicy.Offline)]
    public void VerifyFailsClosedWhenRevocationCannotBeEstablished(
        CmsRevocationPolicy revocationPolicy)
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        CmsTrustPolicy policy = CreatePolicy(identity, publicRoot, revocationPolicy);
        byte[] content = "signed request"u8.ToArray();

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                content,
                identity.Sign(content),
                policy,
                VerificationTime);

        AssertError(result, TrustedDetachedCmsError.RevocationUncertain);
    }

    [Fact]
    public void VerifyRetainedLabPinnedRejectsReissuedCertificateForSameKey()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();
        using X509Certificate2 reissued = identity.Reissue(
            authority.Certificate,
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1),
            RequiredEkuOid);
        CmsTrustPolicy policy = CreatePolicy(
            identity,
            publicRoot,
            CmsRevocationPolicy.RetainedLabPinned,
            identity.CertificateSha256);
        byte[] content = "signed request"u8.ToArray();

        TrustedDetachedCmsVerificationResult result =
            TrustedDetachedCmsSignatureVerifier.Verify(
                content,
                CmsTestIdentity.SignWithCertificate(
                    content,
                    reissued,
                    detached: true),
                policy,
                VerificationTime);

        AssertError(
            result,
            TrustedDetachedCmsError.SignerCertificateMismatch);
    }

    [Fact]
    public void PolicyRejectsPrivateTrustMaterial()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);

        Assert.Throws<ArgumentException>(
            () => CreatePolicy(identity, authority.Certificate));
    }

    [Fact]
    public void PolicyRequiresCertificatePinOnlyForRetainedLab()
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();

        Assert.Throws<ArgumentException>(() => CreatePolicy(
            identity,
            publicRoot,
            CmsRevocationPolicy.RetainedLabPinned));
        Assert.Throws<ArgumentException>(() => CreatePolicy(
            identity,
            publicRoot,
            CmsRevocationPolicy.DisposableTestNoCheck,
            identity.CertificateSha256));
    }

    [Theory]
    [InlineData("1.03.6")]
    [InlineData("3.1.1")]
    [InlineData("1")]
    [InlineData("not-an-oid")]
    public void PolicyRejectsNonCanonicalEkuOid(string oid)
    {
        using CmsTestCertificateAuthority authority = CreateAuthority();
        using CmsTestIdentity identity = CreateIdentity(authority, RequiredEkuOid);
        using X509Certificate2 publicRoot = authority.ExportPublicCertificate();

        Assert.Throws<ArgumentException>(
            () => new CmsTrustPolicy(
                identity.SubjectPublicKeyInfoSha256,
                oid,
                [publicRoot],
                CmsRevocationPolicy.DisposableTestNoCheck,
                TimeSpan.FromSeconds(1)));
    }

    private static CmsTestCertificateAuthority CreateAuthority()
    {
        return CmsTestCertificateAuthority.Create(
            VerificationTime.AddDays(-1),
            VerificationTime.AddDays(1));
    }

    private static CmsTestIdentity CreateIdentity(
        CmsTestCertificateAuthority authority,
        string? enhancedKeyUsageOid)
    {
        return CmsTestIdentity.CreateIssued(
            authority.Certificate,
            VerificationTime.AddHours(-1),
            VerificationTime.AddHours(1),
            enhancedKeyUsageOid);
    }

    private static CmsTrustPolicy CreatePolicy(
        CmsTestIdentity identity,
        X509Certificate2 trustedRoot,
        CmsRevocationPolicy revocationPolicy =
            CmsRevocationPolicy.DisposableTestNoCheck,
        string? expectedSignerCertificateSha256 = null)
    {
        return new CmsTrustPolicy(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [trustedRoot],
            revocationPolicy,
            TimeSpan.FromSeconds(1),
            expectedSignerCertificateSha256:
                expectedSignerCertificateSha256);
    }

    private static void AssertError(
        TrustedDetachedCmsVerificationResult result,
        TrustedDetachedCmsError expected,
        DetachedCmsError detachedError = DetachedCmsError.None)
    {
        Assert.False(result.IsSuccess);
        Assert.Null(result.Signer);
        Assert.Equal(expected, result.Error);
        Assert.Equal(detachedError, result.DetachedSignatureError);
    }
}

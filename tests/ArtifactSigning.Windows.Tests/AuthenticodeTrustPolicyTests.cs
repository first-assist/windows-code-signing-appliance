using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class AuthenticodeTrustPolicyTests
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    private const string SubscriberEku =
        "1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699";

    [Fact]
    public void AcceptsCanonicalInstalledPolicy()
    {
        AuthenticodeTrustPolicy policy = new(
            Thumbprint,
            WindowsTrustRevocationPolicy.Online);

        Assert.Equal(Thumbprint, policy.ExpectedSignerThumbprint);
        Assert.Equal(
            WindowsTrustRevocationPolicy.Online,
            policy.RevocationPolicy);
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef01234567")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456")]
    [InlineData("G123456789ABCDEF0123456789ABCDEF01234567")]
    public void RejectsNoncanonicalSignerThumbprint(string thumbprint)
    {
        Assert.Throws<ArgumentException>(
            () => new AuthenticodeTrustPolicy(
                thumbprint,
                WindowsTrustRevocationPolicy.Online));
    }

    [Fact]
    public void RejectsUnknownRevocationPolicy()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new AuthenticodeTrustPolicy(
                Thumbprint,
                (WindowsTrustRevocationPolicy)999));
    }

    [Fact]
    public void RetainedSignerCannotDisableTimestampRevocation()
    {
        Assert.Throws<ArgumentException>(
            () => new AuthenticodeTrustPolicy(
                Thumbprint,
                WindowsTrustRevocationPolicy.RetainedLabPinned,
                WindowsTrustRevocationPolicy.DisposableTestNoCheck,
                new string('a', 64),
                new string('b', 64)));
    }

    [Fact]
    public void RetainedSignerRequiresBothExactPins()
    {
        Assert.Throws<ArgumentException>(
            () => new AuthenticodeTrustPolicy(
                Thumbprint,
                WindowsTrustRevocationPolicy.RetainedLabPinned,
                WindowsTrustRevocationPolicy.Online,
                expectedSignerCertificateSha256: null,
                expectedSignerSubjectPublicKeyInfoSha256:
                    new string('b', 64)));
        Assert.Throws<ArgumentException>(
            () => new AuthenticodeTrustPolicy(
                Thumbprint,
                WindowsTrustRevocationPolicy.RetainedLabPinned,
                WindowsTrustRevocationPolicy.Online,
                new string('a', 64),
                expectedSignerSubjectPublicKeyInfoSha256: null));
    }

    [Fact]
    public void NonRetainedSignerRejectsExactPins()
    {
        Assert.Throws<ArgumentException>(
            () => new AuthenticodeTrustPolicy(
                Thumbprint,
                WindowsTrustRevocationPolicy.Online,
                WindowsTrustRevocationPolicy.Online,
                new string('a', 64),
                new string('b', 64)));
    }

    [Fact]
    public void AcceptsClosedMicrosoftPublisherPolicy()
    {
        AuthenticodeTrustPolicy policy = AuthenticodeTrustPolicy
            .CreateMicrosoftArtifactSigningPublisher(
                new string('a', 64),
                SubscriberEku,
                [Thumbprint],
                WindowsTrustRevocationPolicy.Online,
                WindowsTrustRevocationPolicy.Online);

        Assert.Equal(
            AuthenticodeSignerTrustKind.MicrosoftArtifactSigningPublisher,
            policy.SignerTrustKind);
        Assert.Null(policy.ExpectedSignerThumbprint);
        Assert.Equal(SubscriberEku, policy.RequiredPublisherEnhancedKeyUsageOid);
        Assert.Equal(Thumbprint, Assert.Single(
            policy.TrustedPublisherRootThumbprints));
    }

    [Theory]
    [InlineData("1.3.6.01")]
    [InlineData("1.3.6.")]
    [InlineData("not-an-oid")]
    public void MicrosoftPublisherRejectsUnsafeSubscriberOid(string oid)
    {
        Assert.Throws<ArgumentException>(() => AuthenticodeTrustPolicy
            .CreateMicrosoftArtifactSigningPublisher(
                new string('a', 64),
                oid,
                [Thumbprint],
                WindowsTrustRevocationPolicy.Online,
                WindowsTrustRevocationPolicy.Online));
    }
}

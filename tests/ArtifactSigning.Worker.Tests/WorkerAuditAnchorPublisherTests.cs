using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerAuditAnchorPublisherTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void PublishesCanonicalSignedCurrentHead()
    {
        using WorkerStateTestEnvironment environment = new();
        Directory.CreateDirectory(
            environment.Layout.GatewayStatusRoot);
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        _ = store.AdmitApproved(
            requestId,
            new string('a', 64),
            Now);
        using WorkerCmsTestCertificateAuthority authority =
            WorkerCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using WorkerCmsTestIdentity identity =
            WorkerCmsTestIdentity.CreateIssued(
                authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = new(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
        WorkerReceiptCmsSigner signer = new(
            identity.Certificate,
            trust);
        WorkerAuditAnchorPublisher publisher = new(
            store,
            signer,
            new FixedDependencyProbe(ready: true),
            new FixedTimeProvider(Now));

        Assert.True(publisher.Publish(workerReady: true));

        string jsonPath = Assert.Single(
            Directory.EnumerateFiles(
                environment.Layout.GatewayStatusRoot,
                "*.json"));
        string signaturePath = Assert.Single(
            Directory.EnumerateFiles(
                environment.Layout.GatewayStatusRoot,
                "*.p7s"));
        byte[] json = File.ReadAllBytes(jsonPath);
        byte[] signature =
            File.ReadAllBytes(signaturePath);
        WorkerAuditAnchorJsonParseResult parsed =
            WorkerAuditAnchorJson.Parse(json);
        TrustedDetachedCmsVerificationResult verified =
            TrustedDetachedCmsSignatureVerifier.Verify(
                json,
                signature,
                trust,
                Now);

        Assert.True(parsed.IsSuccess);
        Assert.Equal(
            store.GetAuditHead().Sequence,
            parsed.Anchor?.WorkerSequence);
        Assert.True(parsed.Anchor?.WorkerReady);
        Assert.True(
            parsed.Anchor?.TimestampDependencyReady);
        Assert.True(verified.IsSuccess);
    }

    [Fact]
    public void PublishesFailClosedDependencyState()
    {
        using WorkerStateTestEnvironment environment = new();
        Directory.CreateDirectory(
            environment.Layout.GatewayStatusRoot);
        WorkerStateStore store = environment.CreateStore();
        using WorkerCmsTestCertificateAuthority authority =
            WorkerCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using WorkerCmsTestIdentity identity =
            WorkerCmsTestIdentity.CreateIssued(
                authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        WorkerReceiptCmsSigner signer = new(
            identity.Certificate,
            new CmsTrustPolicy(
                identity.SubjectPublicKeyInfoSha256,
                RequiredEkuOid,
                [root],
                CmsRevocationPolicy.DisposableTestNoCheck,
                TimeSpan.FromSeconds(1)));
        WorkerAuditAnchorPublisher publisher = new(
            store,
            signer,
            new FixedDependencyProbe(ready: false),
            new FixedTimeProvider(Now));

        Assert.True(publisher.Publish(workerReady: true));

        byte[] json = File.ReadAllBytes(Assert.Single(
            Directory.EnumerateFiles(
                environment.Layout.GatewayStatusRoot,
                "*.json")));
        WorkerAuditAnchorJsonParseResult parsed =
            WorkerAuditAnchorJson.Parse(json);
        Assert.True(parsed.IsSuccess);
        Assert.False(
            parsed.Anchor?.TimestampDependencyReady);
    }

    private sealed class FixedDependencyProbe(
        bool ready) : IWorkerReadinessDependencyProbe
    {
        public bool IsTimestampDependencyReady()
        {
            return ready;
        }
    }

    private sealed class FixedTimeProvider(
        DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }
}

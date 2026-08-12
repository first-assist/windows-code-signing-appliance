using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayAuditAnchorReaderTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void VerifiesSignedCurrentAnchorAndReadiness()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        using TestAnchorIdentity identity =
            TestAnchorIdentity.Create();
        WriteAnchor(
            environment.Layout,
            identity.Identity,
            CreateAnchor(
                identity.Identity
                    .SubjectPublicKeyInfoSha256));
        GatewayAuditAnchorReader reader = new(
            environment.Layout,
            identity.Trust);
        GatewayReadinessProbe readiness = new(
            store,
            reader,
            timeProvider: new FixedTimeProvider(Now));

        GatewayVerifiedWorkerAuditAnchor result =
            reader.ReadCurrent(Now);

        Assert.Equal(1UL, result.Anchor.WorkerSequence);
        Assert.True(readiness.IsReady());
    }

    [Fact]
    public void RejectsTamperStalenessAndFork()
    {
        using GatewayStateTestEnvironment environment = new();
        _ = environment.CreateStore();
        using TestAnchorIdentity identity =
            TestAnchorIdentity.Create();
        WorkerAuditAnchorV1 anchor = CreateAnchor(
            identity.Identity
                .SubjectPublicKeyInfoSha256);
        string jsonPath = WriteAnchor(
            environment.Layout,
            identity.Identity,
            anchor);
        GatewayAuditAnchorReader reader = new(
            environment.Layout,
            identity.Trust);

        byte[] tampered = File.ReadAllBytes(jsonPath);
        tampered[^2] ^= 0x01;
        File.WriteAllBytes(jsonPath, tampered);
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadCurrent(Now));

        foreach (string path in Directory.EnumerateFiles(
                     environment.Layout.WorkerStatusRoot))
        {
            File.Delete(path);
        }

        WriteAnchor(
            environment.Layout,
            identity.Identity,
            anchor);
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadCurrent(
                anchor.ExpiresAt));

        WriteAnchor(
            environment.Layout,
            identity.Identity,
            new WorkerAuditAnchorV1(
                anchor.WorkerSequence,
                anchor.WorkerEventDigest,
                anchor.WorkerVersion,
                workerReady: false,
                timestampDependencyReady: true,
                anchor.PublishedAt,
                anchor.ExpiresAt,
                anchor.ReceiptSignerSpkiSha256));
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadCurrent(Now));
    }

    private static WorkerAuditAnchorV1 CreateAnchor(
        string receiptSignerSpkiSha256)
    {
        return new WorkerAuditAnchorV1(
            1,
            new string('a', 64),
            GatewayReadinessProbe
                .RequiredWorkerVersion,
            workerReady: true,
            timestampDependencyReady: true,
            Now,
            Now.AddMinutes(2),
            receiptSignerSpkiSha256);
    }

    private static string WriteAnchor(
        GatewayDirectoryLayout layout,
        GatewayCmsTestIdentity identity,
        WorkerAuditAnchorV1 anchor)
    {
        byte[] json =
            WorkerAuditAnchorJson.Serialize(anchor);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(json));
        string jsonPath = Path.Combine(
            layout.WorkerStatusRoot,
            WorkerAuditAnchorFiles.GetJsonFileName(digest));
        File.WriteAllBytes(jsonPath, json);
        File.WriteAllBytes(
            Path.Combine(
                layout.WorkerStatusRoot,
                WorkerAuditAnchorFiles
                    .GetSignatureFileName(digest)),
            identity.Sign(json, detached: true));
        return jsonPath;
    }

    private sealed class TestAnchorIdentity :
        IDisposable
    {
        private readonly GatewayCmsTestCertificateAuthority
            _authority;
        private readonly X509Certificate2 _root;

        private TestAnchorIdentity(
            GatewayCmsTestCertificateAuthority authority,
            GatewayCmsTestIdentity identity,
            X509Certificate2 root)
        {
            _authority = authority;
            Identity = identity;
            _root = root;
            Trust = new CmsTrustPolicy(
                identity.SubjectPublicKeyInfoSha256,
                RequiredEkuOid,
                [root],
                CmsRevocationPolicy.DisposableTestNoCheck,
                TimeSpan.FromSeconds(1));
        }

        internal GatewayCmsTestIdentity Identity { get; }

        internal CmsTrustPolicy Trust { get; }

        internal static TestAnchorIdentity Create()
        {
            GatewayCmsTestCertificateAuthority authority =
                GatewayCmsTestCertificateAuthority.Create(
                    Now.AddDays(-1),
                    Now.AddDays(1));
            GatewayCmsTestIdentity identity =
                GatewayCmsTestIdentity.CreateIssued(
                    authority,
                    Now.AddHours(-1),
                    Now.AddHours(1),
                    RequiredEkuOid);
            X509Certificate2 root =
                authority.ExportPublicCertificate();
            return new TestAnchorIdentity(
                authority,
                identity,
                root);
        }

        public void Dispose()
        {
            Identity.Dispose();
            _root.Dispose();
            _authority.Dispose();
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

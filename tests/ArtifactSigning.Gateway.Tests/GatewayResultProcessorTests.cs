using System.Formats.Tar;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayResultProcessorTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 18, 0, 0, TimeSpan.Zero);
    private static readonly string[] ExpectedArchiveNames =
    [
        "signing-receipt.json",
        "signing-receipt.p7s",
        "bundle/manifest.json",
        "bundle/agent.exe",
    ];

    [Fact]
    public void AcceptsBoundReceiptAndBuildsClosedResultArchive()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        using GatewayCmsTestCertificateAuthority authority =
            GatewayCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using GatewayCmsTestIdentity receiptSigner =
            GatewayCmsTestIdentity.CreateIssued(
                authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = new(
            receiptSigner.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
        SyntheticProfile profile = new();
        SigningProfileRegistry profiles = new([profile]);
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('a');
        string submitterSpki = Digest('b');
        string approverSpki = Digest('c');
        GatewayRequestRecord signing = CreateSigningRequest(
            store,
            request,
            requestDigest,
            submitterSpki,
            approverSpki);
        IReadOnlyDictionary<string, byte[]> resultContent =
            new Dictionary<string, byte[]>(
                StringComparer.Ordinal)
            {
                ["manifest.json"] = "finalized manifest"u8
                    .ToArray(),
                ["agent.exe"] = "signed executable"u8
                    .ToArray(),
            };
        WriteWorkerResult(
            store.Layout,
            request,
            requestDigest,
            submitterSpki,
            approverSpki,
            receiptSigner,
            resultContent);
        GatewayResultProcessor processor = new(
            store,
            profiles,
            trust,
            new FixedTimeProvider(Now.AddSeconds(5)));

        GatewayWorkerObservationResult observed =
            processor.Observe(signing);

        Assert.Equal(
            GatewayWorkerObservationOutcome.Completed,
            observed.Outcome);
        Assert.Equal(
            RequestState.Signed,
            observed.Request?.State);
        using GatewayPreparedResultArchive archive =
            processor.PrepareResultArchive(
                observed.Request!);
        using FileStream input = File.OpenRead(
            archive.ArchivePath);
        using TarReader reader = new(input);
        List<string> names = [];
        TarEntry? entry;
        while ((entry = reader.GetNextEntry()) is not null)
        {
            names.Add(entry.Name);
        }

        Assert.Equal(
            ExpectedArchiveNames,
            names);
        store.VerifyIntegrity();
    }

    [Fact]
    public void QuarantinesResultWhoseArtifactChangedAfterReceipt()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        using GatewayCmsTestCertificateAuthority authority =
            GatewayCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using GatewayCmsTestIdentity receiptSigner =
            GatewayCmsTestIdentity.CreateIssued(
                authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = new(
            receiptSigner.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
        SyntheticProfile profile = new();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('d');
        GatewayRequestRecord signing = CreateSigningRequest(
            store,
            request,
            requestDigest,
            Digest('e'),
            Digest('f'));
        Dictionary<string, byte[]> resultContent = new(
            StringComparer.Ordinal)
        {
            ["manifest.json"] = "finalized manifest"u8
                .ToArray(),
            ["agent.exe"] = "signed executable"u8
                .ToArray(),
        };
        WriteWorkerResult(
            store.Layout,
            request,
            requestDigest,
            Digest('e'),
            Digest('f'),
            receiptSigner,
            resultContent);
        File.WriteAllBytes(
            Path.Combine(
                store.Layout.OutputRoot,
                request.RequestId.ToString("N"),
                "bundle",
                "agent.exe"),
            "changed executable"u8.ToArray());
        GatewayResultProcessor processor = new(
            store,
            new SigningProfileRegistry([profile]),
            trust,
            new FixedTimeProvider(Now.AddSeconds(5)));

        GatewayWorkerObservationResult observed =
            processor.Observe(signing);

        Assert.Equal(
            GatewayWorkerObservationOutcome.Quarantined,
            observed.Outcome);
        Assert.Equal(
            RequestState.Quarantined,
            observed.Request?.State);
        store.VerifyIntegrity();
    }

    [Fact]
    public void WorkerFailureCategoryRemainsPrivateAtGatewayBoundary()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        using GatewayCmsTestCertificateAuthority authority =
            GatewayCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using GatewayCmsTestIdentity receiptSigner =
            GatewayCmsTestIdentity.CreateIssued(
                authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = new(
            receiptSigner.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
        SyntheticProfile profile = new();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = Digest('7');
        GatewayRequestRecord signing = CreateSigningRequest(
            store,
            request,
            requestDigest,
            Digest('8'),
            Digest('9'));
        Directory.CreateDirectory(store.Layout.WorkerStatusRoot);
        WorkerTerminalStatusV1 status = new(
            request.RequestId,
            requestDigest,
            RequestState.Quarantined,
            "SigningToolInvocationFailed",
            evidenceDigest: null,
            Now.AddSeconds(3));
        File.WriteAllBytes(
            Path.Combine(
                store.Layout.WorkerStatusRoot,
                $"{request.RequestId:N}.json"),
            WorkerTerminalStatusJson.Serialize(status));
        GatewayResultProcessor processor = new(
            store,
            new SigningProfileRegistry([profile]),
            trust,
            new FixedTimeProvider(Now.AddSeconds(5)));

        GatewayWorkerObservationResult observed =
            processor.Observe(signing);

        Assert.Equal(
            GatewayWorkerObservationOutcome.Quarantined,
            observed.Outcome);
        Assert.Equal(RequestState.Quarantined, observed.Request?.State);
        Assert.Equal(
            GatewayResultCode.WorkerResultRejected,
            observed.Request?.ResultCode);
        Assert.DoesNotContain(
            "SigningToolInvocationFailed",
            observed.Request?.ResultCode.ToString(),
            StringComparison.Ordinal);
        store.VerifyIntegrity();
    }

    private static GatewayRequestRecord CreateSigningRequest(
        GatewayStateStore store,
        ArtifactSigningRequestV1 request,
        string requestDigest,
        string submitterSpki,
        string approverSpki)
    {
        GatewayRequestRecord pending = store.AdmitPending(
                request,
                requestDigest,
                submitterSpki,
                Now)
            .Request!;
        ArtifactSigningApprovalV1 approval = new(
            request.RequestId,
            requestDigest,
            ApprovalDecision.Approve,
            "Approved for result processing",
            Now.AddSeconds(1),
            Now.AddMinutes(2),
            CanonicalNonce(0x22));
        GatewayRequestRecord approved =
            store.TryRecordApproval(
                    request.RequestId,
                    requestDigest,
                    pending.RowVersion,
                    approval,
                    approverSpki,
                    Digest('1'),
                    requireDistinctSubmitterAndApprover: true,
                    Now.AddSeconds(1))
                .Request!;
        return store.TryMarkWorkerDispatched(
                request.RequestId,
                requestDigest,
                approved.RowVersion,
                Now.AddSeconds(2))
            .Request!;
    }

    private static void WriteWorkerResult(
        GatewayDirectoryLayout layout,
        ArtifactSigningRequestV1 request,
        string requestDigest,
        string submitterSpki,
        string approverSpki,
        GatewayCmsTestIdentity receiptSigner,
        IReadOnlyDictionary<string, byte[]> resultContent)
    {
        string output = Path.Combine(
            layout.OutputRoot,
            request.RequestId.ToString("N"));
        string bundle = Path.Combine(output, "bundle");
        Directory.CreateDirectory(bundle);
        foreach ((string name, byte[] content) in resultContent)
        {
            File.WriteAllBytes(
                Path.Combine(bundle, name),
                content);
        }

        ArtifactSigningReceiptV1 receipt = new(
            request.RequestId,
            requestDigest,
            request.ProjectId,
            request.ProfileId,
            request.ProfileVersion,
            request.SourceRepository,
            request.SourceCommit,
            request.ReleaseVersion,
            request.SignerPolicyId,
            request.TimestampPolicyId,
            submitterSpki,
            approverSpki,
            receiptSigner.SubjectPublicKeyInfoSha256,
            request.Artifacts.Select(item =>
                new ReceiptArtifactV1(
                    item.Role,
                    item.File,
                    item.Size,
                    item.Sha256)),
            [
                ResultArtifact(
                    "Manifest",
                    "manifest.json",
                    resultContent["manifest.json"]),
                ResultArtifact(
                    "Agent",
                    "agent.exe",
                    resultContent["agent.exe"]),
            ],
            [
                new ReceiptAuthenticodeArtifactV1(
                    "Agent",
                    "agent.exe",
                    request.Artifacts.Single(item =>
                        item.Role is "Agent").Sha256,
                    Sha256(resultContent["agent.exe"]),
                    new string('A', 40),
                    new string('B', 40),
                    Now.AddSeconds(2)),
            ],
            "0.7.0",
            Digest('2'),
            1,
            Now.AddSeconds(3));
        byte[] receiptJson =
            ArtifactSigningReceiptJsonSerializer.Serialize(
                receipt);
        File.WriteAllBytes(
            Path.Combine(output, "signing-receipt.json"),
            receiptJson);
        File.WriteAllBytes(
            Path.Combine(output, "signing-receipt.p7s"),
            receiptSigner.Sign(receiptJson, detached: true));
        string evidenceDigest =
            SigningReceiptDigest.ComputeHex(receiptJson);
        WorkerTerminalStatusV1 status = new(
            request.RequestId,
            requestDigest,
            RequestState.Signed,
            "SigningCompleted",
            evidenceDigest,
            Now.AddSeconds(4));
        File.WriteAllBytes(
            Path.Combine(
                layout.WorkerStatusRoot,
                $"{request.RequestId:N}.json"),
            WorkerTerminalStatusJson.Serialize(status));
    }

    private static ReceiptArtifactV1 ResultArtifact(
        string role,
        string file,
        byte[] content)
    {
        return new ReceiptArtifactV1(
            role,
            file,
            content.LongLength,
            Sha256(content));
    }

    private static ArtifactSigningRequestV1 CreateRequest()
    {
        return new ArtifactSigningRequestV1(
            Guid.NewGuid(),
            SyntheticProfile.ProjectId,
            SyntheticProfile.ProfileId,
            SyntheticProfile.ProfileVersion,
            SyntheticProfile.SourceRepository,
            new string('3', 40),
            "1.0.0",
            Now.AddMinutes(-1),
            Now.AddMinutes(10),
            CanonicalNonce(0x21),
            SyntheticProfile.SignerPolicyId,
            SyntheticProfile.TimestampPolicyId,
            [
                new RequestArtifactV1(
                    "Manifest",
                    "manifest.json",
                    8,
                    Digest('4')),
                new RequestArtifactV1(
                    "Agent",
                    "agent.exe",
                    16,
                    Digest('5')),
            ]);
    }

    private static string Sha256(ReadOnlySpan<byte> content)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(content));
    }

    private static string Digest(char value)
    {
        return new string(value, 64);
    }

    private static string CanonicalNonce(byte value)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(value, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed class SyntheticProfile : ISigningProfile
    {
        internal const string ProfileId =
            "GatewayResultTestV1";
        internal const int ProfileVersion = 1;
        internal const string ProjectId =
            "gateway-result-test";
        internal const string SourceRepository =
            "example/gateway-result-test";
        internal const string SignerPolicyId =
            "GatewayResultSignerV1";
        internal const string TimestampPolicyId =
            "GatewayResultTimestampV1";

        private static readonly SigningProfileDescriptor
            CompiledDescriptor = new(
                new SigningProfileIdentity(
                    ProfileId,
                    ProfileVersion),
                [ProjectId],
                [SourceRepository],
                [
                    new SigningProfileArtifactDefinition(
                        "Manifest",
                        "manifest.json",
                        SigningProfileArtifactKind
                            .JsonManifest,
                        4096),
                    new SigningProfileArtifactDefinition(
                        "Agent",
                        "agent.exe",
                        SigningProfileArtifactKind
                            .PortableExecutable,
                        4096),
                ],
                [SignerPolicyId],
                [TimestampPolicyId],
                8192);

        public SigningProfileDescriptor Descriptor =>
            CompiledDescriptor;

        public SigningProfileValidationResult
            ValidateUnsignedBundle(
                SigningProfileValidationContext context)
        {
            return SigningProfileValidationResult.Success;
        }

        public SigningProfileFinalizationResult
            FinalizeSignedBundle(
                SigningProfileFinalizationContext context)
        {
            return SigningProfileFinalizationResult
                .Failure(
                    SigningProfileValidationError
                        .FinalizedManifestInvalid);
        }

        public SigningProfileValidationResult
            ValidateFinalizedBundle(
                SigningProfileFinalizedValidationContext
                    context)
        {
            return SigningProfileValidationResult.Success;
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

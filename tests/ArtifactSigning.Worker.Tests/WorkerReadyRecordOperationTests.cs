using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerReadyRecordOperationTests
{
    private const string RequiredEkuOid = "1.3.6.1.5.5.7.3.2";
    private const string AuthenticodeThumbprint =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string TimestampAuthorityThumbprint =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CompletesClosedReadyRecordAndPublishesSignedReceipt()
    {
        using ReadyRecordEnvironment environment = new();

        WorkerProcessingResult result =
            await environment.Processor.ProcessApprovedAsync(
                environment.Request.RequestId,
                environment.RequestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Completed, result.Outcome);
        Assert.Equal(RequestState.Signed, result.Job?.State);
        Assert.Equal(1, environment.ArtifactSigner.CallCount);
        string output = environment.State.Layout.GetOutputDirectory(
            environment.Request.RequestId);
        Assert.Equal(
            new[]
            {
                WorkerReadyRecordOperation.BundleDirectoryName,
                WorkerReadyRecordOperation.ReceiptJsonFileName,
                WorkerReadyRecordOperation.ReceiptSignatureFileName,
            },
            Directory.EnumerateFileSystemEntries(output)
                .Select(Path.GetFileName)
                .Order(StringComparer.Ordinal));
        string bundle = Path.Combine(
            output,
            WorkerReadyRecordOperation.BundleDirectoryName);
        Assert.Equal(
            SyntheticSigningProfile.FinalizedManifest,
            await File.ReadAllTextAsync(
                Path.Combine(
                    bundle,
                    SyntheticSigningProfile.ManifestFileName),
                TestContext.Current.CancellationToken));
        Assert.Equal(
            SyntheticSigningProfile.SignedAgent,
            await File.ReadAllTextAsync(
                Path.Combine(
                    bundle,
                    SyntheticSigningProfile.AgentFileName),
                TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(
            bundle,
            SyntheticSigningProfile.BuildEvidenceFileName)));
        Assert.False(File.Exists(Path.Combine(
            output,
            WorkerReadyRecordOperation.RequestJsonFileName)));

        byte[] receiptJson = await File.ReadAllBytesAsync(
            Path.Combine(
                output,
                WorkerReadyRecordOperation.ReceiptJsonFileName),
            TestContext.Current.CancellationToken);
        byte[] receiptSignature = await File.ReadAllBytesAsync(
            Path.Combine(
                output,
                WorkerReadyRecordOperation.ReceiptSignatureFileName),
            TestContext.Current.CancellationToken);
        TrustedDetachedCmsVerificationResult receiptVerification =
            TrustedDetachedCmsSignatureVerifier.Verify(
                receiptJson,
                receiptSignature,
                environment.ReceiptTrustPolicy,
                Now);

        Assert.True(receiptVerification.IsSuccess);
        Assert.Equal(
            SigningReceiptDigest.ComputeHex(receiptJson),
            result.Job?.EvidenceDigest);
        string receiptText = Encoding.UTF8.GetString(receiptJson);
        Assert.Contains(
            environment.RequestDigest,
            receiptText,
            StringComparison.Ordinal);
        Assert.Contains(
            TimestampAuthorityThumbprint,
            receiptText,
            StringComparison.Ordinal);
        environment.State.VerifyIntegrity();
    }

    [Fact]
    public async Task AlteredRequestSignatureFailsBeforeSigning()
    {
        using ReadyRecordEnvironment environment = new();
        string signaturePath = Path.Combine(
            environment.WorkDirectory,
            WorkerReadyRecordOperation.RequestSignatureFileName);
        byte[] signature = await File.ReadAllBytesAsync(
            signaturePath,
            TestContext.Current.CancellationToken);
        signature[^1] ^= 0x01;
        await File.WriteAllBytesAsync(
            signaturePath,
            signature,
            TestContext.Current.CancellationToken);

        WorkerProcessingResult result =
            await environment.Processor.ProcessApprovedAsync(
                environment.Request.RequestId,
                environment.RequestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerProcessingOutcome.FailedBeforeSigning,
            result.Outcome);
        Assert.Equal(0, environment.ArtifactSigner.CallCount);
        Assert.Equal(RequestState.Failed, result.Job?.State);
    }

    [Fact]
    public async Task AlteredProfileArtifactFailsBeforeSigning()
    {
        using ReadyRecordEnvironment environment = new();
        await File.WriteAllTextAsync(
            Path.Combine(
                environment.WorkDirectory,
                WorkerReadyRecordOperation.BundleDirectoryName,
                SyntheticSigningProfile.AgentFileName),
            "altered-agent",
            TestContext.Current.CancellationToken);

        WorkerProcessingResult result =
            await environment.Processor.ProcessApprovedAsync(
                environment.Request.RequestId,
                environment.RequestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerProcessingOutcome.FailedBeforeSigning,
            result.Outcome);
        Assert.Equal(0, environment.ArtifactSigner.CallCount);
    }

    [Theory]
    [InlineData(
        WorkerArtifactSigningError.UnsignedInspectionFailed,
        WorkerResultCode.SigningArtifactPrecheckFailed)]
    [InlineData(
        WorkerArtifactSigningError.SignToolFailed,
        WorkerResultCode.SigningToolInvocationFailed)]
    [InlineData(
        WorkerArtifactSigningError.SignedSnapshotInvalid,
        WorkerResultCode.SigningSignatureVerificationFailed)]
    [InlineData(
        WorkerArtifactSigningError.SignedVerificationFailed,
        WorkerResultCode.SigningSignatureVerificationFailed)]
    public async Task ArtifactSignerFailurePersistsFixedCategory(
        WorkerArtifactSigningError failure,
        WorkerResultCode expected)
    {
        using ReadyRecordEnvironment environment = new(
            artifactSigningError: failure);

        WorkerProcessingResult result =
            await environment.Processor.ProcessApprovedAsync(
                environment.Request.RequestId,
                environment.RequestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(WorkerProcessingOutcome.Quarantined, result.Outcome);
        Assert.Equal(expected, result.Job?.ResultCode);
        Assert.Equal(1, environment.ArtifactSigner.CallCount);
    }

    [Fact]
    public async Task RejectionDecisionCannotCrossKeyBoundary()
    {
        using ReadyRecordEnvironment environment = new(
            ApprovalDecision.Reject);

        WorkerProcessingResult result =
            await environment.Processor.ProcessApprovedAsync(
                environment.Request.RequestId,
                environment.RequestDigest,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerProcessingOutcome.FailedBeforeSigning,
            result.Outcome);
        Assert.Equal(0, environment.ArtifactSigner.CallCount);
    }

    [Fact]
    public void ProductionPolicyRejectsSameSubmitterAndApprover()
    {
        using WorkerCmsTestCertificateAuthority authority =
            CreateAuthority();
        using WorkerCmsTestIdentity identity =
            CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = CreateTrustPolicy(
            identity,
            publicRoot);

        Assert.Throws<ArgumentException>(
            () => new WorkerAuthorizationPolicy(
                SyntheticSigningProfile.ProjectId,
                SyntheticSigningProfile.ProfileId,
                SyntheticSigningProfile.ProfileVersion,
                trust,
                trust,
                requireDistinctSubmitterAndApprover: true));
    }

    [Fact]
    public void WorkerRejectsReceiptAndAuthenticodeSpkiReuse()
    {
        using WorkerStateTestEnvironment stateEnvironment = new();
        WorkerStateStore state = stateEnvironment.CreateStore();
        using WorkerCmsTestCertificateAuthority authority =
            CreateAuthority();
        using WorkerCmsTestIdentity submitter =
            CreateIdentity(authority);
        using WorkerCmsTestIdentity approver =
            CreateIdentity(authority);
        using WorkerCmsTestIdentity receipt =
            CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy submitterTrust =
            CreateTrustPolicy(submitter, publicRoot);
        CmsTrustPolicy approverTrust =
            CreateTrustPolicy(approver, publicRoot);
        CmsTrustPolicy receiptTrust =
            CreateTrustPolicy(receipt, publicRoot);
        WorkerReceiptCmsSigner receiptSigner = new(
            receipt.Certificate,
            receiptTrust);
        WorkerInstalledSigningPolicy signingPolicy = new(
            SyntheticSigningProfile.SignerPolicyId,
            SyntheticSigningProfile.TimestampPolicyId,
            new string('1', 64),
            AuthenticodeThumbprint,
            receipt.SubjectPublicKeyInfoSha256,
            new FakeArtifactSigner());

        Assert.Throws<ArgumentException>(
            () => new WorkerReadyRecordOperation(
                state,
                new SigningProfileRegistry(
                    [SyntheticSigningProfile.Instance]),
                [
                    new WorkerAuthorizationPolicy(
                        SyntheticSigningProfile.ProjectId,
                        SyntheticSigningProfile.ProfileId,
                        SyntheticSigningProfile.ProfileVersion,
                        submitterTrust,
                        approverTrust,
                        requireDistinctSubmitterAndApprover: true),
                ],
                [signingPolicy],
                receiptSigner,
                new FixedTimeProvider(Now)));
    }

    private static WorkerCmsTestCertificateAuthority CreateAuthority()
    {
        return WorkerCmsTestCertificateAuthority.Create(
            Now.AddDays(-1),
            Now.AddDays(1));
    }

    private static WorkerCmsTestIdentity CreateIdentity(
        WorkerCmsTestCertificateAuthority authority)
    {
        return WorkerCmsTestIdentity.CreateIssued(
            authority,
            Now.AddHours(-1),
            Now.AddHours(1),
            RequiredEkuOid);
    }

    private static CmsTrustPolicy CreateTrustPolicy(
        WorkerCmsTestIdentity identity,
        X509Certificate2 publicRoot)
    {
        return new CmsTrustPolicy(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [publicRoot],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
    }

    private sealed class ReadyRecordEnvironment : IDisposable
    {
        private readonly WorkerStateTestEnvironment _stateEnvironment;
        private readonly WorkerCmsTestCertificateAuthority _authority;
        private readonly WorkerCmsTestIdentity _submitter;
        private readonly WorkerCmsTestIdentity _approver;
        private readonly WorkerCmsTestIdentity _receipt;

        internal ReadyRecordEnvironment(
            ApprovalDecision decision = ApprovalDecision.Approve,
            WorkerArtifactSigningError artifactSigningError =
                WorkerArtifactSigningError.None)
        {
            _stateEnvironment = new WorkerStateTestEnvironment();
            State = _stateEnvironment.CreateStore();
            _authority = CreateAuthority();
            _submitter = CreateIdentity(_authority);
            _approver = CreateIdentity(_authority);
            _receipt = CreateIdentity(_authority);
            using X509Certificate2 publicRoot =
                _authority.ExportPublicCertificate();
            CmsTrustPolicy submitterTrust =
                CreateTrustPolicy(_submitter, publicRoot);
            CmsTrustPolicy approverTrust =
                CreateTrustPolicy(_approver, publicRoot);
            ReceiptTrustPolicy =
                CreateTrustPolicy(_receipt, publicRoot);

            WorkDirectory = State.Layout.GetWorkDirectory(
                Guid.NewGuid());
            Directory.CreateDirectory(WorkDirectory);
            string bundleDirectory = Path.Combine(
                WorkDirectory,
                WorkerReadyRecordOperation.BundleDirectoryName);
            Directory.CreateDirectory(bundleDirectory);
            Dictionary<string, byte[]> artifacts =
                SyntheticSigningProfile.CreateUnsignedArtifacts();
            Request = CreateRequest(
                Path.GetFileName(WorkDirectory),
                artifacts);
            RequestDigest = WriteReadyRecord(
                WorkDirectory,
                bundleDirectory,
                artifacts,
                decision);

            WorkerMutationResult admitted = State.AdmitApproved(
                Request.RequestId,
                RequestDigest,
                Now.AddMinutes(-1));
            Assert.Equal(
                WorkerMutationOutcome.Applied,
                admitted.Outcome);

            ArtifactSigner = new FakeArtifactSigner(
                artifactSigningError);
            WorkerInstalledSigningPolicy signingPolicy = new(
                SyntheticSigningProfile.SignerPolicyId,
                SyntheticSigningProfile.TimestampPolicyId,
                new string('1', 64),
                AuthenticodeThumbprint,
                new string('2', 64),
                ArtifactSigner);
            WorkerReceiptCmsSigner receiptSigner = new(
                _receipt.Certificate,
                ReceiptTrustPolicy);
            WorkerReadyRecordOperation operation = new(
                State,
                new SigningProfileRegistry(
                    [SyntheticSigningProfile.Instance]),
                [
                    new WorkerAuthorizationPolicy(
                        SyntheticSigningProfile.ProjectId,
                        SyntheticSigningProfile.ProfileId,
                        SyntheticSigningProfile.ProfileVersion,
                        submitterTrust,
                        approverTrust,
                        requireDistinctSubmitterAndApprover: true),
                ],
                [signingPolicy],
                receiptSigner,
                new FixedTimeProvider(Now));
            Processor = new WorkerJobProcessor(
                State,
                operation,
                operation,
                new TestOutputPublisher(State.Layout),
                new FixedTimeProvider(Now));
        }

        internal WorkerStateStore State { get; }

        internal ArtifactSigningRequestV1 Request { get; private set; }

        internal string RequestDigest { get; }

        internal string WorkDirectory { get; }

        internal FakeArtifactSigner ArtifactSigner { get; }

        internal WorkerJobProcessor Processor { get; }

        internal CmsTrustPolicy ReceiptTrustPolicy { get; }

        public void Dispose()
        {
            _receipt.Dispose();
            _approver.Dispose();
            _submitter.Dispose();
            _authority.Dispose();
            _stateEnvironment.Dispose();
        }

        private string WriteReadyRecord(
            string workDirectory,
            string bundleDirectory,
            IReadOnlyDictionary<string, byte[]> artifacts,
            ApprovalDecision decision)
        {
            foreach ((string fileName, byte[] content) in artifacts)
            {
                File.WriteAllBytes(
                    Path.Combine(bundleDirectory, fileName),
                    content);
            }

            byte[] requestJson = SerializeRequest(Request);
            string requestDigest =
                ArtifactSigning.Protocol.RequestDigest.ComputeHex(
                    requestJson);
            byte[] approvalJson = SerializeApproval(
                Request.RequestId,
                requestDigest,
                decision);
            File.WriteAllBytes(
                Path.Combine(
                    workDirectory,
                    WorkerReadyRecordOperation.RequestJsonFileName),
                requestJson);
            File.WriteAllBytes(
                Path.Combine(
                    workDirectory,
                    WorkerReadyRecordOperation
                        .RequestSignatureFileName),
                _submitter.Sign(requestJson, detached: true));
            File.WriteAllBytes(
                Path.Combine(
                    workDirectory,
                    WorkerReadyRecordOperation
                        .ApprovalSignatureFileName),
                _approver.Sign(approvalJson, detached: false));
            return requestDigest;
        }

        private static ArtifactSigningRequestV1 CreateRequest(
            string requestDirectoryName,
            Dictionary<string, byte[]> artifacts)
        {
            Guid requestId = Guid.ParseExact(
                requestDirectoryName,
                "N");
            IReadOnlyList<RequestArtifactV1> requestArtifacts =
                SyntheticSigningProfile.Instance.Descriptor.Artifacts
                    .Select(definition =>
                    {
                        byte[] content = artifacts[definition.FileName];
                        return new RequestArtifactV1(
                            definition.Role,
                            definition.FileName,
                            content.Length,
                            Sha256(content));
                    })
                    .ToArray();
            return new ArtifactSigningRequestV1(
                requestId,
                SyntheticSigningProfile.ProjectId,
                SyntheticSigningProfile.ProfileId,
                SyntheticSigningProfile.ProfileVersion,
                SyntheticSigningProfile.SourceRepository,
                "0123456789abcdef0123456789abcdef01234567",
                "1.2.3",
                Now.AddMinutes(-2),
                Now.AddMinutes(10),
                CanonicalNonce(),
                SyntheticSigningProfile.SignerPolicyId,
                SyntheticSigningProfile.TimestampPolicyId,
                requestArtifacts);
        }
    }

    private sealed class FakeArtifactSigner(
        WorkerArtifactSigningError resultError =
            WorkerArtifactSigningError.None) : IWorkerArtifactSigner
    {
        internal int CallCount { get; private set; }

        public async ValueTask<WorkerArtifactSigningResult>
            SignAndVerifyAsync(
                Guid trustedRequestId,
                string trustedWorkDirectory,
                string trustedRole,
                string trustedFileName,
                string trustedAbsoluteArtifactPath,
                long expectedUnsignedSize,
                string expectedUnsignedSha256,
                CancellationToken cancellationToken = default)
        {
            Assert.NotEqual(Guid.Empty, trustedRequestId);
            Assert.Equal(
                Path.GetDirectoryName(
                    Path.GetDirectoryName(trustedAbsoluteArtifactPath)),
                trustedWorkDirectory);
            CallCount++;
            if (resultError is not WorkerArtifactSigningError.None)
            {
                return new WorkerArtifactSigningResult(
                    null,
                    null,
                    resultError);
            }

            byte[] unsigned = await File.ReadAllBytesAsync(
                    trustedAbsoluteArtifactPath,
                    cancellationToken)
                .ConfigureAwait(true);
            Assert.Equal(expectedUnsignedSize, unsigned.Length);
            Assert.Equal(expectedUnsignedSha256, Sha256(unsigned));
            byte[] signed =
                Encoding.UTF8.GetBytes(SyntheticSigningProfile.SignedAgent);
            await File.WriteAllBytesAsync(
                    trustedAbsoluteArtifactPath,
                    signed,
                    cancellationToken)
                .ConfigureAwait(true);
            return new WorkerArtifactSigningResult(
                new VerifiedAuthenticodeArtifact(
                    trustedRole,
                    trustedFileName,
                    signed.Length,
                    Sha256(signed),
                    AuthenticodeThumbprint,
                    Now.AddMinutes(-1)),
                TimestampAuthorityThumbprint,
                WorkerArtifactSigningError.None);
        }
    }

    private sealed class TestOutputPublisher(
        WorkerDirectoryLayout layout) : IWorkerOutputPublisher
    {
        public bool TryPublish(WorkerJobRecord signingJob)
        {
            return layout.TryPublish(signingJob.RequestId);
        }
    }

    private sealed class SyntheticSigningProfile : ISigningProfile
    {
        internal const string ProjectId = "synthetic-project";
        internal const string ProfileId = "SyntheticBundleV1";
        internal const int ProfileVersion = 1;
        internal const string SourceRepository = "example/synthetic";
        internal const string SignerPolicyId = "SyntheticSignerV1";
        internal const string TimestampPolicyId =
            "SyntheticTimestampV1";
        internal const string ManifestFileName = "manifest.json";
        internal const string BuildEvidenceFileName = "evidence.json";
        internal const string AgentFileName = "agent.exe";
        internal const string UnsignedManifest =
            "{\"State\":\"Unsigned\"}\n";
        internal const string FinalizedManifest =
            "{\"State\":\"Finalized\"}\n";
        internal const string BuildEvidence = "{\"Clean\":true}\n";
        internal const string UnsignedAgent = "unsigned-agent";
        internal const string SignedAgent = "signed-agent";

        private static readonly SigningProfileDescriptor CompiledDescriptor =
            new(
                new SigningProfileIdentity(ProfileId, ProfileVersion),
                [ProjectId],
                [SourceRepository],
                [
                    new SigningProfileArtifactDefinition(
                        "Manifest",
                        ManifestFileName,
                        SigningProfileArtifactKind.JsonManifest,
                        1024),
                    new SigningProfileArtifactDefinition(
                        "BuildEvidence",
                        BuildEvidenceFileName,
                        SigningProfileArtifactKind.JsonBuildEvidence,
                        1024),
                    new SigningProfileArtifactDefinition(
                        "Agent",
                        AgentFileName,
                        SigningProfileArtifactKind.PortableExecutable,
                        1024),
                ],
                [SignerPolicyId],
                [TimestampPolicyId],
                4096);

        internal static SyntheticSigningProfile Instance { get; } = new();

        public SigningProfileDescriptor Descriptor =>
            CompiledDescriptor;

        internal static Dictionary<string, byte[]>
            CreateUnsignedArtifacts()
        {
            return new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [ManifestFileName] =
                    Encoding.UTF8.GetBytes(UnsignedManifest),
                [BuildEvidenceFileName] =
                    Encoding.UTF8.GetBytes(BuildEvidence),
                [AgentFileName] =
                    Encoding.UTF8.GetBytes(UnsignedAgent),
            };
        }

        public SigningProfileValidationResult ValidateUnsignedBundle(
            SigningProfileValidationContext context)
        {
            SigningProfileValidationError requestError =
                SigningProfileRequestValidator.Validate(
                    Descriptor,
                    context.Request);
            if (requestError is not SigningProfileValidationError.None)
            {
                return SigningProfileValidationResult.Failure(
                    requestError);
            }

            Dictionary<string, byte[]> expected =
                CreateUnsignedArtifacts();
            foreach (SigningProfileArtifactDefinition definition
                     in Descriptor.Artifacts)
            {
                byte[] actual = ReadAll(
                    context.ArtifactReader,
                    definition.FileName);
                RequestArtifactV1 requestArtifact =
                    context.Request.Artifacts.Single(artifact =>
                        string.Equals(
                            artifact.Role,
                            definition.Role,
                            StringComparison.Ordinal));
                if (!actual.AsSpan().SequenceEqual(
                        expected[definition.FileName])
                    || actual.Length != requestArtifact.Size
                    || !string.Equals(
                        Sha256(actual),
                        requestArtifact.Sha256,
                        StringComparison.Ordinal))
                {
                    return SigningProfileValidationResult.Failure(
                        SigningProfileValidationError
                            .ArtifactHashMismatch);
                }
            }

            return SigningProfileValidationResult.Success;
        }

        public SigningProfileFinalizationResult FinalizeSignedBundle(
            SigningProfileFinalizationContext context)
        {
            if (!ReadText(
                    context.UnsignedArtifactReader,
                    AgentFileName).Equals(
                    UnsignedAgent,
                    StringComparison.Ordinal)
                || !ReadText(
                    context.SignedArtifactReader,
                    AgentFileName).Equals(
                    SignedAgent,
                    StringComparison.Ordinal)
                || context.VerifiedArtifacts.Count is not 1)
            {
                return SigningProfileFinalizationResult.Failure(
                    SigningProfileValidationError
                        .SignatureEvidenceMismatch);
            }

            return SigningProfileFinalizationResult.Success(
                Encoding.UTF8.GetBytes(FinalizedManifest));
        }

        public SigningProfileValidationResult ValidateFinalizedBundle(
            SigningProfileFinalizedValidationContext context)
        {
            if (!ReadText(
                    context.FinalizedArtifactReader,
                    ManifestFileName).Equals(
                    FinalizedManifest,
                    StringComparison.Ordinal)
                || !ReadText(
                    context.FinalizedArtifactReader,
                    AgentFileName).Equals(
                    SignedAgent,
                    StringComparison.Ordinal)
                || context.VerifiedArtifacts.Count is not 1)
            {
                return SigningProfileValidationResult.Failure(
                    SigningProfileValidationError
                        .FinalizedManifestInvalid);
            }

            return SigningProfileValidationResult.Success;
        }

        private static byte[] ReadAll(
            IProfileArtifactReader reader,
            string fileName)
        {
            using Stream stream = reader.OpenRead(fileName);
            using MemoryStream content = new();
            stream.CopyTo(content);
            return content.ToArray();
        }

        private static string ReadText(
            IProfileArtifactReader reader,
            string fileName)
        {
            return Encoding.UTF8.GetString(ReadAll(reader, fileName));
        }
    }

    private static byte[] SerializeRequest(
        ArtifactSigningRequestV1 request)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "Format",
                ArtifactSigningRequestV1.FormatIdentifier);
            writer.WriteString("RequestId", request.RequestId.ToString("D"));
            writer.WriteString("ProjectId", request.ProjectId);
            writer.WriteString("ProfileId", request.ProfileId);
            writer.WriteNumber("ProfileVersion", request.ProfileVersion);
            writer.WriteString(
                "SourceRepository",
                request.SourceRepository);
            writer.WriteString("SourceCommit", request.SourceCommit);
            writer.WriteString("ReleaseVersion", request.ReleaseVersion);
            writer.WriteString("RequestedAt", FormatTime(request.RequestedAt));
            writer.WriteString("ExpiresAt", FormatTime(request.ExpiresAt));
            writer.WriteString("Nonce", request.Nonce);
            writer.WriteString("SignerPolicyId", request.SignerPolicyId);
            writer.WriteString(
                "TimestampPolicyId",
                request.TimestampPolicyId);
            writer.WriteStartArray("Artifacts");
            foreach (RequestArtifactV1 artifact in request.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("Role", artifact.Role);
                writer.WriteString("File", artifact.File);
                writer.WriteNumber("Size", artifact.Size);
                writer.WriteString("Sha256", artifact.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static byte[] SerializeApproval(
        Guid requestId,
        string requestDigest,
        ApprovalDecision decision)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "Format",
                ArtifactSigningApprovalV1.FormatIdentifier);
            writer.WriteString("RequestId", requestId.ToString("D"));
            writer.WriteString("RequestDigest", requestDigest);
            writer.WriteString("Decision", decision.ToString());
            writer.WriteString("Reason", "Synthetic release accepted");
            writer.WriteString(
                "ApprovedAt",
                FormatTime(Now.AddMinutes(-1)));
            writer.WriteString(
                "ExpiresAt",
                FormatTime(Now.AddMinutes(4)));
            writer.WriteString("Nonce", CanonicalNonce(0x01));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static string CanonicalNonce(byte value = 0x00)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(value, 32).Select(item => (byte)item)
                    .ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string FormatTime(DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string Sha256(ReadOnlySpan<byte> content)
    {
        return Convert.ToHexStringLower(SHA256.HashData(content));
    }

    private sealed class FixedTimeProvider(DateTimeOffset value)
        : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }
}

using System.Formats.Tar;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayHandoffProcessorTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";

    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 16, 30, 0, TimeSpan.Zero);

    [Fact]
    public void ValidSubmissionPublishesClosedPendingRecord()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        byte[] archive = environment.CreateSubmission(request);

        GatewaySubmissionResult result =
            environment.Submit(archive);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            RequestState.PendingApproval,
            result.Request?.State);
        string pending =
            environment.Store.Layout.GetPendingRequestDirectory(
                request.RequestId);
        Assert.Equal(
            new[]
            {
                GatewaySubmissionProcessor.BundleDirectoryName,
                GatewaySubmissionProcessor.RequestJsonFileName,
                GatewaySubmissionProcessor
                    .RequestSignatureFileName,
            },
            Directory.EnumerateFileSystemEntries(pending)
                .Select(Path.GetFileName)
                .Order(StringComparer.Ordinal));
        environment.Store.VerifyIntegrity();
    }

    [Fact]
    public void ExactSubmissionRetryIsIdempotent()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        byte[] archive = environment.CreateSubmission(request);
        _ = environment.Submit(archive);

        GatewaySubmissionResult retry =
            environment.Submit(archive);

        Assert.True(retry.IsSuccess);
        Assert.Equal(request.RequestId, retry.Request?.RequestId);
        Assert.Single(
            Directory.EnumerateDirectories(
                environment.Store.Layout.PendingRoot));
    }

    [Fact]
    public void AlteredArtifactAndUnexpectedEntryFailClosed()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 first =
            environment.CreateRequest();
        byte[] alteredArchive = environment.CreateSubmission(
            first,
            manifestOverride:
                Encoding.UTF8.GetBytes("{\"Altered\":true}\n"));

        GatewaySubmissionResult altered =
            environment.Submit(alteredArchive);

        ArtifactSigningRequestV1 second =
            environment.CreateRequest();
        byte[] unexpectedArchive = environment.CreateSubmission(
            second,
            unexpectedEntry: true);
        GatewaySubmissionResult unexpected =
            environment.Submit(unexpectedArchive);

        Assert.Equal(
            GatewaySubmissionError.ProfileInvalid,
            altered.Error);
        Assert.Equal(
            GatewaySubmissionError.ArchiveInvalid,
            unexpected.Error);
        Assert.Empty(
            Directory.EnumerateDirectories(
                environment.Store.Layout.PendingRoot));
    }

    [Fact]
    public void TransportAndDetachedSignerMustBeTheSameInstalledIdentity()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        byte[] archive = environment.CreateSubmission(request);

        GatewaySubmissionResult result = environment.Submit(
            archive,
            environment.Approver
                .SubjectPublicKeyInfoSha256);

        Assert.Equal(
            GatewaySubmissionError.TransportIdentityMismatch,
            result.Error);
        Assert.Null(environment.Store.GetRequest(
            request.RequestId));
    }

    [Fact]
    public void ApprovalPublishesExactReadyRecordAndReplaysAfterExpiry()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        _ = environment.Submit(
            environment.CreateSubmission(request));
        byte[] approval =
            environment.CreateApproval(
                request,
                ApprovalDecision.Approve);

        GatewayApprovalResult result =
            environment.Approve(request.RequestId, approval);

        Assert.True(result.IsSuccess);
        Assert.True(result.WorkerNotificationRequired);
        Assert.Equal(RequestState.Approved, result.Request?.State);
        string ready =
            environment.Store.Layout.GetReadyRequestDirectory(
                request.RequestId);
        Assert.False(Directory.Exists(
            environment.Store.Layout
                .GetPendingRequestDirectory(request.RequestId)));
        Assert.Equal(
            new[]
            {
                GatewayApprovalProcessor
                    .ApprovalSignatureFileName,
                GatewaySubmissionProcessor.BundleDirectoryName,
                GatewaySubmissionProcessor.RequestJsonFileName,
                GatewaySubmissionProcessor
                    .RequestSignatureFileName,
            },
            Directory.EnumerateFileSystemEntries(ready)
                .Select(Path.GetFileName)
                .Order(StringComparer.Ordinal));

        GatewayApprovalProcessor recoveryProcessor = new(
            environment.Store,
            environment.ReadyRecordAccess,
            new FixedTimeProvider(Now.AddMinutes(10)));
        GatewayApprovalResult recovery = recoveryProcessor.Process(
            request.RequestId,
            approval,
            environment.ApproverPolicy,
            environment.Approver.SubjectPublicKeyInfoSha256);

        Assert.True(recovery.IsSuccess);
        Assert.True(recovery.WorkerNotificationRequired);
    }

    [Fact]
    public void ProductionDualControlRejectsSubmitterApproval()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        _ = environment.Submit(
            environment.CreateSubmission(request));
        byte[] approvalJson = SerializeApproval(
            request.RequestId,
            environment.Store.GetRequest(request.RequestId)!
                .RequestDigest,
            ApprovalDecision.Approve);
        byte[] signature = environment.Submitter.Sign(
            approvalJson,
            detached: false);
        GatewayApproverPolicy policy = new(
            GatewayTestProfile.ProjectId,
            GatewayTestProfile.ProfileId,
            GatewayTestProfile.ProfileVersion,
            environment.SubmitterPolicy.TrustPolicy,
            requireDistinctSubmitterAndApprover: true);
        GatewayApprovalProcessor processor = new(
            environment.Store,
            environment.ReadyRecordAccess,
            new FixedTimeProvider(Now));

        GatewayApprovalResult result = processor.Process(
            request.RequestId,
            signature,
            policy,
            environment.Submitter
                .SubjectPublicKeyInfoSha256);

        Assert.Equal(
            GatewayApprovalError.DualControlViolation,
            result.Error);
        Assert.Equal(
            RequestState.PendingApproval,
            environment.Store.GetRequest(request.RequestId)
                ?.State);
    }

    [Fact]
    public void ReadyRecordAccessFailureBlocksNotificationAndRetryRepairs()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        _ = environment.Submit(
            environment.CreateSubmission(request));
        byte[] approval = environment.CreateApproval(
            request,
            ApprovalDecision.Approve);

        GatewayApprovalResult blocked = environment.Approve(
            request.RequestId,
            approval,
            new TestReadyRecordAccessController(success: false));

        Assert.Equal(
            GatewayApprovalError.StorageFailed,
            blocked.Error);
        Assert.False(blocked.WorkerNotificationRequired);
        Assert.Equal(
            RequestState.Approved,
            environment.Store.GetRequest(request.RequestId)?.State);

        TestReadyRecordAccessController repairedAccess = new();
        GatewayApprovalResult repaired = environment.Approve(
            request.RequestId,
            approval,
            repairedAccess);

        Assert.True(repaired.IsSuccess);
        Assert.True(repaired.WorkerNotificationRequired);
        Assert.Equal(1, repairedAccess.CallCount);
    }

    [Fact]
    public void WindowsReadyRecordProjectionCreatesExactWorkerReadTree()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier gatewaySid = identity.User!;
        SecurityIdentifier systemSid = new(
            WellKnownSidType.LocalSystemSid,
            null);
        SecurityIdentifier administratorsSid = new(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
        if (gatewaySid == systemSid
            || gatewaySid == administratorsSid)
        {
            return;
        }

        using HandoffEnvironment environment = new();
        SecurityIdentifier workerSid = new(
            "S-1-5-80-101-202-303-404-505");
        SetTestParentRules(
            environment.Store.Layout.ReceivingRoot,
            gatewaySid,
            workerSid,
            workerRead: false);
        SetTestParentRules(
            environment.Store.Layout.PendingRoot,
            gatewaySid,
            workerSid,
            workerRead: false);
        SetTestParentRules(
            environment.Store.Layout.ReadyRoot,
            gatewaySid,
            workerSid,
            workerRead: true);
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        _ = environment.Submit(
            environment.CreateSubmission(request));
        GatewayApprovalResult approved = environment.Approve(
            request.RequestId,
            environment.CreateApproval(
                request,
                ApprovalDecision.Approve));
        Assert.True(approved.IsSuccess);

        string ready = environment.Store.Layout
            .GetReadyRequestDirectory(request.RequestId);
        AssertWorkerRuleAbsent(ready, workerSid);
        foreach (string path in Directory.EnumerateFileSystemEntries(
                     ready,
                     "*",
                     SearchOption.AllDirectories))
        {
            AssertWorkerRuleAbsent(path, workerSid);
        }

        GatewayReadyRecordAccessController controller = new(
            environment.Store.Layout,
            new SigningProfileRegistry(
                [GatewayTestProfile.Instance]),
            gatewaySid,
            workerSid);

        Assert.True(controller.PrepareForWorker(approved.Request!));
        Assert.True(controller.PrepareForWorker(approved.Request!));

        string bundle = Path.Combine(
            ready,
            GatewaySubmissionProcessor.BundleDirectoryName);
        AssertExactWorkerReadDirectory(
            ready,
            gatewaySid,
            workerSid);
        AssertExactWorkerReadDirectory(
            bundle,
            gatewaySid,
            workerSid);
        foreach (string file in Directory.EnumerateFiles(
                     ready,
                     "*",
                     SearchOption.AllDirectories))
        {
            FileSecurity security = new FileInfo(file)
                .GetAccessControl(
                    AccessControlSections.Access
                        | AccessControlSections.Owner);
            AssertExactWorkerReadRules(
                security,
                gatewaySid,
                workerSid,
                directory: false);
        }
    }

    [Fact]
    public void RejectionIsTerminalAndNeverPublishesReady()
    {
        using HandoffEnvironment environment = new();
        ArtifactSigningRequestV1 request =
            environment.CreateRequest();
        _ = environment.Submit(
            environment.CreateSubmission(request));
        byte[] approval = environment.CreateApproval(
            request,
            ApprovalDecision.Reject);

        GatewayApprovalResult result =
            environment.Approve(request.RequestId, approval);

        Assert.True(result.IsSuccess);
        Assert.False(result.WorkerNotificationRequired);
        Assert.Equal(RequestState.Rejected, result.Request?.State);
        Assert.False(Directory.Exists(
            environment.Store.Layout.GetReadyRequestDirectory(
                request.RequestId)));
        Assert.False(Directory.Exists(
            environment.Store.Layout.GetPendingRequestDirectory(
                request.RequestId)));
    }

    private sealed class HandoffEnvironment : IDisposable
    {
        private readonly GatewayStateTestEnvironment
            _stateEnvironment = new();
        private readonly GatewayCmsTestCertificateAuthority
            _authority;
        private readonly X509Certificate2 _publicRoot;
        private int _nonceCounter;

        internal HandoffEnvironment()
        {
            Store = _stateEnvironment.CreateStore();
            _authority =
                GatewayCmsTestCertificateAuthority.Create(
                    Now.AddDays(-1),
                    Now.AddDays(1));
            Submitter = GatewayCmsTestIdentity.CreateIssued(
                _authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
            Approver = GatewayCmsTestIdentity.CreateIssued(
                _authority,
                Now.AddHours(-1),
                Now.AddHours(1),
                RequiredEkuOid);
            _publicRoot =
                _authority.ExportPublicCertificate();
            SubmitterPolicy = new GatewaySubmitterPolicy(
                GatewayTestProfile.ProjectId,
                GatewayTestProfile.ProfileId,
                GatewayTestProfile.ProfileVersion,
                CreateTrustPolicy(Submitter));
            ApproverPolicy = new GatewayApproverPolicy(
                GatewayTestProfile.ProjectId,
                GatewayTestProfile.ProfileId,
                GatewayTestProfile.ProfileVersion,
                CreateTrustPolicy(Approver),
                requireDistinctSubmitterAndApprover: true);
        }

        internal GatewayStateStore Store { get; }

        internal GatewayCmsTestIdentity Submitter { get; }

        internal GatewayCmsTestIdentity Approver { get; }

        internal GatewaySubmitterPolicy SubmitterPolicy { get; }

        internal GatewayApproverPolicy ApproverPolicy { get; }

        internal TestReadyRecordAccessController
            ReadyRecordAccess
        { get; } = new();

        internal ArtifactSigningRequestV1 CreateRequest()
        {
            byte[] manifest = GatewayTestProfile.Manifest;
            return new ArtifactSigningRequestV1(
                Guid.NewGuid(),
                GatewayTestProfile.ProjectId,
                GatewayTestProfile.ProfileId,
                GatewayTestProfile.ProfileVersion,
                GatewayTestProfile.SourceRepository,
                "0123456789abcdef0123456789abcdef01234567",
                "1.2.3",
                Now.AddMinutes(-1),
                Now.AddMinutes(5),
                CanonicalNonce(
                    checked((byte)++_nonceCounter)),
                GatewayTestProfile.SignerPolicyId,
                GatewayTestProfile.TimestampPolicyId,
                [
                    new RequestArtifactV1(
                        GatewayTestProfile.ManifestRole,
                        GatewayTestProfile.ManifestFileName,
                        manifest.Length,
                        Sha256(manifest)),
                ]);
        }

        internal byte[] CreateSubmission(
            ArtifactSigningRequestV1 request,
            byte[]? manifestOverride = null,
            bool unexpectedEntry = false)
        {
            byte[] requestJson = SerializeRequest(request);
            Dictionary<string, byte[]> entries =
                new(StringComparer.Ordinal)
                {
                    [GatewaySubmissionProcessor
                        .RequestJsonFileName] = requestJson,
                    [GatewaySubmissionProcessor
                        .RequestSignatureFileName] =
                        Submitter.Sign(
                            requestJson,
                            detached: true),
                    [$"{GatewaySubmissionProcessor.BundleDirectoryName}/{GatewayTestProfile.ManifestFileName}"] =
                        manifestOverride
                        ?? GatewayTestProfile.Manifest,
                };
            if (unexpectedEntry)
            {
                entries.Add("unexpected.txt", [0x01]);
            }

            return CreateTar(entries);
        }

        internal GatewaySubmissionResult Submit(
            byte[] archive,
            string? authenticatedSpki = null)
        {
            GatewaySubmissionProcessor processor = new(
                Store,
                new SigningProfileRegistry(
                    [GatewayTestProfile.Instance]),
                new FixedTimeProvider(Now));
            using MemoryStream stream = new(archive);
            return processor.Process(
                stream,
                SubmitterPolicy,
                authenticatedSpki
                    ?? Submitter.SubjectPublicKeyInfoSha256);
        }

        internal byte[] CreateApproval(
            ArtifactSigningRequestV1 request,
            ApprovalDecision decision)
        {
            string digest = Store.GetRequest(request.RequestId)!
                .RequestDigest;
            byte[] approvalJson = SerializeApproval(
                request.RequestId,
                digest,
                decision);
            return Approver.Sign(
                approvalJson,
                detached: false);
        }

        internal GatewayApprovalResult Approve(
            Guid requestId,
            byte[] signature,
            IGatewayReadyRecordAccessController?
                readyRecordAccess = null)
        {
            GatewayApprovalProcessor processor = new(
                Store,
                readyRecordAccess ?? ReadyRecordAccess,
                new FixedTimeProvider(Now));
            return processor.Process(
                requestId,
                signature,
                ApproverPolicy,
                Approver.SubjectPublicKeyInfoSha256);
        }

        public void Dispose()
        {
            _publicRoot.Dispose();
            Approver.Dispose();
            Submitter.Dispose();
            _authority.Dispose();
            _stateEnvironment.Dispose();
        }

        private CmsTrustPolicy CreateTrustPolicy(
            GatewayCmsTestIdentity identity)
        {
            return new CmsTrustPolicy(
                identity.SubjectPublicKeyInfoSha256,
                RequiredEkuOid,
                [_publicRoot],
                CmsRevocationPolicy.DisposableTestNoCheck,
                TimeSpan.FromSeconds(1));
        }
    }

    private static void AssertExactWorkerReadDirectory(
        string path,
        SecurityIdentifier gatewaySid,
        SecurityIdentifier workerSid)
    {
        DirectorySecurity security = new DirectoryInfo(path)
            .GetAccessControl(
                AccessControlSections.Access
                    | AccessControlSections.Owner);
        AssertExactWorkerReadRules(
            security,
            gatewaySid,
            workerSid,
            directory: true);
    }

    private static void AssertExactWorkerReadRules(
        FileSystemSecurity security,
        SecurityIdentifier gatewaySid,
        SecurityIdentifier workerSid,
        bool directory)
    {
        FileSystemAccessRule[] rules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        FileSystemAccessRule normalized = directory
            ? new FileSystemAccessRule(
                workerSid,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow)
            : new FileSystemAccessRule(
                workerSid,
                FileSystemRights.ReadAndExecute,
                AccessControlType.Allow);
        Assert.True(security.AreAccessRulesProtected);
        SecurityIdentifier owner = Assert.IsType<SecurityIdentifier>(
            security.GetOwner(typeof(SecurityIdentifier)));
        Assert.Contains(
            owner,
            new SecurityIdentifier[]
            {
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null),
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null),
                gatewaySid,
            });
        Assert.Equal(4, rules.Length);
        Assert.All(rules, rule => Assert.False(rule.IsInherited));
        Assert.Single(rules, rule =>
            rule.IdentityReference == workerSid
            && rule.FileSystemRights
                == normalized.FileSystemRights
            && rule.InheritanceFlags
                == normalized.InheritanceFlags
            && rule.PropagationFlags
                == normalized.PropagationFlags
            && rule.AccessControlType
                is AccessControlType.Allow);
    }

    private static void AssertWorkerRuleAbsent(
        string path,
        SecurityIdentifier workerSid)
    {
        FileSystemSecurity security = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl(
                AccessControlSections.Access)
            : new FileInfo(path).GetAccessControl(
                AccessControlSections.Access);
        FileSystemAccessRule[] rules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        Assert.DoesNotContain(
            rules,
            rule => rule.IdentityReference == workerSid);
    }

    private static void SetTestParentRules(
        string path,
        SecurityIdentifier gatewaySid,
        SecurityIdentifier workerSid,
        bool workerRead)
    {
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        foreach (SecurityIdentifier sid in new[]
                 {
                     new SecurityIdentifier(
                         WellKnownSidType.LocalSystemSid,
                         null),
                     new SecurityIdentifier(
                         WellKnownSidType.BuiltinAdministratorsSid,
                         null),
                     gatewaySid,
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        if (workerRead)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                workerSid,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static byte[] CreateTar(
        IReadOnlyDictionary<string, byte[]> entries)
    {
        using MemoryStream archive = new();
        using (TarWriter writer = new(
                   archive,
                   TarEntryFormat.Ustar,
                   leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                UstarTarEntry entry = new(
                    TarEntryType.RegularFile,
                    name)
                {
                    DataStream = new MemoryStream(content),
                };
                writer.WriteEntry(entry);
            }
        }

        return archive.ToArray();
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
            writer.WriteString(
                "RequestId",
                request.RequestId.ToString("D"));
            writer.WriteString("ProjectId", request.ProjectId);
            writer.WriteString("ProfileId", request.ProfileId);
            writer.WriteNumber(
                "ProfileVersion",
                request.ProfileVersion);
            writer.WriteString(
                "SourceRepository",
                request.SourceRepository);
            writer.WriteString(
                "SourceCommit",
                request.SourceCommit);
            writer.WriteString(
                "ReleaseVersion",
                request.ReleaseVersion);
            writer.WriteString(
                "RequestedAt",
                FormatTime(request.RequestedAt));
            writer.WriteString(
                "ExpiresAt",
                FormatTime(request.ExpiresAt));
            writer.WriteString("Nonce", request.Nonce);
            writer.WriteString(
                "SignerPolicyId",
                request.SignerPolicyId);
            writer.WriteString(
                "TimestampPolicyId",
                request.TimestampPolicyId);
            writer.WriteStartArray("Artifacts");
            foreach (RequestArtifactV1 artifact
                     in request.Artifacts)
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
            writer.WriteString(
                "RequestId",
                requestId.ToString("D"));
            writer.WriteString(
                "RequestDigest",
                requestDigest);
            writer.WriteString(
                "Decision",
                decision.ToString());
            writer.WriteString(
                "Reason",
                "Disposable test decision");
            writer.WriteString(
                "ApprovedAt",
                FormatTime(Now.AddSeconds(-1)));
            writer.WriteString(
                "ExpiresAt",
                FormatTime(Now.AddMinutes(4)));
            writer.WriteString(
                "Nonce",
                CanonicalNonce(0x7f));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static string CanonicalNonce(byte value)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(value, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string FormatTime(DateTimeOffset timestamp)
    {
        return timestamp.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }

    private static string Sha256(ReadOnlySpan<byte> content)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(content));
    }

    private sealed class FixedTimeProvider(
        DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }

    private sealed class GatewayTestProfile : ISigningProfile
    {
        internal const string ProjectId = "gateway-test";
        internal const string ProfileId = "GatewayTestBundleV1";
        internal const int ProfileVersion = 1;
        internal const string SourceRepository =
            "test/gateway";
        internal const string SignerPolicyId =
            "GatewayTestSignerV1";
        internal const string TimestampPolicyId =
            "GatewayTestTimestampV1";
        internal const string ManifestRole = "Manifest";
        internal const string ManifestFileName =
            "release-manifest.json";

        internal static readonly byte[] Manifest =
            Encoding.UTF8.GetBytes("{\"State\":\"Unsigned\"}\n");

        private static readonly SigningProfileDescriptor
            CompiledDescriptor = new(
                new SigningProfileIdentity(
                    ProfileId,
                    ProfileVersion),
                [ProjectId],
                [SourceRepository],
                [
                    new SigningProfileArtifactDefinition(
                        ManifestRole,
                        ManifestFileName,
                        SigningProfileArtifactKind.JsonManifest,
                        1024),
                ],
                [SignerPolicyId],
                [TimestampPolicyId],
                4096);

        internal static GatewayTestProfile Instance { get; } =
            new();

        public SigningProfileDescriptor Descriptor =>
            CompiledDescriptor;

        public SigningProfileValidationResult
            ValidateUnsignedBundle(
                SigningProfileValidationContext context)
        {
            SigningProfileValidationError requestError =
                SigningProfileRequestValidator.Validate(
                    Descriptor,
                    context.Request);
            if (requestError is not
                SigningProfileValidationError.None)
            {
                return SigningProfileValidationResult.Failure(
                    requestError);
            }

            using Stream input =
                context.ArtifactReader.OpenRead(
                    ManifestFileName);
            using MemoryStream content = new();
            input.CopyTo(content);
            return content.ToArray().AsSpan()
                    .SequenceEqual(Manifest)
                ? SigningProfileValidationResult.Success
                : SigningProfileValidationResult.Failure(
                    SigningProfileValidationError
                        .ArtifactHashMismatch);
        }

        public SigningProfileFinalizationResult
            FinalizeSignedBundle(
                SigningProfileFinalizationContext context)
        {
            return SigningProfileFinalizationResult.Failure(
                SigningProfileValidationError
                    .FinalizedManifestInvalid);
        }

        public SigningProfileValidationResult
            ValidateFinalizedBundle(
                SigningProfileFinalizedValidationContext context)
        {
            return SigningProfileValidationResult.Failure(
                SigningProfileValidationError
                    .FinalizedManifestInvalid);
        }
    }
}

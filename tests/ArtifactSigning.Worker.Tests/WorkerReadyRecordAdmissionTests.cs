using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerReadyRecordAdmissionTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 16, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CopiesAndRevalidatesBeforeDurableAdmission()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        CreateReadyRecord(store.Layout, requestId);
        RecordingRevalidator revalidator = new(
            WorkerRevalidationResult.Success);
        WorkerReadyRecordAdmission admission = CreateAdmission(
            store,
            revalidator);

        WorkerAdmissionResult result = await admission.AdmitAsync(
            requestId,
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(RequestState.Approved, result.Job?.State);
        Assert.Equal(1, revalidator.CallCount);
        Assert.Equal(
            WorkerResultCode.ApprovedValidated,
            store.GetJob(requestId)?.ResultCode);
        Assert.True(Directory.Exists(
            store.Layout.GetReadyInboxDirectory(requestId)));
        Assert.Equal(
            new[]
            {
                WorkerReadyRecordOperation
                    .ApprovalSignatureFileName,
                WorkerReadyRecordOperation.BundleDirectoryName,
                WorkerReadyRecordOperation.RequestJsonFileName,
                WorkerReadyRecordOperation
                    .RequestSignatureFileName,
            },
            Directory.EnumerateFileSystemEntries(
                    store.Layout.GetWorkDirectory(requestId))
                .Select(Path.GetFileName)
                .Order(StringComparer.Ordinal));
        store.VerifyIntegrity();
    }

    [Fact]
    public async Task UnexpectedReadyEntryFailsBeforeStateAdmission()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string ready =
            CreateReadyRecord(store.Layout, requestId);
        await File.WriteAllTextAsync(
            Path.Combine(ready, "unexpected.txt"),
            "denied",
            TestContext.Current.CancellationToken);
        RecordingRevalidator revalidator = new(
            WorkerRevalidationResult.Success);

        WorkerAdmissionResult result =
            await CreateAdmission(store, revalidator).AdmitAsync(
                requestId,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerAdmissionError.ReadyRecordMissing,
            result.Error);
        Assert.Null(store.GetJob(requestId));
        Assert.Equal(0, revalidator.CallCount);
    }

    [Fact]
    public async Task FailedIndependentValidationNeverAdmitsJob()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        _ = CreateReadyRecord(store.Layout, requestId);
        RecordingRevalidator revalidator = new(
            new WorkerRevalidationResult(
                WorkerRevalidationError.AuthorizationInvalid));

        WorkerAdmissionResult result =
            await CreateAdmission(store, revalidator).AdmitAsync(
                requestId,
                TestContext.Current.CancellationToken);

        Assert.Equal(
            WorkerAdmissionError.AuthorizationInvalid,
            result.Error);
        Assert.Null(store.GetJob(requestId));
        Assert.False(Directory.Exists(
            store.Layout.GetWorkDirectory(requestId)));
    }

    [Fact]
    public async Task RevalidatesOrphanedWorkBeforeCrashRecoveryAdmission()
    {
        using WorkerStateTestEnvironment environment = new();
        WorkerStateStore store = environment.CreateStore();
        Guid requestId = Guid.NewGuid();
        string ready =
            CreateReadyRecord(store.Layout, requestId);
        CopyDirectory(
            ready,
            store.Layout.GetWorkDirectory(requestId));
        RecordingRevalidator revalidator = new(
            WorkerRevalidationResult.Success);

        WorkerAdmissionResult result =
            await CreateAdmission(store, revalidator).AdmitAsync(
                requestId,
                TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, revalidator.CallCount);
        Assert.Equal(
            RequestState.Approved,
            store.GetJob(requestId)?.State);
    }

    private static WorkerReadyRecordAdmission CreateAdmission(
        WorkerStateStore store,
        IWorkerJobRevalidator revalidator)
    {
        return new WorkerReadyRecordAdmission(
            store,
            new SigningProfileRegistry(
                [AdmissionTestProfile.Instance]),
            revalidator,
            new FixedTimeProvider(Now));
    }

    private static string CreateReadyRecord(
        WorkerDirectoryLayout layout,
        Guid requestId)
    {
        Directory.CreateDirectory(layout.InboxRoot);
        Directory.CreateDirectory(layout.ReadyInboxRoot);
        string ready =
            layout.GetReadyInboxDirectory(requestId);
        Directory.CreateDirectory(ready);
        string bundle = Path.Combine(
            ready,
            WorkerReadyRecordOperation.BundleDirectoryName);
        Directory.CreateDirectory(bundle);
        byte[] manifest =
            Encoding.UTF8.GetBytes("{\"State\":\"Unsigned\"}\n");
        File.WriteAllBytes(
            Path.Combine(bundle, AdmissionTestProfile.ManifestFileName),
            manifest);
        ArtifactSigningRequestV1 request = new(
            requestId,
            AdmissionTestProfile.ProjectId,
            AdmissionTestProfile.ProfileId,
            AdmissionTestProfile.ProfileVersion,
            AdmissionTestProfile.SourceRepository,
            "0123456789abcdef0123456789abcdef01234567",
            "1.0.0",
            Now.AddMinutes(-1),
            Now.AddMinutes(5),
            CanonicalNonce(),
            AdmissionTestProfile.SignerPolicyId,
            AdmissionTestProfile.TimestampPolicyId,
            [
                new RequestArtifactV1(
                    "Manifest",
                    AdmissionTestProfile.ManifestFileName,
                    manifest.Length,
                    Sha256(manifest)),
            ]);
        File.WriteAllBytes(
            Path.Combine(
                ready,
                WorkerReadyRecordOperation.RequestJsonFileName),
            SerializeRequest(request));
        File.WriteAllBytes(
            Path.Combine(
                ready,
                WorkerReadyRecordOperation
                    .RequestSignatureFileName),
            [0x01]);
        File.WriteAllBytes(
            Path.Combine(
                ready,
                WorkerReadyRecordOperation
                    .ApprovalSignatureFileName),
            [0x02]);
        return ready;
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

    private static void CopyDirectory(
        string source,
        string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string directory in Directory
                     .EnumerateDirectories(
                         source,
                         "*",
                         SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(
                directory.Replace(
                    source,
                    destination,
                    StringComparison.Ordinal));
        }

        foreach (string file in Directory.EnumerateFiles(
                     source,
                     "*",
                     SearchOption.AllDirectories))
        {
            File.Copy(
                file,
                file.Replace(
                    source,
                    destination,
                    StringComparison.Ordinal));
        }
    }

    private static string CanonicalNonce()
    {
        return Convert.ToBase64String(new byte[32])
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string Sha256(ReadOnlySpan<byte> content)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(content));
    }

    private static string FormatTime(DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class RecordingRevalidator(
        WorkerRevalidationResult result)
        : IWorkerJobRevalidator
    {
        internal int CallCount { get; private set; }

        public ValueTask<WorkerRevalidationResult>
            RevalidateAsync(
                WorkerJobRecord job,
                string trustedWorkDirectory,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(result);
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

    private sealed class AdmissionTestProfile : ISigningProfile
    {
        internal const string ProjectId = "test-project";
        internal const string ProfileId = "TestBundleV1";
        internal const int ProfileVersion = 1;
        internal const string SourceRepository = "test/repository";
        internal const string SignerPolicyId = "TestSignerV1";
        internal const string TimestampPolicyId =
            "TestTimestampV1";
        internal const string ManifestFileName = "manifest.json";

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
                        ManifestFileName,
                        SigningProfileArtifactKind.JsonManifest,
                        1024),
                ],
                [SignerPolicyId],
                [TimestampPolicyId],
                4096);

        internal static AdmissionTestProfile Instance { get; } =
            new();

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

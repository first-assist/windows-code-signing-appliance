using System.Formats.Tar;
using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public enum GatewayWorkerObservationOutcome
{
    NoChange,
    Completed,
    Quarantined,
    Conflict,
}

public sealed record GatewayWorkerObservationResult(
    GatewayWorkerObservationOutcome Outcome,
    GatewayRequestRecord? Request);

public sealed class GatewayPreparedResultArchive : IDisposable
{
    internal GatewayPreparedResultArchive(
        string directory,
        string archivePath)
    {
        DirectoryPath = directory;
        ArchivePath = archivePath;
    }

    public string DirectoryPath { get; }

    public string ArchivePath { get; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(DirectoryPath)
                && !File.GetAttributes(DirectoryPath)
                    .HasFlag(FileAttributes.ReparsePoint))
            {
                Directory.Delete(
                    DirectoryPath,
                    recursive: true);
            }
        }
        catch (IOException)
        {
            // Startup reconciliation removes bounded response staging.
        }
        catch (UnauthorizedAccessException)
        {
            // Startup reconciliation removes bounded response staging.
        }
    }
}

public sealed class GatewayResultProcessor
{
    private readonly GatewayStateStore _stateStore;
    private readonly SigningProfileRegistry _profiles;
    private readonly CmsTrustPolicy _receiptTrust;
    private readonly TimeProvider _timeProvider;

    public GatewayResultProcessor(
        GatewayStateStore stateStore,
        SigningProfileRegistry profiles,
        CmsTrustPolicy receiptTrust,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(receiptTrust);
        _stateStore = stateStore;
        _profiles = profiles;
        _receiptTrust = receiptTrust;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public GatewayWorkerObservationResult Observe(
        GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.State is not RequestState.Signing)
        {
            return new GatewayWorkerObservationResult(
                GatewayWorkerObservationOutcome.NoChange,
                request);
        }

        string statusPath = Path.Combine(
            _stateStore.Layout.WorkerStatusRoot,
            $"{request.RequestId:N}.json");
        if (!File.Exists(statusPath))
        {
            return new GatewayWorkerObservationResult(
                GatewayWorkerObservationOutcome.NoChange,
                request);
        }

        try
        {
            byte[] statusJson = ReadBounded(
                statusPath,
                WorkerTerminalStatusJson
                    .MaximumStatusJsonBytes);
            WorkerTerminalStatusJsonParseResult parsed =
                WorkerTerminalStatusJson.Parse(statusJson);
            if (!parsed.IsSuccess
                || parsed.Status is null
                || parsed.Status.RequestId != request.RequestId
                || !FixedDigestEquals(
                    parsed.Status.RequestDigest,
                    request.RequestDigest)
                || parsed.Status.UpdatedAt
                    < request.UpdatedAt
                || parsed.Status.UpdatedAt > WholeSecondNow())
            {
                return Quarantine(request);
            }

            WorkerTerminalStatusV1 status = parsed.Status;
            if (status.State is not RequestState.Signed)
            {
                return Quarantine(request);
            }

            if (!string.Equals(
                    status.ResultCode,
                    "SigningCompleted",
                    StringComparison.Ordinal)
                || status.EvidenceDigest is null
                || !ValidateSignedOutput(
                    request,
                    status.EvidenceDigest,
                    out _,
                    request.UpdatedAt))
            {
                return Quarantine(request);
            }

            GatewayMutationResult transition =
                _stateStore.TryRecordWorkerTerminal(
                    request.RequestId,
                    request.RequestDigest,
                    request.RowVersion,
                    RequestState.Signed,
                    status.EvidenceDigest,
                    WholeSecondNow());
            if ((transition.Outcome is
                    GatewayMutationOutcome.Applied
                    or GatewayMutationOutcome.AlreadyApplied)
                && transition.Request is not null)
            {
                TryDeleteReady(request.RequestId);
                return new GatewayWorkerObservationResult(
                    GatewayWorkerObservationOutcome.Completed,
                    transition.Request);
            }

            return new GatewayWorkerObservationResult(
                GatewayWorkerObservationOutcome.Conflict,
                transition.Request);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Quarantine(request);
        }
    }

    public GatewayPreparedResultArchive PrepareResultArchive(
        GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.State is not RequestState.Signed
            || !ValidateSignedOutput(
                request,
                expectedEvidenceDigest: null,
                out IReadOnlyList<ValidatedResultFile> files))
        {
            throw new InvalidDataException(
                "Signed result validation failed.");
        }

        string directory =
            _stateStore.Layout.CreateReceivingDirectoryPath();
        Directory.CreateDirectory(directory);
        string archivePath = Path.Combine(
            directory,
            "result.tar");
        try
        {
            using FileStream archive = new(
                archivePath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 64 * 1024,
                    Options = FileOptions.WriteThrough,
                });
            using TarWriter writer = new(
                archive,
                TarEntryFormat.Ustar,
                leaveOpen: true);
            foreach (ValidatedResultFile file in files)
            {
                byte[] content = ReadBounded(
                    file.Path,
                    file.MaximumBytes);
                if (!FixedDigestEquals(
                        Convert.ToHexStringLower(
                            SHA256.HashData(content)),
                        file.Sha256))
                {
                    throw new InvalidDataException(
                        "Signed result changed during publication.");
                }

                UstarTarEntry entry = new(
                    TarEntryType.RegularFile,
                    file.ArchiveName)
                {
                    DataStream = new MemoryStream(
                        content,
                        writable: false),
                    Gid = 0,
                    Uid = 0,
                    GroupName = string.Empty,
                    UserName = string.Empty,
                    Mode =
                        UnixFileMode.UserRead
                        | UnixFileMode.UserWrite,
                    ModificationTime =
                        DateTimeOffset.UnixEpoch,
                };
                writer.WriteEntry(entry);
            }

            archive.Flush(flushToDisk: true);
            return new GatewayPreparedResultArchive(
                directory,
                archivePath);
        }
        catch
        {
            new GatewayPreparedResultArchive(
                directory,
                archivePath).Dispose();
            throw;
        }
    }

    private bool ValidateSignedOutput(
        GatewayRequestRecord request,
        string? expectedEvidenceDigest,
        out IReadOnlyList<ValidatedResultFile> files,
        DateTimeOffset? minimumCompletedAt = null)
    {
        files = Array.Empty<ValidatedResultFile>();
        ISigningProfile? profile = _profiles.Resolve(
            request.ProfileId,
            request.ProfileVersion);
        if (profile is null)
        {
            return false;
        }

        string output = Path.Combine(
            _stateStore.Layout.OutputRoot,
            request.RequestId.ToString("N"));
        string bundle = Path.Combine(
            output,
            WorkerReadyRecordOperationNames.BundleDirectoryName);
        SigningProfileArtifactDefinition[] resultDefinitions =
            profile.Descriptor.Artifacts
                .Where(item => item.Kind is not
                    SigningProfileArtifactKind.JsonBuildEvidence)
                .ToArray();
        if (!HasExactEntries(
                output,
                [
                    WorkerReadyRecordOperationNames
                        .ReceiptJsonFileName,
                    WorkerReadyRecordOperationNames
                        .ReceiptSignatureFileName,
                    WorkerReadyRecordOperationNames
                        .BundleDirectoryName,
                ])
            || !HasExactEntries(
                bundle,
                resultDefinitions.Select(item =>
                    item.FileName)))
        {
            return false;
        }

        string receiptJsonPath = Path.Combine(
            output,
            WorkerReadyRecordOperationNames.ReceiptJsonFileName);
        string receiptSignaturePath = Path.Combine(
            output,
            WorkerReadyRecordOperationNames
                .ReceiptSignatureFileName);
        byte[] receiptJson = ReadBounded(
            receiptJsonPath,
            ArtifactSigningReceiptJsonSerializer
                .MaximumReceiptJsonBytes);
        string receiptDigest =
            SigningReceiptDigest.ComputeHex(receiptJson);
        if (expectedEvidenceDigest is not null
            && !FixedDigestEquals(
                receiptDigest,
                expectedEvidenceDigest))
        {
            return false;
        }

        byte[] receiptSignature = ReadBounded(
            receiptSignaturePath,
            DetachedCmsSignatureVerifier.MaximumSignatureBytes);
        TrustedDetachedCmsVerificationResult verification =
            TrustedDetachedCmsSignatureVerifier.Verify(
                receiptJson,
                receiptSignature,
                _receiptTrust,
                WholeSecondNow());
        if (!verification.IsSuccess)
        {
            return false;
        }

        ReceiptJsonParseResult receiptParse =
            ArtifactSigningReceiptJsonParser.Parse(
                receiptJson);
        if (!receiptParse.IsSuccess
            || receiptParse.Receipt is null)
        {
            return false;
        }

        List<ValidatedResultFile> resultFiles =
            resultDefinitions.Select(definition =>
                ValidateFile(
                    $"{WorkerReadyRecordOperationNames.BundleDirectoryName}/{definition.FileName}",
                    Path.Combine(bundle, definition.FileName),
                    checked((int)Math.Min(
                        int.MaxValue,
                        definition.MaximumBytes))))
                .ToList();
        if (!ReceiptMatchesRequestAndOutput(
                request,
                receiptParse.Receipt,
                verification.Signer!,
                resultDefinitions,
                resultFiles,
                minimumCompletedAt))
        {
            return false;
        }

        List<ValidatedResultFile> validated =
        [
            ValidateFile(
                WorkerReadyRecordOperationNames.ReceiptJsonFileName,
                receiptJsonPath,
                ArtifactSigningReceiptJsonSerializer
                    .MaximumReceiptJsonBytes),
            ValidateFile(
                WorkerReadyRecordOperationNames
                    .ReceiptSignatureFileName,
                receiptSignaturePath,
                DetachedCmsSignatureVerifier
                    .MaximumSignatureBytes),
        ];
        validated.AddRange(resultFiles);
        files = validated.AsReadOnly();
        return true;
    }

    private bool ReceiptMatchesRequestAndOutput(
        GatewayRequestRecord request,
        ArtifactSigningReceiptV1 receipt,
        CmsSignerIdentity receiptSigner,
        IReadOnlyList<SigningProfileArtifactDefinition>
            resultDefinitions,
        IReadOnlyList<ValidatedResultFile> resultFiles,
        DateTimeOffset? minimumCompletedAt)
    {
        GatewayApprovalRecord? approval =
            _stateStore.GetApproval(request.RequestId);
        if (approval is null
            || approval.Decision is not ApprovalDecision.Approve
            || receipt.RequestId != request.RequestId
            || !FixedDigestEquals(
                receipt.RequestDigest,
                request.RequestDigest)
            || !string.Equals(
                receipt.ProjectId,
                request.ProjectId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ProfileId,
                request.ProfileId,
                StringComparison.Ordinal)
            || receipt.ProfileVersion != request.ProfileVersion
            || !string.Equals(
                receipt.SourceRepository,
                request.SourceRepository,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.SourceCommit,
                request.SourceCommit,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ReleaseVersion,
                request.ReleaseVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.SignerPolicyId,
                request.SignerPolicyId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.TimestampPolicyId,
                request.TimestampPolicyId,
                StringComparison.Ordinal)
            || !FixedDigestEquals(
                receipt.SubmitterSpkiSha256,
                request.SubmitterSpkiSha256)
            || !FixedDigestEquals(
                receipt.ApproverSpkiSha256,
                approval.ApproverSpkiSha256)
            || !FixedDigestEquals(
                receipt.ReceiptSignerSpkiSha256,
                receiptSigner.SubjectPublicKeyInfoSha256)
            || receipt.CompletedAt
                < (minimumCompletedAt ?? request.RequestedAt)
            || receipt.CompletedAt > WholeSecondNow())
        {
            return false;
        }

        IReadOnlyList<RequestArtifactV1> unsigned =
            _stateStore.GetRequestArtifacts(
                request.RequestId);
        if (!ReceiptArtifactsMatch(
                receipt.UnsignedArtifacts,
                unsigned.Select(item =>
                    new ExpectedReceiptArtifact(
                        item.Role,
                        item.File,
                        item.Size,
                        item.Sha256))))
        {
            return false;
        }

        Dictionary<string, ValidatedResultFile>
            resultFilesByName = resultFiles.ToDictionary(
                item => Path.GetFileName(item.ArchiveName),
                StringComparer.Ordinal);
        if (!ReceiptArtifactsMatch(
                receipt.ResultArtifacts,
                resultDefinitions.Select(definition =>
                {
                    ValidatedResultFile file =
                        resultFilesByName[
                            definition.FileName];
                    return new ExpectedReceiptArtifact(
                        definition.Role,
                        definition.FileName,
                        file.Size,
                        file.Sha256);
                })))
        {
            return false;
        }

        HashSet<(string Role, string File)>
            expectedAuthenticode = resultDefinitions
                .Where(item => item.Kind is
                    SigningProfileArtifactKind
                        .PortableExecutable)
                .Select(item => (
                    item.Role,
                    File: item.FileName))
                .ToHashSet();
        HashSet<(string Role, string File)>
            actualAuthenticode = receipt
                .AuthenticodeArtifacts
                .Select(item => (
                    item.Role,
                    item.File))
                .ToHashSet();
        return expectedAuthenticode.SetEquals(
            actualAuthenticode);
    }

    private static bool ReceiptArtifactsMatch(
        IReadOnlyCollection<ReceiptArtifactV1> actual,
        IEnumerable<ExpectedReceiptArtifact> expected)
    {
        ExpectedReceiptArtifact[] expectedArray =
            expected.ToArray();
        Dictionary<(string Role, string File),
            ReceiptArtifactV1> actualByIdentity =
                actual.ToDictionary(
                    item => (item.Role, item.File));
        return actualByIdentity.Count == expectedArray.Length
            && expectedArray.All(item =>
                actualByIdentity.TryGetValue(
                    (item.Role, item.File),
                    out ReceiptArtifactV1? observed)
                && observed.Size == item.Size
                && FixedDigestEquals(
                    observed.Sha256,
                    item.Sha256));
    }

    private static ValidatedResultFile ValidateFile(
        string archiveName,
        string path,
        int maximumBytes)
    {
        using FileStream input =
            GatewayDirectFile.OpenRead(path);
        if (input.Length is <= 0
            || input.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Signed result file exceeds its bound.");
        }

        string digest = Convert.ToHexStringLower(
            SHA256.HashData(input));
        return new ValidatedResultFile(
            archiveName,
            path,
            maximumBytes,
            input.Length,
            digest);
    }

    private GatewayWorkerObservationResult Quarantine(
        GatewayRequestRecord request)
    {
        GatewayMutationResult transition =
            _stateStore.TryRecordWorkerTerminal(
                request.RequestId,
                request.RequestDigest,
                request.RowVersion,
                RequestState.Quarantined,
                evidenceDigest: null,
                WholeSecondNow());
        TryDeleteReady(request.RequestId);
        return new GatewayWorkerObservationResult(
            transition.Outcome is GatewayMutationOutcome.Applied
                or GatewayMutationOutcome.AlreadyApplied
                ? GatewayWorkerObservationOutcome.Quarantined
                : GatewayWorkerObservationOutcome.Conflict,
            transition.Request);
    }

    private void TryDeleteReady(Guid requestId)
    {
        try
        {
            string ready = _stateStore.Layout
                .GetReadyRequestDirectory(requestId);
            if (Directory.Exists(ready)
                && !File.GetAttributes(ready).HasFlag(
                    FileAttributes.ReparsePoint))
            {
                Directory.Delete(ready, recursive: true);
            }
        }
        catch (IOException)
        {
            // Terminal state is authoritative; restart retries cleanup.
        }
        catch (UnauthorizedAccessException)
        {
            // Terminal state is authoritative; restart retries cleanup.
        }
    }

    private static byte[] ReadBounded(
        string path,
        int maximumBytes)
    {
        using FileStream input =
            GatewayDirectFile.OpenRead(path);
        if (input.Length is <= 0
            || input.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Gateway result input exceeds its bound.");
        }

        byte[] content =
            new byte[checked((int)input.Length)];
        input.ReadExactly(content);
        return content;
    }

    private static bool HasExactEntries(
        string directory,
        IEnumerable<string> expectedEntries)
    {
        try
        {
            FileAttributes attributes =
                File.GetAttributes(directory);
            if (!attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(
                    FileAttributes.ReparsePoint))
            {
                return false;
            }

            HashSet<string> expected =
                expectedEntries.ToHashSet(
                    StringComparer.Ordinal);
            string?[] actual = Directory
                .EnumerateFileSystemEntries(directory)
                .Select(Path.GetFileName)
                .ToArray();
            return actual.Length == expected.Count
                && actual.All(item =>
                    item is not null
                    && expected.Contains(item));
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool FixedDigestEquals(
        string left,
        string right)
    {
        return left.Length is 64
            && right.Length is 64
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
    }

    private DateTimeOffset WholeSecondNow()
    {
        DateTimeOffset now =
            _timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private sealed record ValidatedResultFile(
        string ArchiveName,
        string Path,
        int MaximumBytes,
        long Size,
        string Sha256);

    private sealed record ExpectedReceiptArtifact(
        string Role,
        string File,
        long Size,
        string Sha256);

    private static class WorkerReadyRecordOperationNames
    {
        internal const string BundleDirectoryName = "bundle";
        internal const string ReceiptJsonFileName =
            "signing-receipt.json";
        internal const string ReceiptSignatureFileName =
            "signing-receipt.p7s";
    }
}

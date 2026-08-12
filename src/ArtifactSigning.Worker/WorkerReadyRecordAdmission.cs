using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public enum WorkerAdmissionError
{
    None,
    ReadyRecordMissing,
    InventoryInvalid,
    RequestInvalid,
    ProfileInvalid,
    AuthorizationInvalid,
    Conflict,
    StorageFailed,
}

public sealed record WorkerAdmissionResult(
    WorkerAdmissionError Error,
    WorkerJobRecord? Job)
{
    public bool IsSuccess =>
        Error is WorkerAdmissionError.None
        && Job is not null;
}

public interface IWorkerReadyRecordAdmission
{
    ValueTask<WorkerAdmissionResult> AdmitAsync(
        Guid requestId,
        CancellationToken cancellationToken);
}

public sealed class WorkerReadyRecordAdmission :
    IWorkerReadyRecordAdmission
{
    private readonly WorkerStateStore _stateStore;
    private readonly SigningProfileRegistry _profiles;
    private readonly IWorkerJobRevalidator _revalidator;
    private readonly TimeProvider _timeProvider;

    public WorkerReadyRecordAdmission(
        WorkerStateStore stateStore,
        SigningProfileRegistry profiles,
        IWorkerJobRevalidator revalidator,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(revalidator);
        _stateStore = stateStore;
        _profiles = profiles;
        _revalidator = revalidator;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<WorkerAdmissionResult> AdmitAsync(
        Guid requestId,
        CancellationToken cancellationToken)
    {
        if (requestId == Guid.Empty)
        {
            return Failure(WorkerAdmissionError.RequestInvalid);
        }

        WorkerJobRecord? existing =
            _stateStore.GetJob(requestId);
        if (existing is not null)
        {
            return existing.State is RequestState.Approved
                ? Success(existing)
                : Failure(WorkerAdmissionError.Conflict, existing);
        }

        string source =
            _stateStore.Layout.GetReadyInboxDirectory(requestId);
        string staging =
            _stateStore.Layout.CreateAdmissionDirectoryPath();
        bool movedToWork = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsDirectDirectory(source)
                || !HasExactEntries(
                    source,
                    [
                        WorkerReadyRecordOperation
                            .RequestJsonFileName,
                        WorkerReadyRecordOperation
                            .RequestSignatureFileName,
                        WorkerReadyRecordOperation
                            .ApprovalSignatureFileName,
                        WorkerReadyRecordOperation
                            .BundleDirectoryName,
                    ]))
            {
                return Failure(
                    WorkerAdmissionError.ReadyRecordMissing);
            }

            Directory.CreateDirectory(staging);
            string stagingBundle = Path.Combine(
                staging,
                WorkerReadyRecordOperation.BundleDirectoryName);
            Directory.CreateDirectory(stagingBundle);
            CopyBoundedFile(
                Path.Combine(
                    source,
                    WorkerReadyRecordOperation
                        .RequestJsonFileName),
                Path.Combine(
                    staging,
                    WorkerReadyRecordOperation
                        .RequestJsonFileName),
                ArtifactSigningRequestJsonParser
                    .MaximumRequestJsonBytes);
            CopyBoundedFile(
                Path.Combine(
                    source,
                    WorkerReadyRecordOperation
                        .RequestSignatureFileName),
                Path.Combine(
                    staging,
                    WorkerReadyRecordOperation
                        .RequestSignatureFileName),
                DetachedCmsSignatureVerifier.MaximumSignatureBytes);
            CopyBoundedFile(
                Path.Combine(
                    source,
                    WorkerReadyRecordOperation
                        .ApprovalSignatureFileName),
                Path.Combine(
                    staging,
                    WorkerReadyRecordOperation
                        .ApprovalSignatureFileName),
                DetachedCmsSignatureVerifier.MaximumSignatureBytes);

            byte[] requestJson = WorkerDirectFile.ReadBounded(
                Path.Combine(
                    staging,
                    WorkerReadyRecordOperation.RequestJsonFileName),
                ArtifactSigningRequestJsonParser
                    .MaximumRequestJsonBytes);
            RequestJsonParseResult parsed =
                ArtifactSigningRequestJsonParser.Parse(requestJson);
            if (!parsed.IsSuccess
                || parsed.Request is null
                || parsed.Request.RequestId != requestId)
            {
                return Failure(WorkerAdmissionError.RequestInvalid);
            }

            ISigningProfile? profile = _profiles.Resolve(
                parsed.Request.ProfileId,
                parsed.Request.ProfileVersion);
            if (profile is null)
            {
                return Failure(WorkerAdmissionError.ProfileInvalid);
            }

            string sourceBundle = Path.Combine(
                source,
                WorkerReadyRecordOperation.BundleDirectoryName);
            HashSet<string> artifactNames =
                profile.Descriptor.Artifacts
                    .Select(definition => definition.FileName)
                    .ToHashSet(StringComparer.Ordinal);
            if (!IsDirectDirectory(sourceBundle)
                || !HasExactEntries(
                    sourceBundle,
                    artifactNames))
            {
                return Failure(
                    WorkerAdmissionError.InventoryInvalid);
            }

            foreach (SigningProfileArtifactDefinition definition
                     in profile.Descriptor.Artifacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CopyBoundedFile(
                    Path.Combine(
                        sourceBundle,
                        definition.FileName),
                    Path.Combine(
                        stagingBundle,
                        definition.FileName),
                    definition.MaximumBytes);
            }

            if (!HasExactEntries(
                    source,
                    [
                        WorkerReadyRecordOperation
                            .RequestJsonFileName,
                        WorkerReadyRecordOperation
                            .RequestSignatureFileName,
                        WorkerReadyRecordOperation
                            .ApprovalSignatureFileName,
                        WorkerReadyRecordOperation
                            .BundleDirectoryName,
                    ])
                || !HasExactEntries(
                    sourceBundle,
                    artifactNames))
            {
                return Failure(
                    WorkerAdmissionError.InventoryInvalid);
            }

            string requestDigest =
                RequestDigest.ComputeHex(requestJson);
            DateTimeOffset admittedAt = GetWholeSecondUtcNow();
            WorkerJobRecord candidate = new(
                requestId,
                requestDigest,
                RequestState.Approved,
                RowVersion: 1,
                WorkerResultCode.ApprovedValidated,
                EvidenceDigest: null,
                admittedAt,
                admittedAt);
            WorkerRevalidationResult validation =
                await _revalidator.RevalidateAsync(
                        candidate,
                        staging,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (!validation.IsSuccess)
            {
                return Failure(MapValidationError(validation.Error));
            }

            string work =
                _stateStore.Layout.GetWorkDirectory(requestId);
            if (Directory.Exists(work))
            {
                WorkerAdmissionResult recovery =
                    await RecoverExistingWorkAsync(
                            candidate,
                            work,
                            cancellationToken)
                        .ConfigureAwait(false);
                return recovery;
            }

            Directory.Move(staging, work);
            movedToWork = true;
            WorkerMutationResult admitted =
                _stateStore.AdmitApproved(
                    requestId,
                    requestDigest,
                    admittedAt);
            if ((admitted.Outcome is WorkerMutationOutcome.Applied
                    or WorkerMutationOutcome.AlreadyApplied)
                && admitted.Job is not null)
            {
                return Success(admitted.Job!);
            }

            TryDeleteOwnedDirectory(work);
            movedToWork = false;
            return Failure(WorkerAdmissionError.Conflict);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Failure(WorkerAdmissionError.StorageFailed);
        }
        finally
        {
            if (!movedToWork)
            {
                TryDeleteOwnedDirectory(staging);
            }
        }
    }

    private async ValueTask<WorkerAdmissionResult>
        RecoverExistingWorkAsync(
            WorkerJobRecord candidate,
            string work,
            CancellationToken cancellationToken)
    {
        WorkerRevalidationResult validation =
            await _revalidator.RevalidateAsync(
                    candidate,
                    work,
                    cancellationToken)
                .ConfigureAwait(false);
        if (!validation.IsSuccess)
        {
            return Failure(WorkerAdmissionError.Conflict);
        }

        WorkerMutationResult admitted =
            _stateStore.AdmitApproved(
                candidate.RequestId,
                candidate.RequestDigest,
                candidate.CreatedAt);
        return (admitted.Outcome is WorkerMutationOutcome.Applied
                or WorkerMutationOutcome.AlreadyApplied)
            && admitted.Job is not null
            ? Success(admitted.Job!)
            : Failure(WorkerAdmissionError.Conflict);
    }

    private static void CopyBoundedFile(
        string sourcePath,
        string destinationPath,
        long maximumBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            maximumBytes);
        using FileStream source =
            WorkerDirectFile.OpenRead(sourcePath);
        if (source.Length is <= 0
            || source.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Ready-record file exceeds its compiled bound.");
        }

        long expectedLength = source.Length;
        using FileStream destination = new(
            destinationPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 64 * 1024,
                Options = FileOptions.SequentialScan
                    | FileOptions.WriteThrough,
            });
        source.CopyTo(destination);
        if (destination.Length != expectedLength
            || source.ReadByte() is not -1)
        {
            throw new InvalidDataException(
                "Ready-record file changed while being copied.");
        }

        destination.Flush(flushToDisk: true);
    }

    private DateTimeOffset GetWholeSecondUtcNow()
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

    private static WorkerAdmissionError MapValidationError(
        WorkerRevalidationError error)
    {
        return error switch
        {
            WorkerRevalidationError.AuthorizationInvalid
                or WorkerRevalidationError.ApprovalInvalid =>
                WorkerAdmissionError.AuthorizationInvalid,
            WorkerRevalidationError.ProfileInvalid =>
                WorkerAdmissionError.ProfileInvalid,
            _ => WorkerAdmissionError.RequestInvalid,
        };
    }

    private static bool HasExactEntries(
        string directory,
        IEnumerable<string> expectedEntries)
    {
        if (!IsDirectDirectory(directory))
        {
            return false;
        }

        HashSet<string> expected =
            expectedEntries.ToHashSet(StringComparer.Ordinal);
        try
        {
            string?[] actual = Directory
                .EnumerateFileSystemEntries(directory)
                .Select(Path.GetFileName)
                .ToArray();
            return actual.Length == expected.Count
                && actual.All(item =>
                    item is not null && expected.Contains(item));
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

    private static bool IsDirectDirectory(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.Directory)
                && !attributes.HasFlag(FileAttributes.ReparsePoint);
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

    private static void TryDeleteOwnedDirectory(string path)
    {
        try
        {
            if (IsDirectDirectory(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Admission cleanup is best effort before durable state.
        }
        catch (UnauthorizedAccessException)
        {
            // Admission cleanup is best effort before durable state.
        }
    }

    private static WorkerAdmissionResult Success(
        WorkerJobRecord job)
    {
        return new WorkerAdmissionResult(
            WorkerAdmissionError.None,
            job);
    }

    private static WorkerAdmissionResult Failure(
        WorkerAdmissionError error,
        WorkerJobRecord? job = null)
    {
        return new WorkerAdmissionResult(error, job);
    }
}

using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public enum GatewayStartupReconciliationOutcome
{
    Ready,
    Unresolved,
}

public sealed class GatewayStartupReconciler
{
    private readonly GatewayStateStore _stateStore;
    private readonly IGatewayWorkerNotifier _notifier;
    private readonly IGatewayReadyRecordAccessController
        _readyRecordAccess;
    private readonly GatewayResultProcessor? _resultProcessor;
    private readonly TimeProvider _timeProvider;

    public GatewayStartupReconciler(
        GatewayStateStore stateStore,
        IGatewayWorkerNotifier notifier,
        IGatewayReadyRecordAccessController readyRecordAccess,
        TimeProvider? timeProvider = null,
        GatewayResultProcessor? resultProcessor = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(notifier);
        ArgumentNullException.ThrowIfNull(readyRecordAccess);
        _stateStore = stateStore;
        _notifier = notifier;
        _readyRecordAccess = readyRecordAccess;
        _resultProcessor = resultProcessor;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<GatewayStartupReconciliationOutcome>
        ReconcileAsync(CancellationToken cancellationToken)
    {
        try
        {
            _stateStore.VerifyIntegrity();
            if (!ClearReceiving()
                || !ReconcilePending()
                || !ReconcileReady())
            {
                return GatewayStartupReconciliationOutcome
                    .Unresolved;
            }

            IReadOnlyList<GatewayRequestRecord> dispatches =
                _stateStore.GetRequestsByStates(
                    RequestState.Approved,
                    RequestState.Signing);
            foreach (GatewayRequestRecord request in dispatches)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (request.State is RequestState.Signing
                    && _resultProcessor is not null)
                {
                    GatewayWorkerObservationResult observation =
                        _resultProcessor.Observe(request);
                    if (observation.Outcome is
                        GatewayWorkerObservationOutcome.Completed
                        or GatewayWorkerObservationOutcome
                            .Quarantined)
                    {
                        continue;
                    }

                    if (observation.Outcome is
                        GatewayWorkerObservationOutcome.Conflict)
                    {
                        return
                            GatewayStartupReconciliationOutcome
                                .Unresolved;
                    }
                }

                GatewayWorkerNotificationResult notification =
                    await _notifier.NotifyAsync(
                            request.RequestId,
                            cancellationToken)
                        .ConfigureAwait(false);
                if (!notification.IsSuccess)
                {
                    return GatewayStartupReconciliationOutcome
                        .Unresolved;
                }

                if (request.State is RequestState.Approved)
                {
                    GatewayMutationResult transition =
                        _stateStore.TryMarkWorkerDispatched(
                            request.RequestId,
                            request.RequestDigest,
                            request.RowVersion,
                            WholeSecondNow());
                    if (transition.Outcome is not (
                            GatewayMutationOutcome.Applied
                            or GatewayMutationOutcome
                                .AlreadyApplied))
                    {
                        return GatewayStartupReconciliationOutcome
                            .Unresolved;
                    }
                }
            }

            _stateStore.VerifyIntegrity();
            return GatewayStartupReconciliationOutcome.Ready;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return GatewayStartupReconciliationOutcome.Unresolved;
        }
    }

    private bool ClearReceiving()
    {
        foreach (string path in Directory.EnumerateFileSystemEntries(
                     _stateStore.Layout.ReceivingRoot))
        {
            string? name = Path.GetFileName(path);
            if (name is null
                || !name.StartsWith(
                    "receiving-",
                    StringComparison.Ordinal)
                || !Guid.TryParseExact(
                    name.AsSpan("receiving-".Length),
                    "N",
                    out Guid identifier)
                || identifier == Guid.Empty
                || !IsDirectDirectory(path)
                || !TryDeleteOwnedDirectory(path))
            {
                return false;
            }
        }

        return true;
    }

    private bool ReconcilePending()
    {
        Dictionary<Guid, GatewayRequestRecord> expected =
            _stateStore.GetRequestsByStates(
                    RequestState.PendingApproval)
                .ToDictionary(
                    item => item.RequestId);
        foreach (string path in Directory.EnumerateFileSystemEntries(
                     _stateStore.Layout.PendingRoot))
        {
            if (!TryParseJobDirectory(path, out Guid requestId))
            {
                return false;
            }

            if (expected.Remove(requestId))
            {
                continue;
            }

            GatewayRequestRecord? record =
                _stateStore.GetRequest(requestId);
            if (record is null
                || RequestStateTransitions.IsTerminal(record.State))
            {
                if (!TryDeleteOwnedDirectory(path))
                {
                    return false;
                }

                continue;
            }

            return false;
        }

        return expected.Count is 0;
    }

    private bool ReconcileReady()
    {
        Dictionary<Guid, GatewayRequestRecord> expected =
            _stateStore.GetRequestsByStates(
                    RequestState.Approved,
                    RequestState.Signing)
                .ToDictionary(
                    item => item.RequestId);
        foreach (string path in Directory.EnumerateFileSystemEntries(
                     _stateStore.Layout.ReadyRoot))
        {
            if (!TryParseJobDirectory(path, out Guid requestId))
            {
                return false;
            }

            if (expected.Remove(
                    requestId,
                    out GatewayRequestRecord? request))
            {
                if (!_readyRecordAccess.PrepareForWorker(
                        request))
                {
                    return false;
                }

                continue;
            }

            GatewayRequestRecord? record =
                _stateStore.GetRequest(requestId);
            if (record is null
                || RequestStateTransitions.IsTerminal(record.State))
            {
                if (!TryDeleteOwnedDirectory(path))
                {
                    return false;
                }

                continue;
            }

            return false;
        }

        return expected.Count is 0;
    }

    private static bool TryParseJobDirectory(
        string path,
        out Guid requestId)
    {
        requestId = Guid.Empty;
        string? name = Path.GetFileName(path);
        return name is not null
            && name.Length is 32
            && Guid.TryParseExact(name, "N", out requestId)
            && requestId != Guid.Empty
            && string.Equals(
                requestId.ToString("N"),
                name,
                StringComparison.Ordinal)
            && IsDirectDirectory(path);
    }

    private static bool IsDirectDirectory(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.Directory)
                && !attributes.HasFlag(
                    FileAttributes.ReparsePoint);
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

    private static bool TryDeleteOwnedDirectory(string path)
    {
        try
        {
            if (!IsDirectDirectory(path))
            {
                return false;
            }

            Directory.Delete(path, recursive: true);
            return !Directory.Exists(path);
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
}

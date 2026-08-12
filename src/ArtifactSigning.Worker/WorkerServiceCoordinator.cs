namespace ArtifactSigning.Worker;

public enum WorkerServiceStartupOutcome
{
    Ready,
    ReconciliationUnresolved,
}

public sealed class WorkerServiceCoordinator
{
    private readonly WorkerJobProcessor _processor;
    private readonly WorkerNotificationDispatcher _dispatcher;
    private readonly IWorkerNotificationSource _notificationSource;
    private readonly IWorkerAuditAnchorPublisher?
        _auditAnchorPublisher;
    private readonly TimeProvider _timeProvider;

    public WorkerServiceCoordinator(
        WorkerJobProcessor processor,
        WorkerNotificationDispatcher dispatcher,
        IWorkerNotificationSource notificationSource,
        IWorkerAuditAnchorPublisher?
            auditAnchorPublisher = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(notificationSource);
        _processor = processor;
        _dispatcher = dispatcher;
        _notificationSource = notificationSource;
        _auditAnchorPublisher = auditAnchorPublisher;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public WorkerServiceStartupOutcome ReconcileStartup()
    {
        IReadOnlyList<WorkerReconciliationResult> results =
            _processor.ReconcileStartup();
        bool unresolved = results.Any(result =>
                result.Outcome is WorkerReconciliationOutcome.Unresolved)
            || _auditAnchorPublisher is not null
                && !_auditAnchorPublisher.Publish(
                    workerReady: true);
        return unresolved
            ? WorkerServiceStartupOutcome
                .ReconciliationUnresolved
            : WorkerServiceStartupOutcome.Ready;
    }

    public async Task RunAsync(
        Func<
            WorkerNotificationReadResult,
            WorkerNotificationDispatchResult?,
            CancellationToken,
            ValueTask> observer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observer);

        if (_auditAnchorPublisher is null)
        {
            await RunWithoutAnchorHeartbeatAsync(
                    observer,
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        using PeriodicTimer timer = new(
            TimeSpan.FromSeconds(30),
            _timeProvider);
        Task<WorkerNotificationReadResult> notificationTask =
            _notificationSource
                .ReadAsync(cancellationToken)
                .AsTask();
        Task<bool> tickTask = timer
            .WaitForNextTickAsync(cancellationToken)
            .AsTask();
        while (!cancellationToken.IsCancellationRequested)
        {
            Task completed = await Task.WhenAny(
                    notificationTask,
                    tickTask)
                .ConfigureAwait(false);
            if (completed == tickTask)
            {
                if (!await tickTask.ConfigureAwait(false)
                    || !_auditAnchorPublisher.Publish(
                        workerReady: true))
                {
                    throw new InvalidOperationException(
                        "Worker audit anchor publication failed.");
                }

                tickTask = timer
                    .WaitForNextTickAsync(
                        cancellationToken)
                    .AsTask();
                continue;
            }

            WorkerNotificationReadResult notification =
                await notificationTask.ConfigureAwait(false);
            WorkerNotificationDispatchResult? dispatch =
                await DispatchAsync(
                        notification,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (!_auditAnchorPublisher.Publish(
                    workerReady: true))
            {
                throw new InvalidOperationException(
                    "Worker audit anchor publication failed.");
            }

            await observer(
                    notification,
                    dispatch,
                    cancellationToken)
                .ConfigureAwait(false);
            notificationTask = _notificationSource
                .ReadAsync(cancellationToken)
                .AsTask();
        }
    }

    private async Task RunWithoutAnchorHeartbeatAsync(
        Func<
            WorkerNotificationReadResult,
            WorkerNotificationDispatchResult?,
            CancellationToken,
            ValueTask> observer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            WorkerNotificationReadResult notification =
                await _notificationSource
                    .ReadAsync(cancellationToken)
                    .ConfigureAwait(false);
            WorkerNotificationDispatchResult? dispatch =
                await DispatchAsync(
                        notification,
                        cancellationToken)
                    .ConfigureAwait(false);
            await observer(
                    notification,
                    dispatch,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<
        WorkerNotificationDispatchResult?> DispatchAsync(
        WorkerNotificationReadResult notification,
        CancellationToken cancellationToken)
    {
        if (notification is not
            {
                Outcome: WorkerNotificationReadOutcome.Accepted,
                RequestId: Guid requestId,
            })
        {
            return null;
        }

        return await _dispatcher.DispatchAsync(
                requestId,
                cancellationToken)
            .ConfigureAwait(false);
    }
}

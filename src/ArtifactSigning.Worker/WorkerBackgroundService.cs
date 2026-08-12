using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ArtifactSigning.Worker;

public sealed partial class WorkerBackgroundService : BackgroundService
{
    private const int ServiceFailureExitCode = 70;

    private readonly WorkerServiceCoordinator _coordinator;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly ILogger<WorkerBackgroundService> _logger;

    public WorkerBackgroundService(
        WorkerServiceCoordinator coordinator,
        IHostApplicationLifetime applicationLifetime,
        ILogger<WorkerBackgroundService> logger)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(applicationLifetime);
        ArgumentNullException.ThrowIfNull(logger);
        _coordinator = coordinator;
        _applicationLifetime = applicationLifetime;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        try
        {
            WorkerServiceStartupOutcome startup =
                _coordinator.ReconcileStartup();
            if (startup
                is WorkerServiceStartupOutcome.ReconciliationUnresolved)
            {
                FailService("ReconciliationUnresolved");
                return;
            }

            WorkerReady(_logger);
            await _coordinator.RunAsync(
                    ObserveAsync,
                    stoppingToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            FailService("WorkerLoopFailed");
        }
    }

    private ValueTask ObserveAsync(
        WorkerNotificationReadResult notification,
        WorkerNotificationDispatchResult? dispatch,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (notification.Outcome is WorkerNotificationReadOutcome.Rejected)
        {
            NotificationRejected(_logger);
            return ValueTask.CompletedTask;
        }

        Guid requestId = notification.RequestId!.Value;
        if (dispatch?.ProcessingResult?.Job is WorkerJobRecord job)
        {
            NotificationProcessed(
                _logger,
                requestId,
                job.RequestDigest,
                dispatch.ProcessingResult.Outcome);
        }
        else
        {
            NotificationIgnored(
                _logger,
                requestId,
                dispatch?.Outcome);
        }

        return ValueTask.CompletedTask;
    }

    private void FailService(string resultCode)
    {
        WorkerFailed(_logger, resultCode);
        Environment.ExitCode = ServiceFailureExitCode;
        _applicationLifetime.StopApplication();
    }

    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Information,
        Message = "Worker state Ready.")]
    private static partial void WorkerReady(
        ILogger logger);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "Worker notification rejected.")]
    private static partial void NotificationRejected(
        ILogger logger);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "Worker request {RequestId} digest {RequestDigest} result {ResultCode}.")]
    private static partial void NotificationProcessed(
        ILogger logger,
        Guid requestId,
        string requestDigest,
        WorkerProcessingOutcome resultCode);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Information,
        Message = "Worker request {RequestId} notification result {ResultCode}.")]
    private static partial void NotificationIgnored(
        ILogger logger,
        Guid requestId,
        WorkerNotificationDispatchOutcome? resultCode);

    [LoggerMessage(
        EventId = 1099,
        Level = LogLevel.Critical,
        Message = "Worker stopped with result {ResultCode}.")]
    private static partial void WorkerFailed(
        ILogger logger,
        string resultCode);
}

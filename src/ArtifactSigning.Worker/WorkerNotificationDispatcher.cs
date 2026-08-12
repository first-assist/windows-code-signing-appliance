using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public enum WorkerNotificationDispatchOutcome
{
    Processed,
    NotApproved,
    StateChanged,
}

public sealed record WorkerNotificationDispatchResult(
    WorkerNotificationDispatchOutcome Outcome,
    WorkerProcessingResult? ProcessingResult);

public sealed class WorkerNotificationDispatcher
{
    private readonly WorkerStateStore _stateStore;
    private readonly WorkerJobProcessor _processor;
    private readonly IWorkerReadyRecordAdmission? _admission;

    public WorkerNotificationDispatcher(
        WorkerStateStore stateStore,
        WorkerJobProcessor processor,
        IWorkerReadyRecordAdmission? admission = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(processor);
        _stateStore = stateStore;
        _processor = processor;
        _admission = admission;
    }

    public async ValueTask<WorkerNotificationDispatchResult> DispatchAsync(
        Guid requestId,
        CancellationToken cancellationToken = default)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        WorkerJobRecord? job = _stateStore.GetJob(requestId);
        if (job is null && _admission is not null)
        {
            WorkerAdmissionResult admission =
                await _admission.AdmitAsync(
                        requestId,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (admission.IsSuccess)
            {
                job = admission.Job;
            }
        }

        if (job?.State is not RequestState.Approved)
        {
            return new WorkerNotificationDispatchResult(
                WorkerNotificationDispatchOutcome.NotApproved,
                null);
        }

        WorkerProcessingResult processing =
            await _processor.ProcessApprovedAsync(
                    requestId,
                    job.RequestDigest,
                    cancellationToken)
                .ConfigureAwait(false);
        return new WorkerNotificationDispatchResult(
            processing.Outcome is WorkerProcessingOutcome.StateMismatch
                ? WorkerNotificationDispatchOutcome.StateChanged
                : WorkerNotificationDispatchOutcome.Processed,
            processing);
    }
}

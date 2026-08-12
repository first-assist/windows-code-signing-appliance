using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public interface IWorkerJobRevalidator
{
    ValueTask<WorkerRevalidationResult> RevalidateAsync(
        WorkerJobRecord job,
        string trustedWorkDirectory,
        CancellationToken cancellationToken);
}

public interface IWorkerSigningOperation
{
    ValueTask<WorkerSigningOperationResult> ExecuteAsync(
        WorkerJobRecord signingJob,
        string trustedWorkDirectory,
        CancellationToken cancellationToken);
}

public sealed class WorkerJobProcessor
{
    private readonly WorkerStateStore _stateStore;
    private readonly IWorkerJobRevalidator _revalidator;
    private readonly IWorkerSigningOperation _signingOperation;
    private readonly IWorkerOutputPublisher _outputPublisher;
    private readonly TimeProvider _timeProvider;
    private readonly IWorkerTerminalStatusPublisher?
        _terminalStatusPublisher;
    private readonly IWorkerAuditAnchorPublisher?
        _auditAnchorPublisher;

    public WorkerJobProcessor(
        WorkerStateStore stateStore,
        IWorkerJobRevalidator revalidator,
        IWorkerSigningOperation signingOperation,
        IWorkerOutputPublisher outputPublisher,
        TimeProvider? timeProvider = null,
        IWorkerTerminalStatusPublisher?
            terminalStatusPublisher = null,
        IWorkerAuditAnchorPublisher?
            auditAnchorPublisher = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(revalidator);
        ArgumentNullException.ThrowIfNull(signingOperation);
        ArgumentNullException.ThrowIfNull(outputPublisher);
        _stateStore = stateStore;
        _revalidator = revalidator;
        _signingOperation = signingOperation;
        _outputPublisher = outputPublisher;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _terminalStatusPublisher = terminalStatusPublisher;
        _auditAnchorPublisher = auditAnchorPublisher;
    }

    public async ValueTask<WorkerProcessingResult> ProcessApprovedAsync(
        Guid requestId,
        string requestDigest,
        CancellationToken cancellationToken = default)
    {
        WorkerContractRules.ValidateRequest(requestId, requestDigest);
        WorkerJobRecord? approvedJob = _stateStore.GetJob(requestId);
        if (approvedJob is null
            || !string.Equals(
                approvedJob.RequestDigest,
                requestDigest,
                StringComparison.Ordinal)
            || approvedJob.State is not RequestState.Approved)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.StateMismatch,
                approvedJob);
        }

        string workDirectory =
            _stateStore.Layout.GetWorkDirectory(requestId);
        if (!_stateStore.Layout.HasDirectWorkDirectory(requestId))
        {
            return FailBeforeSigning(approvedJob);
        }

        WorkerRevalidationResult revalidation;
        try
        {
            revalidation = await _revalidator.RevalidateAsync(
                    approvedJob,
                    workDirectory,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.CancelledBeforeSigning,
                approvedJob);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return FailBeforeSigning(approvedJob);
        }

        if (revalidation is null || !revalidation.IsSuccess)
        {
            return FailBeforeSigning(approvedJob);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.CancelledBeforeSigning,
                approvedJob);
        }

        WorkerMutationResult claim = _stateStore.TryBeginSigning(
            approvedJob.RequestId,
            approvedJob.RequestDigest,
            approvedJob.RowVersion,
            GetWholeSecondUtcNow());
        if (claim.Outcome is WorkerMutationOutcome.SigningBusy)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.SigningBusy,
                claim.Job);
        }

        if (claim.Outcome is not WorkerMutationOutcome.Applied
            || claim.Job is null)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.StateMismatch,
                claim.Job);
        }

        WorkerJobRecord signingJob = claim.Job;
        if (_auditAnchorPublisher is not null
            && !_auditAnchorPublisher.Publish(
                workerReady: true))
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome
                    .ReconciliationRequired,
                signingJob);
        }

        WorkerSigningOperationResult signingResult;
        try
        {
            signingResult = await _signingOperation.ExecuteAsync(
                    signingJob,
                    workDirectory,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            return Quarantine(
                signingJob,
                WorkerResultCode.SigningCancelled);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Quarantine(
                signingJob,
                WorkerResultCode.SigningOperationFailed);
        }

        if (signingResult is null
            || !signingResult.IsSuccess
            || signingResult.EvidenceDigest is null)
        {
            return Quarantine(
                signingJob,
                signingResult?.Failure is WorkerSigningFailure failure
                    ? MapSigningFailure(failure)
                    : WorkerResultCode.SigningOperationFailed);
        }

        if (!_outputPublisher.TryPublish(signingJob))
        {
            return Quarantine(
                signingJob,
                WorkerResultCode.OutputPublicationFailed);
        }

        try
        {
            WorkerMutationResult completion = _stateStore.TryCompleteSigned(
                signingJob.RequestId,
                signingJob.RequestDigest,
                signingJob.RowVersion,
                signingResult.EvidenceDigest,
                GetWholeSecondUtcNow());
            if (completion.Outcome is WorkerMutationOutcome.Applied
                or WorkerMutationOutcome.AlreadyApplied)
            {
                if (!PublishTerminal(completion.Job))
                {
                    return new WorkerProcessingResult(
                        WorkerProcessingOutcome
                            .ReconciliationRequired,
                        completion.Job);
                }

                return new WorkerProcessingResult(
                    WorkerProcessingOutcome.Completed,
                    completion.Job);
            }

            if (completion.Job?.State is not RequestState.Signing)
            {
                return new WorkerProcessingResult(
                    WorkerProcessingOutcome.ReconciliationRequired,
                    completion.Job);
            }
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            // A completion exception is commit-ambiguous. Leave the durable
            // state and directory untouched for startup reconciliation.
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.ReconciliationRequired,
                null);
        }

        return Quarantine(
            signingJob,
            WorkerResultCode.CompletionPersistenceFailed);
    }

    public IReadOnlyList<WorkerReconciliationResult> ReconcileStartup()
    {
        List<WorkerReconciliationResult> results = [];
        foreach (WorkerJobRecord signingJob in _stateStore.GetSigningJobs())
        {
            if (!_stateStore.Layout.TryMoveSoleJobDirectoryToQuarantine(
                    signingJob.RequestId))
            {
                results.Add(
                    new WorkerReconciliationResult(
                        signingJob.RequestId,
                        WorkerReconciliationOutcome.Unresolved,
                        signingJob));
                continue;
            }

            try
            {
                WorkerMutationResult transition = _stateStore.TryQuarantine(
                    signingJob.RequestId,
                    signingJob.RequestDigest,
                    signingJob.RowVersion,
                    WorkerResultCode.RestartAmbiguity,
                    GetWholeSecondUtcNow());
                if (transition.Outcome is WorkerMutationOutcome.Applied
                    or WorkerMutationOutcome.AlreadyApplied)
                {
                    results.Add(
                        new WorkerReconciliationResult(
                            signingJob.RequestId,
                            WorkerReconciliationOutcome.Quarantined,
                            transition.Job));
                    continue;
                }
            }
            catch (Exception exception)
                when (exception is not OutOfMemoryException)
            {
                // The unresolved Signing row retains the global signing lease.
            }

            results.Add(
                new WorkerReconciliationResult(
                    signingJob.RequestId,
                    WorkerReconciliationOutcome.Unresolved,
                    signingJob));
        }

        foreach (WorkerJobRecord terminal
                 in _stateStore.GetTerminalJobs())
        {
            if (terminal.State is RequestState.Signed
                && !_outputPublisher.TryPublish(terminal))
            {
                results.Add(new WorkerReconciliationResult(
                    terminal.RequestId,
                    WorkerReconciliationOutcome.Unresolved,
                    terminal));
                continue;
            }

            if (!PublishTerminal(terminal))
            {
                results.Add(new WorkerReconciliationResult(
                    terminal.RequestId,
                    WorkerReconciliationOutcome.Unresolved,
                    terminal));
            }
        }

        return results;
    }

    private WorkerProcessingResult FailBeforeSigning(
        WorkerJobRecord approvedJob)
    {
        WorkerMutationResult failure = _stateStore.TryFailApproved(
            approvedJob.RequestId,
            approvedJob.RequestDigest,
            approvedJob.RowVersion,
            GetWholeSecondUtcNow());
        return (failure.Outcome is WorkerMutationOutcome.Applied
                or WorkerMutationOutcome.AlreadyApplied)
            && PublishTerminal(failure.Job)
            ? new WorkerProcessingResult(
                WorkerProcessingOutcome.FailedBeforeSigning,
                failure.Job)
            : new WorkerProcessingResult(
                WorkerProcessingOutcome.StateMismatch,
                failure.Job);
    }

    private WorkerProcessingResult Quarantine(
        WorkerJobRecord signingJob,
        WorkerResultCode resultCode)
    {
        if (!_stateStore.Layout.TryMoveSoleJobDirectoryToQuarantine(
                signingJob.RequestId))
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.ReconciliationRequired,
                signingJob);
        }

        try
        {
            WorkerMutationResult quarantine = _stateStore.TryQuarantine(
                signingJob.RequestId,
                signingJob.RequestDigest,
                signingJob.RowVersion,
                resultCode,
                GetWholeSecondUtcNow());
            return (quarantine.Outcome
                    is WorkerMutationOutcome.Applied
                    or WorkerMutationOutcome.AlreadyApplied)
                && PublishTerminal(quarantine.Job)
                ? new WorkerProcessingResult(
                    WorkerProcessingOutcome.Quarantined,
                    quarantine.Job)
                : new WorkerProcessingResult(
                    WorkerProcessingOutcome.ReconciliationRequired,
                    quarantine.Job);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return new WorkerProcessingResult(
                WorkerProcessingOutcome.ReconciliationRequired,
                null);
        }
    }

    private static WorkerResultCode MapSigningFailure(
        WorkerSigningFailure failure)
    {
        return failure switch
        {
            WorkerSigningFailure.ReadyRecordInvalid =>
                WorkerResultCode.SigningReadyRecordInvalid,
            WorkerSigningFailure.AuthorizationInvalid =>
                WorkerResultCode.SigningAuthorizationInvalid,
            WorkerSigningFailure.ArtifactPrecheckFailed =>
                WorkerResultCode.SigningArtifactPrecheckFailed,
            WorkerSigningFailure.SignToolRejected =>
                WorkerResultCode.SigningToolInvocationFailed,
            WorkerSigningFailure.SignatureVerificationFailed =>
                WorkerResultCode.SigningSignatureVerificationFailed,
            WorkerSigningFailure.ProfileFinalizationFailed =>
                WorkerResultCode.SigningProfileFinalizationFailed,
            WorkerSigningFailure.FinalizedValidationFailed =>
                WorkerResultCode.SigningFinalizedValidationFailed,
            WorkerSigningFailure.ReceiptSigningFailed =>
                WorkerResultCode.SigningReceiptSigningFailed,
            WorkerSigningFailure.OutputPreparationFailed =>
                WorkerResultCode.SigningOutputPreparationFailed,
            _ => throw new ArgumentOutOfRangeException(
                nameof(failure),
                failure,
                "Signing failure is not a compiled result code."),
        };
    }

    private DateTimeOffset GetWholeSecondUtcNow()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private bool PublishTerminal(WorkerJobRecord? job)
    {
        return job is not null
            && (_terminalStatusPublisher is null
                || _terminalStatusPublisher.Publish(job))
            && (_auditAnchorPublisher is null
                || _auditAnchorPublisher.Publish(
                    workerReady: true));
    }
}

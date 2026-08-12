using System.Diagnostics;

namespace ArtifactSigning.Windows;

internal sealed record SignToolProcessOutcome(
    bool Started,
    bool TimedOut,
    bool Cancelled,
    bool TerminationFailed,
    bool OutputLimitExceeded,
    int ExitCode);

internal interface ISignToolProcessExecutor
{
    Task<SignToolProcessOutcome> ExecuteAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        int maximumOutputBytes,
        CancellationToken cancellationToken);
}

internal sealed class SignToolProcessExecutor : ISignToolProcessExecutor
{
    public async Task<SignToolProcessOutcome> ExecuteAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        int maximumOutputBytes,
        CancellationToken cancellationToken)
    {
        using Process process = new()
        {
            StartInfo = startInfo,
        };
        try
        {
            if (!process.Start())
            {
                return new SignToolProcessOutcome(
                    Started: false,
                    TimedOut: false,
                    Cancelled: false,
                    TerminationFailed: false,
                    OutputLimitExceeded: false,
                    ExitCode: -1);
            }
        }
        catch (InvalidOperationException)
        {
            return StartFailure();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return StartFailure();
        }

        Task<bool> standardOutput = DrainAsync(
            process.StandardOutput.BaseStream,
            maximumOutputBytes);
        Task<bool> standardError = DrainAsync(
            process.StandardError.BaseStream,
            maximumOutputBytes);
        Task processExit = process.WaitForExitAsync(CancellationToken.None);
        Task delay = Task.Delay(timeout, cancellationToken);
        Task completed = await Task.WhenAny(processExit, delay).ConfigureAwait(false);

        bool timedOut = false;
        bool cancelled = false;
        if (completed != processExit)
        {
            cancelled = cancellationToken.IsCancellationRequested;
            timedOut = !cancelled;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The process exited between the timeout decision and the kill.
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // The caller still receives a terminal failure and must quarantine.
            }

            Task terminationBound = Task.Delay(
                TimeSpan.FromSeconds(5),
                CancellationToken.None);
            if (await Task.WhenAny(processExit, terminationBound).ConfigureAwait(false)
                != processExit)
            {
                ObserveFault(standardOutput);
                ObserveFault(standardError);
                return new SignToolProcessOutcome(
                    Started: true,
                    TimedOut: timedOut,
                    Cancelled: cancelled,
                    TerminationFailed: true,
                    OutputLimitExceeded: false,
                    ExitCode: -1);
            }
        }

        await processExit.ConfigureAwait(false);
        bool outputLimitExceeded =
            await standardOutput.ConfigureAwait(false)
            || await standardError.ConfigureAwait(false);
        return new SignToolProcessOutcome(
            Started: true,
            TimedOut: timedOut,
            Cancelled: cancelled,
            TerminationFailed: false,
            OutputLimitExceeded: outputLimitExceeded,
            ExitCode: process.ExitCode);
    }

    private static async Task<bool> DrainAsync(
        Stream stream,
        int maximumOutputBytes)
    {
        byte[] buffer = new byte[4096];
        long totalBytes = 0;
        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer).ConfigureAwait(false);
            if (bytesRead is 0)
            {
                return totalBytes > maximumOutputBytes;
            }

            totalBytes = checked(totalBytes + bytesRead);
        }
    }

    private static SignToolProcessOutcome StartFailure()
    {
        return new SignToolProcessOutcome(
            Started: false,
            TimedOut: false,
            Cancelled: false,
            TerminationFailed: false,
            OutputLimitExceeded: false,
            ExitCode: -1);
    }

    private static void ObserveFault(Task task)
    {
        _ = task.ContinueWith(
            completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted
                | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}

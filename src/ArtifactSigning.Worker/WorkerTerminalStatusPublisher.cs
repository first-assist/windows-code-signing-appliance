using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public interface IWorkerTerminalStatusPublisher
{
    bool Publish(WorkerJobRecord job);
}

public sealed class WorkerTerminalStatusPublisher :
    IWorkerTerminalStatusPublisher
{
    private readonly WorkerDirectoryLayout _layout;

    public WorkerTerminalStatusPublisher(
        WorkerDirectoryLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        _layout = layout;
    }

    public bool Publish(WorkerJobRecord job)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (job.State is not (
                RequestState.Signed
                or RequestState.Failed
                or RequestState.Quarantined))
        {
            return false;
        }

        try
        {
            WorkerTerminalStatusV1 status = new(
                job.RequestId,
                job.RequestDigest,
                job.State,
                job.ResultCode.ToString(),
                job.EvidenceDigest,
                job.UpdatedAt);
            byte[] json =
                WorkerTerminalStatusJson.Serialize(status);
            string destination = Path.Combine(
                _layout.GatewayStatusRoot,
                $"{job.RequestId:N}.json");
            string temporary = string.Concat(
                destination,
                ".worker-new");
            if (File.Exists(destination))
            {
                byte[] existing =
                    WorkerDirectFile.ReadBounded(
                        destination,
                        WorkerTerminalStatusJson
                            .MaximumStatusJsonBytes);
                if (!existing.AsSpan().SequenceEqual(json))
                {
                    return false;
                }

                if (File.Exists(temporary))
                {
                    byte[] staged =
                        WorkerDirectFile.ReadBounded(
                            temporary,
                            WorkerTerminalStatusJson
                                .MaximumStatusJsonBytes);
                    if (!staged.AsSpan().SequenceEqual(json))
                    {
                        return false;
                    }

                    File.Delete(temporary);
                }

                return true;
            }

            if (File.Exists(temporary))
            {
                byte[] staged =
                    WorkerDirectFile.ReadBounded(
                        temporary,
                        WorkerTerminalStatusJson
                            .MaximumStatusJsonBytes);
                if (!staged.AsSpan().SequenceEqual(json))
                {
                    return false;
                }

                File.Move(temporary, destination);
                return true;
            }

            using (FileStream output = new(
                       temporary,
                       new FileStreamOptions
                       {
                           Mode = FileMode.CreateNew,
                           Access = FileAccess.Write,
                           Share = FileShare.None,
                           BufferSize = 4096,
                           Options = FileOptions.WriteThrough,
                       }))
            {
                output.Write(json);
                output.Flush(flushToDisk: true);
            }

            File.Move(temporary, destination);
            return true;
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or ArgumentException
                or NotSupportedException)
        {
            return false;
        }
    }
}

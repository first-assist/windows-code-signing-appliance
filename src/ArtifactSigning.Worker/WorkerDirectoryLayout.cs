namespace ArtifactSigning.Worker;

public sealed class WorkerDirectoryLayout
{
    public WorkerDirectoryLayout(string basePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        if (!Path.IsPathFullyQualified(basePath))
        {
            throw new ArgumentException(
                "Worker state root must be a fully qualified path.",
                nameof(basePath));
        }

        BasePath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(basePath));
        StateRoot = Path.Combine(BasePath, "worker-state");
        InboxRoot = Path.Combine(BasePath, "inbox");
        ReadyInboxRoot = Path.Combine(InboxRoot, "ready");
        WorkRoot = Path.Combine(BasePath, "work");
        OutputRoot = Path.Combine(BasePath, "output");
        QuarantineRoot = Path.Combine(BasePath, "quarantine");
        GatewayStatusRoot = Path.Combine(BasePath, "status");
        DatabasePath = Path.Combine(StateRoot, "worker.db");
    }

    public string BasePath { get; }

    public string StateRoot { get; }

    public string InboxRoot { get; }

    public string ReadyInboxRoot { get; }

    public string WorkRoot { get; }

    public string OutputRoot { get; }

    public string QuarantineRoot { get; }

    public string GatewayStatusRoot { get; }

    public string DatabasePath { get; }

    public string GetWorkDirectory(Guid requestId)
    {
        return GetJobDirectory(WorkRoot, requestId);
    }

    public string GetReadyInboxDirectory(Guid requestId)
    {
        return GetJobDirectory(ReadyInboxRoot, requestId);
    }

    public string CreateAdmissionDirectoryPath()
    {
        return Path.Combine(
            WorkRoot,
            $"admission-{Guid.NewGuid():N}");
    }

    public string GetOutputDirectory(Guid requestId)
    {
        return GetJobDirectory(OutputRoot, requestId);
    }

    public string GetQuarantineDirectory(Guid requestId)
    {
        return GetJobDirectory(QuarantineRoot, requestId);
    }

    public void ValidateExistingRoots()
    {
        ValidateDirectDirectory(BasePath);
        ValidateDirectDirectory(StateRoot);
        ValidateDirectDirectory(WorkRoot);
        ValidateDirectDirectory(OutputRoot);
        ValidateDirectDirectory(QuarantineRoot);

        if (File.Exists(DatabasePath))
        {
            FileAttributes attributes = File.GetAttributes(DatabasePath);
            if (attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException(
                    "Worker durable state file is not a direct regular file.");
            }
        }
    }

    public bool TryPublish(Guid requestId)
    {
        string work = GetWorkDirectory(requestId);
        string output = GetOutputDirectory(requestId);
        string quarantine = GetQuarantineDirectory(requestId);
        if (!IsDirectDirectory(work)
            || Directory.Exists(output)
            || Directory.Exists(quarantine))
        {
            return false;
        }

        try
        {
            Directory.Move(work, output);
            return IsDirectDirectory(output);
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

    public bool TryMoveSoleJobDirectoryToQuarantine(Guid requestId)
    {
        string work = GetWorkDirectory(requestId);
        string output = GetOutputDirectory(requestId);
        string quarantine = GetQuarantineDirectory(requestId);
        bool workExists = Directory.Exists(work);
        bool outputExists = Directory.Exists(output);
        bool quarantineExists = Directory.Exists(quarantine);
        int existingCount =
            (workExists ? 1 : 0)
            + (outputExists ? 1 : 0)
            + (quarantineExists ? 1 : 0);
        if (existingCount != 1)
        {
            return false;
        }

        if (quarantineExists)
        {
            return IsDirectDirectory(quarantine);
        }

        string source = workExists ? work : output;
        if (!IsDirectDirectory(source))
        {
            return false;
        }

        try
        {
            Directory.Move(source, quarantine);
            return IsDirectDirectory(quarantine);
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

    public bool HasDirectWorkDirectory(Guid requestId)
    {
        return IsDirectDirectory(GetWorkDirectory(requestId));
    }

    public bool HasSoleDirectOutputDirectory(Guid requestId)
    {
        string work = GetWorkDirectory(requestId);
        string output = GetOutputDirectory(requestId);
        string quarantine = GetQuarantineDirectory(requestId);
        return IsDirectDirectory(output)
            && !Directory.Exists(work)
            && !File.Exists(work)
            && !Directory.Exists(quarantine)
            && !File.Exists(quarantine);
    }

    private static string GetJobDirectory(string root, Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        return Path.Combine(root, requestId.ToString("N"));
    }

    private static void ValidateDirectDirectory(string path)
    {
        if (!IsDirectDirectory(path))
        {
            throw new InvalidOperationException(
                "Worker storage root is not a direct directory.");
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
}

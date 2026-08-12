namespace ArtifactSigning.Gateway;

public sealed class GatewayDirectoryLayout
{
    public GatewayDirectoryLayout(string basePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        if (!Path.IsPathFullyQualified(basePath))
        {
            throw new ArgumentException(
                "Gateway state root must be fully qualified.",
                nameof(basePath));
        }

        BasePath = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(basePath));
        StateRoot = Path.Combine(BasePath, "gateway-state");
        InboxRoot = Path.Combine(BasePath, "inbox");
        ReceivingRoot = Path.Combine(InboxRoot, "receiving");
        PendingRoot = Path.Combine(InboxRoot, "pending");
        ReadyRoot = Path.Combine(InboxRoot, "ready");
        WorkerStatusRoot = Path.Combine(BasePath, "status");
        OutputRoot = Path.Combine(BasePath, "output");
        DatabasePath = Path.Combine(StateRoot, "gateway.db");
    }

    public string BasePath { get; }

    public string StateRoot { get; }

    public string InboxRoot { get; }

    public string ReceivingRoot { get; }

    public string PendingRoot { get; }

    public string ReadyRoot { get; }

    public string WorkerStatusRoot { get; }

    public string OutputRoot { get; }

    public string DatabasePath { get; }

    public string GetPendingRequestDirectory(Guid requestId)
    {
        return GetRequestDirectory(PendingRoot, requestId);
    }

    public string GetReadyRequestDirectory(Guid requestId)
    {
        return GetRequestDirectory(ReadyRoot, requestId);
    }

    public string CreateReceivingDirectoryPath()
    {
        return Path.Combine(
            ReceivingRoot,
            $"receiving-{Guid.NewGuid():N}");
    }

    public void ValidateExistingRoots()
    {
        ValidateDirectDirectory(BasePath);
        ValidateDirectDirectory(StateRoot);
        ValidateDirectDirectory(InboxRoot);
        ValidateDirectDirectory(ReceivingRoot);
        ValidateDirectDirectory(PendingRoot);
        ValidateDirectDirectory(ReadyRoot);
        ValidateDirectDirectory(WorkerStatusRoot);
        ValidateDirectDirectory(OutputRoot);
        if (File.Exists(DatabasePath))
        {
            FileAttributes attributes = File.GetAttributes(DatabasePath);
            if (attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException(
                    "Gateway durable state is not a direct regular file.");
            }
        }
    }

    private static string GetRequestDirectory(
        string root,
        Guid requestId)
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
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            if (!attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException(
                    "Gateway storage root is not a direct directory.");
            }
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "Gateway storage root is unavailable.",
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                "Gateway storage root is unavailable.",
                exception);
        }
    }
}

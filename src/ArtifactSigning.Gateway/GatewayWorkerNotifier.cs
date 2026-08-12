using System.IO.Pipes;
using System.Text;

namespace ArtifactSigning.Gateway;

public enum GatewayWorkerNotificationError
{
    None,
    WorkerUnavailable,
}

public sealed record GatewayWorkerNotificationResult(
    GatewayWorkerNotificationError Error)
{
    public bool IsSuccess =>
        Error is GatewayWorkerNotificationError.None;
}

public interface IGatewayWorkerNotifier
{
    ValueTask<GatewayWorkerNotificationResult> NotifyAsync(
        Guid requestId,
        CancellationToken cancellationToken);
}

public sealed class GatewayWorkerNotifier :
    IGatewayWorkerNotifier
{
    public const string PipeName = "ArtifactSigningWorkerV1";
    public const int RequestIdMessageBytes = 36;
    public const PipeAccessRights ClientAccessRights =
        PipeAccessRights.WriteData
        | PipeAccessRights.ReadAttributes
        | PipeAccessRights.WriteAttributes
        | PipeAccessRights.WriteExtendedAttributes
        | PipeAccessRights.ReadPermissions
        | PipeAccessRights.Synchronize;
    public static readonly TimeSpan OperationTimeout =
        TimeSpan.FromSeconds(5);

    public async ValueTask<GatewayWorkerNotificationResult>
        NotifyAsync(
            Guid requestId,
            CancellationToken cancellationToken)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        if (!OperatingSystem.IsWindows())
        {
            return Failure();
        }

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(OperationTimeout);
        try
        {
            using NamedPipeClientStream pipe = new(
                ".",
                PipeName,
                ClientAccessRights,
                PipeOptions.Asynchronous
                    | PipeOptions.WriteThrough,
                System.Security.Principal
                    .TokenImpersonationLevel.Anonymous,
                HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token)
                .ConfigureAwait(false);
            byte[] message = Encoding.ASCII.GetBytes(
                requestId.ToString("D"));
            if (message.Length != RequestIdMessageBytes)
            {
                return Failure();
            }

            await pipe.WriteAsync(message, timeout.Token)
                .ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token)
                .ConfigureAwait(false);
            return new GatewayWorkerNotificationResult(
                GatewayWorkerNotificationError.None);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            return Failure();
        }
        catch (IOException)
        {
            return Failure();
        }
        catch (UnauthorizedAccessException)
        {
            return Failure();
        }
    }

    private static GatewayWorkerNotificationResult Failure()
    {
        return new GatewayWorkerNotificationResult(
            GatewayWorkerNotificationError.WorkerUnavailable);
    }
}

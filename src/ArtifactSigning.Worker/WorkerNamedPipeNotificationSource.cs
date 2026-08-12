using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ArtifactSigning.Worker;

public enum WorkerNotificationReadOutcome
{
    Accepted,
    Rejected,
}

public sealed record WorkerNotificationReadResult(
    WorkerNotificationReadOutcome Outcome,
    Guid? RequestId);

public interface IWorkerNotificationSource
{
    ValueTask<WorkerNotificationReadResult> ReadAsync(
        CancellationToken cancellationToken);
}

public sealed class WorkerNamedPipeNotificationSource :
    IWorkerNotificationSource
{
    public const string PipeName = "ArtifactSigningWorkerV1";
    public static readonly TimeSpan ClientMessageTimeout =
        TimeSpan.FromSeconds(5);

    private readonly SecurityIdentifier _workerServiceSid;
    private readonly SecurityIdentifier _gatewayServiceSid;

    public WorkerNamedPipeNotificationSource(
        SecurityIdentifier workerServiceSid,
        SecurityIdentifier gatewayServiceSid)
    {
        ArgumentNullException.ThrowIfNull(workerServiceSid);
        ArgumentNullException.ThrowIfNull(gatewayServiceSid);
        if (workerServiceSid == gatewayServiceSid
            || !IsServiceSid(workerServiceSid)
            || !IsServiceSid(gatewayServiceSid))
        {
            throw new ArgumentException(
                "Worker and Gateway pipe identities must be distinct service identities.");
        }

        _workerServiceSid = workerServiceSid;
        _gatewayServiceSid = gatewayServiceSid;
    }

    public async ValueTask<WorkerNotificationReadResult> ReadAsync(
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Worker notification pipe is Windows-only.");
        }

        using NamedPipeServerStream pipe = CreatePipe();
        await pipe.WaitForConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(ClientMessageTimeout);
        byte[] message =
            new byte[WorkerNotificationProtocol.RequestIdMessageBytes + 1];
        try
        {
            int count = await pipe.ReadAsync(message, timeout.Token)
                .ConfigureAwait(false);
            if (count != WorkerNotificationProtocol.RequestIdMessageBytes
                || !pipe.IsMessageComplete
                || !WorkerNotificationProtocol.TryDecode(
                    message.AsSpan(0, count),
                    out Guid requestId))
            {
                return Rejected();
            }

            return new WorkerNotificationReadResult(
                WorkerNotificationReadOutcome.Accepted,
                requestId);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            return Rejected();
        }
        catch (IOException)
        {
            return Rejected();
        }
    }

    internal static PipeSecurity CreatePipeSecurity(
        SecurityIdentifier workerServiceSid,
        SecurityIdentifier gatewayServiceSid)
    {
        PipeSecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(
                WellKnownSidType.NetworkSid,
                null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(
            workerServiceSid,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            gatewayServiceSid,
            PipeAccessRights.WriteData
                | PipeAccessRights.ReadAttributes
                | PipeAccessRights.WriteAttributes
                | PipeAccessRights.WriteExtendedAttributes
                | PipeAccessRights.ReadPermissions
                | PipeAccessRights.Synchronize,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid,
                null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid,
                null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        return security;
    }

    private NamedPipeServerStream CreatePipe()
    {
        PipeSecurity security = CreatePipeSecurity(
            _workerServiceSid,
            _gatewayServiceSid);
        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Message,
            PipeOptions.Asynchronous
                | PipeOptions.WriteThrough
                | PipeOptions.FirstPipeInstance,
            inBufferSize:
                WorkerNotificationProtocol.RequestIdMessageBytes + 1,
            outBufferSize: 0,
            security,
            HandleInheritability.None,
            (PipeAccessRights)0);
    }

    private static bool IsServiceSid(
        SecurityIdentifier identity)
    {
        return identity.Value.StartsWith(
                "S-1-5-80-",
                StringComparison.Ordinal)
            && identity.Value.Count(character => character is '-') is 8;
    }

    private static WorkerNotificationReadResult Rejected()
    {
        return new WorkerNotificationReadResult(
            WorkerNotificationReadOutcome.Rejected,
            null);
    }
}

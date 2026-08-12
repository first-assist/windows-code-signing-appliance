using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayWorkerNotifierTests
{
    [Fact]
    public void ClientRequestsOnlyWorkerGrantedWriteRights()
    {
        const PipeAccessRights expected =
            PipeAccessRights.WriteData
            | PipeAccessRights.ReadAttributes
            | PipeAccessRights.WriteAttributes
            | PipeAccessRights.WriteExtendedAttributes
            | PipeAccessRights.ReadPermissions
            | PipeAccessRights.Synchronize;

        Assert.Equal(
            expected,
            GatewayWorkerNotifier.ClientAccessRights);
        Assert.False(
            GatewayWorkerNotifier.ClientAccessRights.HasFlag(
                PipeAccessRights.CreateNewInstance));
        Assert.False(
            GatewayWorkerNotifier.ClientAccessRights.HasFlag(
                PipeAccessRights.ReadData));
        Assert.True(
            GatewayWorkerNotifier.ClientAccessRights.HasFlag(
                PipeAccessRights.ReadAttributes));
    }

    [Fact]
    public async Task ExplicitClientRightsConnectWithoutPipeCreationRight()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        SecurityIdentifier currentSid =
            WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        PipeSecurity creationSecurity = CreateProtectedSecurity(
            currentSid,
            PipeAccessRights.FullControl);
        using NamedPipeServerStream server =
            NamedPipeServerStreamAcl.Create(
                GatewayWorkerNotifier.PipeName,
                PipeDirection.In,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Message,
                PipeOptions.Asynchronous
                    | PipeOptions.WriteThrough
                    | PipeOptions.FirstPipeInstance,
                inBufferSize:
                    GatewayWorkerNotifier.RequestIdMessageBytes + 1,
                outBufferSize: 0,
                creationSecurity,
                HandleInheritability.None,
                PipeAccessRights.ChangePermissions);
        server.SetAccessControl(CreateProtectedSecurity(
            currentSid,
            GatewayWorkerNotifier.ClientAccessRights));

        using CancellationTokenSource timeout = new(
            TimeSpan.FromSeconds(10));
        using (NamedPipeClientStream legacyClient = new(
                   ".",
                   GatewayWorkerNotifier.PipeName,
                   PipeDirection.Out,
                   PipeOptions.Asynchronous,
                   TokenImpersonationLevel.Anonymous))
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => legacyClient.ConnectAsync(timeout.Token));
        }

        Guid requestId = Guid.NewGuid();
        GatewayWorkerNotifier notifier = new();
        Task<GatewayWorkerNotificationResult> notification =
            notifier.NotifyAsync(requestId, timeout.Token).AsTask();
        await server.WaitForConnectionAsync(timeout.Token);
        byte[] message =
            new byte[GatewayWorkerNotifier.RequestIdMessageBytes + 1];
        int count = await server.ReadAsync(
            message,
            timeout.Token);
        GatewayWorkerNotificationResult result =
            await notification.ConfigureAwait(true);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            GatewayWorkerNotifier.RequestIdMessageBytes,
            count);
        Assert.True(server.IsMessageComplete);
        Assert.Equal(
            requestId.ToString("D"),
            Encoding.ASCII.GetString(message, 0, count));
    }

    private static PipeSecurity CreateProtectedSecurity(
        SecurityIdentifier identity,
        PipeAccessRights rights)
    {
        PipeSecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            identity,
            rights,
            AccessControlType.Allow));
        return security;
    }
}

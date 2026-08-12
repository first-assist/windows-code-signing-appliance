using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerNamedPipeNotificationSourceTests
{
    [Fact]
    public void RequiresDistinctVirtualServiceIdentities()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        SecurityIdentifier workerSid = CreateWorkerSid();
        SecurityIdentifier gatewaySid = CreateGatewaySid();
        Assert.Throws<ArgumentException>(
            () => new WorkerNamedPipeNotificationSource(
                workerSid,
                workerSid));
        Assert.Throws<ArgumentException>(
            () => new WorkerNamedPipeNotificationSource(
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null),
                gatewaySid));
    }

    [Fact]
    public void PipeAclDeniesNetworkAndAllowsOnlyFixedLocalPrincipals()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        PipeSecurity security =
            WorkerNamedPipeNotificationSource.CreatePipeSecurity(
                CreateWorkerSid(),
                CreateGatewaySid());
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: false,
            typeof(SecurityIdentifier));
        PipeAccessRule[] pipeRules = rules
            .Cast<PipeAccessRule>()
            .ToArray();

        Assert.True(security.AreAccessRulesCanonical);
        Assert.Contains(
            pipeRules,
            rule =>
                rule.IdentityReference
                    == new SecurityIdentifier(
                        WellKnownSidType.NetworkSid,
                        null)
                && rule.AccessControlType is AccessControlType.Deny
                && rule.PipeAccessRights.HasFlag(
                    PipeAccessRights.FullControl));
        Assert.Contains(
            pipeRules,
            rule =>
                rule.IdentityReference == CreateGatewaySid()
                && rule.AccessControlType is AccessControlType.Allow
                && rule.PipeAccessRights
                    == (PipeAccessRights.WriteData
                        | PipeAccessRights.ReadAttributes
                        | PipeAccessRights.WriteAttributes
                        | PipeAccessRights.WriteExtendedAttributes
                        | PipeAccessRights.ReadPermissions
                        | PipeAccessRights.Synchronize));
        Assert.DoesNotContain(
            pipeRules,
            rule =>
                rule.IdentityReference
                    == new SecurityIdentifier(
                        WellKnownSidType.WorldSid,
                        null));
    }

    private static SecurityIdentifier CreateWorkerSid()
    {
        return new SecurityIdentifier(
            "S-1-5-80-100-200-300-400-500");
    }

    private static SecurityIdentifier CreateGatewaySid()
    {
        return new SecurityIdentifier(
            "S-1-5-80-101-201-301-401-501");
    }
}

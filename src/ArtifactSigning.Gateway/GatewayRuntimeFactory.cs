using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using ArtifactSigning.Composition;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public sealed class GatewayInstalledRuntime : IDisposable
{
    internal GatewayInstalledRuntime(
        GatewayServiceConfiguration configuration,
        X509Certificate2 serverCertificate,
        GatewayApiRuntime api,
        GatewayStartupReconciler reconciler)
    {
        Configuration = configuration;
        ServerCertificate = serverCertificate;
        Api = api;
        Reconciler = reconciler;
    }

    public GatewayServiceConfiguration Configuration { get; }

    public X509Certificate2 ServerCertificate { get; }

    public GatewayApiRuntime Api { get; }

    public GatewayStartupReconciler Reconciler { get; }

    public void Dispose()
    {
        ServerCertificate.Dispose();
    }
}

public static class GatewayRuntimeFactory
{
    public static GatewayInstalledRuntime Create(
        GatewayServiceConfiguration configuration)
    {
        return Create(configuration, InstalledProfileSet.Create());
    }

    internal static GatewayInstalledRuntime Create(
        GatewayServiceConfiguration configuration,
        SigningProfilePackageSet profilePackages)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(profilePackages);
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(
                    configuration.ProfileSetSha256),
                System.Text.Encoding.ASCII.GetBytes(
                    profilePackages.PackageSetSha256)))
        {
            throw new InvalidOperationException(
                "The installed Gateway configuration does not match the compiled profile set.");
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Gateway runtime is Windows-only.");
        }

        SecurityIdentifier gatewaySid =
            new(configuration.GatewayServiceSid);
        SecurityIdentifier workerSid =
            new(configuration.WorkerServiceSid);
        ValidateProcessIdentity(gatewaySid, workerSid);
        GatewayDirectoryLayout layout = new(
            GetInstalledStateRoot());
        GatewayInstalledSecurityValidator
            .ValidateStateDirectories(
                layout,
                configuration.GatewayServiceSid,
                configuration.WorkerServiceSid);
        GatewayStateStore stateStore = new(layout);
        SigningProfileRegistry profiles =
            SigningProfileRegistry.FromPackageSet(profilePackages);
        GatewayInstalledAuthorizationPolicy[] policies =
            configuration.AuthorizationPolicies
                .Select(item =>
                    new GatewayInstalledAuthorizationPolicy(
                        item.ProjectId,
                        item.ProfileId,
                        item.ProfileVersion,
                        item.SubmitterClient,
                        GatewayCertificateStore.CreateTrustPolicy(
                            item.SubmitterTrust),
                        item.ApproverClient,
                        GatewayCertificateStore.CreateTrustPolicy(
                            item.ApproverTrust),
                        item.RequireDistinctSubmitterAndApprover))
                .ToArray();
        GatewayAuthorizationRegistry authorization = new(
            policies,
            configuration.Auditors,
            profiles);
        X509Certificate2 serverCertificate =
            GatewayCertificateStore.LoadServerCertificate(
                configuration.ServerCertificateThumbprint);
        try
        {
            GatewayInstalledSecurityValidator
                .ValidateTlsPrivateKeyFile(
                    GatewayCertificateStore
                        .GetPrivateKeyFilePath(
                            serverCertificate),
                    configuration.GatewayServiceSid,
                    configuration.WorkerServiceSid);
            string serverSpki = CertificateIdentity
                .ComputeSubjectPublicKeyInfoSha256(
                    serverCertificate);
            if (policies.Any(item =>
                    string.Equals(
                        item.SubmitterClient
                            .SubjectPublicKeyInfoSha256,
                        serverSpki,
                        StringComparison.Ordinal)
                    || string.Equals(
                        item.ApproverClient
                            .SubjectPublicKeyInfoSha256,
                        serverSpki,
                        StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    "Gateway TLS and authorization identities must be distinct.");
            }

            GatewaySubmissionProcessor submission = new(
                stateStore,
                profiles);
            GatewayReadyRecordAccessController readyRecordAccess =
                new(
                    layout,
                    profiles,
                    gatewaySid,
                    workerSid);
            GatewayApprovalProcessor approval = new(
                stateStore,
                readyRecordAccess);
            GatewayWorkerNotifier notifier = new();
            CmsTrustPolicy receiptTrust =
                GatewayCertificateStore.CreateTrustPolicy(
                    configuration.ReceiptTrust);
            GatewayResultProcessor resultProcessor = new(
                stateStore,
                profiles,
                receiptTrust);
            GatewayAuditAnchorReader auditAnchorReader =
                new(layout, receiptTrust);
            GatewayReadinessProbe readinessProbe = new(
                stateStore,
                auditAnchorReader,
                installedSecurityValidation: () =>
                {
                    GatewayInstalledSecurityValidator
                        .ValidateStateDirectories(
                            layout,
                            configuration.GatewayServiceSid,
                            configuration.WorkerServiceSid);
                    GatewayInstalledSecurityValidator
                        .ValidateTlsPrivateKeyFile(
                            GatewayCertificateStore
                                .GetPrivateKeyFilePath(
                                    serverCertificate),
                            configuration.GatewayServiceSid,
                            configuration.WorkerServiceSid);
                });
            GatewayApiRuntime api = new(
                stateStore,
                authorization,
                profiles,
                submission,
                approval,
                notifier,
                resultProcessor,
                TimeProvider.System,
                auditAnchorReader,
                readinessProbe);
            GatewayStartupReconciler reconciler = new(
                stateStore,
                notifier,
                readyRecordAccess,
                resultProcessor: resultProcessor);
            return new GatewayInstalledRuntime(
                configuration,
                serverCertificate,
                api,
                reconciler);
        }
        catch
        {
            serverCertificate.Dispose();
            throw;
        }
    }

    public static string GetInstalledStateRoot()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The installed Gateway state root is Windows-only.");
        }

        string commonApplicationData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(commonApplicationData)
            || !Path.IsPathFullyQualified(commonApplicationData))
        {
            throw new InvalidOperationException(
                "ProgramData could not be resolved.");
        }

        return Path.Combine(
            commonApplicationData,
            "ArtifactSigning");
    }

    private static void ValidateProcessIdentity(
        SecurityIdentifier gatewaySid,
        SecurityIdentifier workerSid)
    {
        using WindowsIdentity current =
            WindowsIdentity.GetCurrent(
                TokenAccessLevels.Query);
        if (current.User != gatewaySid
            || current.Groups?.Contains(workerSid) is true)
        {
            throw new InvalidOperationException(
                "Gateway process identity does not match installed policy.");
        }
    }
}

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using ArtifactSigning.Composition;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public sealed record WorkerRuntime(
    WorkerStateStore StateStore,
    WorkerJobProcessor Processor,
    WorkerNotificationDispatcher Dispatcher,
    WorkerNamedPipeNotificationSource NotificationSource,
    WorkerServiceCoordinator Coordinator,
    IDisposable? OwnedDependency = null) : IDisposable
{
    public void Dispose()
    {
        OwnedDependency?.Dispose();
    }
}

public static class WorkerRuntimeFactory
{
    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification =
            "The returned WorkerRuntime owns and disposes all runtime resources.")]
    public static WorkerRuntime Create(
        WorkerServiceConfiguration configuration)
    {
        return Create(configuration, InstalledProfileSet.Create());
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification =
            "The returned WorkerRuntime owns and disposes all runtime resources.")]
    internal static WorkerRuntime Create(
        WorkerServiceConfiguration configuration,
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
                "The installed Worker configuration does not match the compiled profile set.");
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Worker runtime is Windows-only.");
        }

        SecurityIdentifier workerSid =
            new(configuration.WorkerServiceSid);
        SecurityIdentifier gatewaySid =
            new(configuration.GatewayServiceSid);
        ValidateProcessIdentity(workerSid, gatewaySid);

        WorkerDirectoryLayout layout =
            new(GetInstalledStateRoot());
        WorkerInstalledSecurityValidator.ValidateStateDirectories(
            layout,
            workerSid,
            gatewaySid);
        WorkerStateStore stateStore = new(layout);
        SigningProfileRegistry profiles =
            SigningProfileRegistry.FromPackageSet(profilePackages);
        WorkerAuthorizationPolicy[] authorizationPolicies =
            configuration.AuthorizationPolicies.Select(item =>
                new WorkerAuthorizationPolicy(
                    item.ProjectId,
                    item.ProfileId,
                    item.ProfileVersion,
                    WorkerCertificateStore.CreateTrustPolicy(
                        item.SubmitterTrust),
                    WorkerCertificateStore.CreateTrustPolicy(
                        item.ApproverTrust),
                    item.RequireDistinctSubmitterAndApprover))
                .ToArray();

        List<X509Certificate2> privateCertificates = [];
        WorkerSigningDependencyProbe? dependencyProbe = null;
        try
        {
            WorkerInstalledSigningPolicy[] signingPolicies =
                configuration.SigningPolicies.Select(item =>
                    CreateSigningPolicy(
                        configuration.Mode,
                        item,
                        workerSid,
                        gatewaySid,
                        privateCertificates)).ToArray();

            X509Certificate2 receiptCertificate =
                WorkerCertificateStore.LoadPrivateMachineCertificate(
                    configuration.Receipt.CertificateThumbprint);
            privateCertificates.Add(receiptCertificate);
            WorkerInstalledSecurityValidator.ValidatePrivateKeyFile(
                WorkerCertificateStore.GetPrivateKeyFilePath(
                    receiptCertificate),
                workerSid,
                gatewaySid);
            WorkerReceiptCmsSigner receiptSigner = new(
                receiptCertificate,
                WorkerCertificateStore.CreateTrustPolicy(
                    configuration.Receipt.Trust));
            dependencyProbe = new WorkerSigningDependencyProbe(
                configuration.SigningPolicies
                    .Where(policy => policy.Provider
                        is WorkerSigningProvider.LocalMachineCertificate)
                    .Select(GetTimestampUrl),
                configuration.SigningPolicies.Any(policy =>
                    policy.Provider
                        is WorkerSigningProvider.MicrosoftArtifactSigning));
            WorkerAuditAnchorPublisher auditPublisher = new(
                stateStore,
                receiptSigner,
                dependencyProbe);
            WorkerReadyRecordOperation operation = new(
                stateStore,
                profiles,
                authorizationPolicies,
                signingPolicies,
                receiptSigner);
            WorkerJobProcessor processor = new(
                stateStore,
                operation,
                operation,
                new WorkerPublishedOutputAccessController(
                    layout,
                    profiles,
                    workerSid,
                    gatewaySid),
                terminalStatusPublisher:
                    new WorkerTerminalStatusPublisher(layout),
                auditAnchorPublisher: auditPublisher);
            WorkerReadyRecordAdmission admission = new(
                stateStore,
                profiles,
                operation);
            WorkerNotificationDispatcher dispatcher = new(
                stateStore,
                processor,
                admission);
            WorkerNamedPipeNotificationSource notificationSource =
                new(workerSid, gatewaySid);
            WorkerServiceCoordinator coordinator = new(
                processor,
                dispatcher,
                notificationSource,
                auditPublisher);

            WorkerRuntimeResources resources = new(
                dependencyProbe,
                privateCertificates);
            WorkerRuntime runtime = new(
                stateStore,
                processor,
                dispatcher,
                notificationSource,
                coordinator,
                resources);
            dependencyProbe = null;
            privateCertificates.Clear();
            return runtime;
        }
        finally
        {
            dependencyProbe?.Dispose();
            foreach (X509Certificate2 certificate
                     in privateCertificates)
            {
                certificate.Dispose();
            }
        }
    }

    internal static void ValidateRetainedSignerIdentity(
        WorkerDeploymentMode mode,
        WorkerLocalMachineCertificateSigningConfiguration configuration,
        X509Certificate2 signerCertificate,
        string signerSubjectPublicKeyInfoSha256)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(signerSubjectPublicKeyInfoSha256);
        if (mode is not WorkerDeploymentMode.RetainedLab)
        {
            return;
        }

        if (!string.Equals(
                CertificateIdentity.ComputeCertificateSha256(signerCertificate),
                configuration.SignerCertificateSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                signerSubjectPublicKeyInfoSha256,
                configuration.SignerSubjectPublicKeyInfoSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Installed signer identity does not match retained lab policy.");
        }
    }

    private static WorkerInstalledSigningPolicy CreateSigningPolicy(
        WorkerDeploymentMode mode,
        WorkerSigningConfiguration configuration,
        SecurityIdentifier workerSid,
        SecurityIdentifier gatewaySid,
        ICollection<X509Certificate2> ownedPrivateCertificates)
    {
        return configuration.ProviderConfiguration switch
        {
            WorkerLocalMachineCertificateSigningConfiguration local =>
                CreateLocalMachineSigningPolicy(
                    mode,
                    configuration,
                    local,
                    workerSid,
                    gatewaySid,
                    ownedPrivateCertificates),
            WorkerMicrosoftArtifactSigningConfiguration microsoft =>
                CreateMicrosoftArtifactSigningPolicy(
                    configuration,
                    microsoft),
            _ => throw new InvalidOperationException(
                "Installed signing provider is not supported."),
        };
    }

    private static WorkerInstalledSigningPolicy
        CreateLocalMachineSigningPolicy(
            WorkerDeploymentMode mode,
            WorkerSigningConfiguration configuration,
            WorkerLocalMachineCertificateSigningConfiguration local,
            SecurityIdentifier workerSid,
            SecurityIdentifier gatewaySid,
            ICollection<X509Certificate2> ownedPrivateCertificates)
    {
        X509Certificate2 signerCertificate =
            WorkerCertificateStore.LoadPrivateMachineCertificate(
                local.SignerCertificateThumbprint);
        ownedPrivateCertificates.Add(signerCertificate);
        string signerSpki = CertificateIdentity
            .ComputeSubjectPublicKeyInfoSha256(signerCertificate);
        ValidateRetainedSignerIdentity(
            mode,
            local,
            signerCertificate,
            signerSpki);
        WorkerInstalledSecurityValidator.ValidatePrivateKeyFile(
            WorkerCertificateStore.GetPrivateKeyFilePath(signerCertificate),
            workerSid,
            gatewaySid);

        InstalledSignToolPolicy signToolPolicy = new(
            local.SignToolPath,
            local.SignToolSha256,
            local.SignToolFileVersion,
            local.SignerCertificateThumbprint,
            local.TimestampUrl,
            TimeSpan.FromSeconds(local.SignToolTimeoutSeconds));
        WorkerAuthenticodeArtifactSigner artifactSigner = new(
            new WindowsAuthenticodeFileVerifier(),
            new HashPinnedSignTool(signToolPolicy),
            new AuthenticodeTrustPolicy(
                local.SignerCertificateThumbprint,
                local.AuthenticodeRevocationPolicy,
                mode is WorkerDeploymentMode.RetainedLab
                    ? WindowsTrustRevocationPolicy.Online
                    : local.AuthenticodeRevocationPolicy,
                local.SignerCertificateSha256,
                local.SignerSubjectPublicKeyInfoSha256));
        return new WorkerInstalledSigningPolicy(
            configuration.SignerPolicyId,
            configuration.TimestampPolicyId,
            WorkerSigningProvider.LocalMachineCertificate,
            local.SignToolSha256,
            local.SignerCertificateThumbprint,
            signerSpki,
            artifactSigner);
    }

    private static WorkerInstalledSigningPolicy
        CreateMicrosoftArtifactSigningPolicy(
            WorkerSigningConfiguration configuration,
            WorkerMicrosoftArtifactSigningConfiguration microsoft)
    {
        MicrosoftArtifactSigningPolicy signingPolicy = new(
            microsoft.Region,
            microsoft.CodeSigningAccountName,
            microsoft.CertificateProfileName,
            microsoft.SignToolPath,
            microsoft.SignToolSha256,
            microsoft.SignToolFileVersion,
            microsoft.DlibPath,
            microsoft.DlibSha256,
            microsoft.DlibFileVersion,
            microsoft.ClientToolsInventorySha256,
            TimeSpan.FromSeconds(microsoft.SignToolTimeoutSeconds));
        AuthenticodeTrustPolicy trustPolicy = AuthenticodeTrustPolicy
            .CreateMicrosoftArtifactSigningPublisher(
                microsoft.ExpectedPublisherSubjectNameSha256,
                microsoft.RequiredPublisherEnhancedKeyUsageOid,
                microsoft.TrustedPublisherRootThumbprints,
                microsoft.AuthenticodeRevocationPolicy,
                microsoft.AuthenticodeRevocationPolicy);
        WorkerMicrosoftArtifactSigningArtifactSigner artifactSigner = new(
            new WindowsAuthenticodeFileVerifier(),
            new HashPinnedMicrosoftArtifactSignTool(signingPolicy),
            signingPolicy,
            trustPolicy);
        return new WorkerInstalledSigningPolicy(
            configuration.SignerPolicyId,
            configuration.TimestampPolicyId,
            WorkerSigningProvider.MicrosoftArtifactSigning,
            microsoft.SignToolSha256,
            signerThumbprint: null,
            signerSpkiSha256: null,
            artifactSigner);
    }

    private static Uri GetTimestampUrl(
        WorkerSigningConfiguration configuration)
    {
        return configuration.ProviderConfiguration switch
        {
            WorkerLocalMachineCertificateSigningConfiguration local =>
                local.TimestampUrl,
            WorkerMicrosoftArtifactSigningConfiguration =>
                throw new InvalidOperationException(
                    "Microsoft Artifact Signing uses the Azure Arc readiness probe."),
            _ => throw new InvalidOperationException(
                "Installed signing provider is not supported."),
        };
    }

    public static string GetInstalledStateRoot()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The installed Worker state root is Windows-only.");
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
        SecurityIdentifier workerSid,
        SecurityIdentifier gatewaySid)
    {
        using WindowsIdentity current =
            WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        if (current.User != workerSid
            || current.Groups?.Contains(gatewaySid) is true)
        {
            throw new InvalidOperationException(
                "Worker process identity does not match installed policy.");
        }
    }

    private sealed class WorkerRuntimeResources :
        IDisposable
    {
        private readonly IDisposable _dependencyProbe;
        private readonly IReadOnlyList<X509Certificate2>
            _certificates;

        internal WorkerRuntimeResources(
            IDisposable dependencyProbe,
            IEnumerable<X509Certificate2> certificates)
        {
            ArgumentNullException.ThrowIfNull(
                dependencyProbe);
            ArgumentNullException.ThrowIfNull(certificates);
            _dependencyProbe = dependencyProbe;
            _certificates = certificates.ToArray();
        }

        public void Dispose()
        {
            _dependencyProbe.Dispose();
            foreach (X509Certificate2 certificate
                     in _certificates)
            {
                certificate.Dispose();
            }
        }
    }
}

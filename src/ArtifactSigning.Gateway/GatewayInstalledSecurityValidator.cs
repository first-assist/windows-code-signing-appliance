using System.Security.AccessControl;
using System.Security.Principal;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Gateway;

public static class GatewayInstalledSecurityValidator
{
    public static void ValidateConfigurationFile(
        string path,
        string gatewayServiceSid,
        string workerServiceSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        SecurityIdentifier gatewaySid =
            new(gatewayServiceSid);
        SecurityIdentifier workerSid =
            new(workerServiceSid);
        string gatewayDirectory = Path.GetDirectoryName(path)
            ?? throw InvalidAcl();
        string installationRoot =
            Path.GetDirectoryName(gatewayDirectory)
            ?? throw InvalidAcl();
        ValidateDirectory(
            installationRoot,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    gatewaySid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    workerSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            gatewayDirectory,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    gatewaySid,
                    FileSystemRights.ReadAndExecute),
            ],
            workerSid);
        ValidateFile(
            path,
            [
                FileRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                FileRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                FileRule(
                    gatewaySid,
                    FileSystemRights.ReadAndExecute),
            ],
            workerSid);
    }

    public static void ValidateStateDirectories(
        GatewayDirectoryLayout layout,
        string gatewayServiceSid,
        string workerServiceSid)
    {
        ArgumentNullException.ThrowIfNull(layout);
        SecurityIdentifier gatewaySid =
            new(gatewayServiceSid);
        SecurityIdentifier workerSid =
            new(workerServiceSid);
        ExpectedRule[] sharedRootRules =
        [
            DirectoryRule(
                SystemSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                AdministratorsSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                gatewaySid,
                FileSystemRights.ReadAndExecute),
            DirectoryRule(
                workerSid,
                FileSystemRights.ReadAndExecute),
        ];
        ExpectedRule[] gatewayPrivateRules =
        [
            DirectoryRule(
                SystemSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                AdministratorsSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                gatewaySid,
                FileSystemRights.FullControl),
        ];
        ValidateDirectory(
            layout.BasePath,
            sharedRootRules,
            disallowedSid: null);
        ValidateDirectory(
            layout.StateRoot,
            gatewayPrivateRules,
            workerSid);
        ValidateDirectory(
            layout.InboxRoot,
            sharedRootRules,
            disallowedSid: null);
        ValidateDirectory(
            layout.ReceivingRoot,
            gatewayPrivateRules,
            workerSid);
        ValidateDirectory(
            layout.PendingRoot,
            gatewayPrivateRules,
            workerSid);
        ValidateDirectory(
            layout.ReadyRoot,
            [
                .. gatewayPrivateRules,
                DirectoryRule(
                    workerSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.WorkerStatusRoot,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    gatewaySid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    workerSid,
                    FileSystemRights.FullControl),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.OutputRoot,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    gatewaySid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    workerSid,
                    FileSystemRights.FullControl),
            ],
            disallowedSid: null);
    }

    public static void ValidateTlsPrivateKeyFile(
        string path,
        string gatewayServiceSid,
        string workerServiceSid)
    {
        SecurityIdentifier gatewaySid =
            new(gatewayServiceSid);
        SecurityIdentifier workerSid =
            new(workerServiceSid);
        ValidateFile(
            path,
            [
                FileRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                FileRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                FileRule(
                    gatewaySid,
                    FileSystemRights.FullControl),
            ],
            workerSid);
    }

    private static void ValidateFile(
        string path,
        IReadOnlyList<ExpectedRule> expectedRules,
        SecurityIdentifier? disallowedSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Gateway ACL validation is Windows-only.");
        }

        WindowsDirectFileReader.ValidateDirectSingleLinkFile(path);
        FileSecurity security = new FileInfo(path)
            .GetAccessControl(
                AccessControlSections.Access
                    | AccessControlSections.Owner);
        ValidateSecurity(
            security,
            expectedRules,
            disallowedSid);
    }

    private static void ValidateDirectory(
        string path,
        IReadOnlyList<ExpectedRule> expectedRules,
        SecurityIdentifier? disallowedSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Gateway ACL validation is Windows-only.");
        }

        DirectoryInfo directory = new(path);
        if (!directory.Attributes.HasFlag(
                FileAttributes.Directory)
            || directory.Attributes.HasFlag(
                FileAttributes.ReparsePoint))
        {
            throw InvalidAcl();
        }

        DirectorySecurity security =
            directory.GetAccessControl(
                AccessControlSections.Access
                    | AccessControlSections.Owner);
        ValidateSecurity(
            security,
            expectedRules,
            disallowedSid);
    }

    private static void ValidateSecurity(
        FileSystemSecurity security,
        IReadOnlyList<ExpectedRule> expectedRules,
        SecurityIdentifier? disallowedSid)
    {
        SecurityIdentifier? owner = security.GetOwner(
            typeof(SecurityIdentifier)) as SecurityIdentifier;
        FileSystemAccessRule[] actualRules =
            security.GetAccessRules(
                    includeExplicit: true,
                    includeInherited: true,
                    typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToArray();
        if (!security.AreAccessRulesProtected
            || owner != SystemSid()
                && owner != AdministratorsSid()
            || actualRules.Length != expectedRules.Count
            || actualRules.Any(rule =>
                rule.IsInherited
                || rule.AccessControlType
                    is not AccessControlType.Allow
                || disallowedSid is not null
                    && rule.IdentityReference == disallowedSid)
            || expectedRules.Any(expected =>
                !actualRules.Any(expected.Matches)))
        {
            throw InvalidAcl();
        }
    }

    private static ExpectedRule FileRule(
        SecurityIdentifier identity,
        FileSystemRights rights)
    {
        FileSystemAccessRule normalized = new(
            identity,
            rights,
            AccessControlType.Allow);
        return new ExpectedRule(
            identity,
            normalized.FileSystemRights,
            InheritanceFlags.None,
            PropagationFlags.None);
    }

    private static ExpectedRule DirectoryRule(
        SecurityIdentifier identity,
        FileSystemRights rights)
    {
        FileSystemAccessRule normalized = new(
            identity,
            rights,
            InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);
        return new ExpectedRule(
            identity,
            normalized.FileSystemRights,
            normalized.InheritanceFlags,
            normalized.PropagationFlags);
    }

    private static SecurityIdentifier SystemSid()
    {
        return new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            null);
    }

    private static SecurityIdentifier AdministratorsSid()
    {
        return new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
    }

    private static InvalidOperationException InvalidAcl()
    {
        return new InvalidOperationException(
            "Installed Gateway access control does not match policy.");
    }

    private sealed record ExpectedRule(
        SecurityIdentifier Identity,
        FileSystemRights Rights,
        InheritanceFlags InheritanceFlags,
        PropagationFlags PropagationFlags)
    {
        internal bool Matches(FileSystemAccessRule actual)
        {
            return actual.IdentityReference == Identity
                && actual.FileSystemRights == Rights
                && actual.InheritanceFlags == InheritanceFlags
                && actual.PropagationFlags == PropagationFlags
                && actual.AccessControlType
                    is AccessControlType.Allow;
        }
    }
}

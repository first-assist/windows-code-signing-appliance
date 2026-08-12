using System.Security.AccessControl;
using System.Security.Principal;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public static class WorkerInstalledSecurityValidator
{
    public static void ValidateConfigurationFile(
        string path,
        SecurityIdentifier workerServiceSid,
        SecurityIdentifier gatewayServiceSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(workerServiceSid);
        ArgumentNullException.ThrowIfNull(gatewayServiceSid);
        string workerDirectory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException(
                "Installed configuration path has no directory.");
        string installationRoot = Path.GetDirectoryName(workerDirectory)
            ?? throw new InvalidOperationException(
                "Installed configuration path has no installation root.");
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
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            workerDirectory,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            gatewayServiceSid);
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
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            gatewayServiceSid);
    }

    public static void ValidateStateDirectories(
        WorkerDirectoryLayout layout,
        SecurityIdentifier workerServiceSid,
        SecurityIdentifier gatewayServiceSid)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(workerServiceSid);
        ArgumentNullException.ThrowIfNull(gatewayServiceSid);

        ExpectedRule[] privateRules =
        [
            DirectoryRule(
                SystemSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                AdministratorsSid(),
                FileSystemRights.FullControl),
            DirectoryRule(
                workerServiceSid,
                FileSystemRights.FullControl),
        ];
        ValidateDirectory(
            layout.BasePath,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.StateRoot,
            privateRules,
            gatewayServiceSid);
        ValidateDirectory(
            layout.InboxRoot,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.ReadyInboxRoot,
            [
                DirectoryRule(
                    SystemSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    AdministratorsSid(),
                    FileSystemRights.FullControl),
                DirectoryRule(
                    workerServiceSid,
                    FileSystemRights.ReadAndExecute),
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.FullControl),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.WorkRoot,
            privateRules,
            gatewayServiceSid);
        ValidateDirectory(
            layout.QuarantineRoot,
            privateRules,
            gatewayServiceSid);
        ValidateDirectory(
            layout.OutputRoot,
            [
                .. privateRules,
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
        ValidateDirectory(
            layout.GatewayStatusRoot,
            [
                .. privateRules,
                DirectoryRule(
                    gatewayServiceSid,
                    FileSystemRights.ReadAndExecute),
            ],
            disallowedSid: null);
    }

    public static void ValidatePrivateKeyFile(
        string path,
        SecurityIdentifier workerServiceSid,
        SecurityIdentifier gatewayServiceSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(workerServiceSid);
        ArgumentNullException.ThrowIfNull(gatewayServiceSid);
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
                    workerServiceSid,
                    FileSystemRights.FullControl),
            ],
            gatewayServiceSid);
    }

    private static void ValidateFile(
        string path,
        IReadOnlyList<ExpectedRule> expectedRules,
        SecurityIdentifier? disallowedSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Installed ACL validation is Windows-only.");
        }

        WindowsDirectFileReader.ValidateDirectSingleLinkFile(path);
        FileInfo file = new(path);
        FileSecurity security = file.GetAccessControl(
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
                "Installed ACL validation is Windows-only.");
        }

        DirectoryInfo directory = new(path);
        FileAttributes attributes = directory.Attributes;
        if (!attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw InvalidAcl();
        }

        DirectorySecurity security = directory.GetAccessControl(
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
        if (!security.AreAccessRulesProtected
            || owner != SystemSid()
                && owner != AdministratorsSid())
        {
            throw InvalidAcl();
        }

        FileSystemAccessRule[] actualRules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        if (actualRules.Length != expectedRules.Count
            || actualRules.Any(rule =>
                rule.IsInherited
                || rule.AccessControlType
                    is not AccessControlType.Allow
                || disallowedSid is not null
                    && rule.IdentityReference == disallowedSid)
            || expectedRules.Any(expected =>
                !actualRules.Any(actual =>
                    expected.Matches(actual))))
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
            "Installed access control does not match policy.");
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

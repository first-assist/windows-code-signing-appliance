using System.Diagnostics.CodeAnalysis;
using System.Security.AccessControl;
using System.Security.Principal;
using ArtifactSigning.Profiles;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Gateway;

public interface IGatewayReadyRecordAccessController
{
    bool PrepareForWorker(GatewayRequestRecord request);
}

public sealed class GatewayReadyRecordAccessController :
    IGatewayReadyRecordAccessController
{
    private readonly GatewayDirectoryLayout _layout;
    private readonly SigningProfileRegistry _profiles;
    private readonly SecurityIdentifier _gatewaySid;
    private readonly SecurityIdentifier _workerSid;
    private readonly SecurityIdentifier _systemSid = new(
        WellKnownSidType.LocalSystemSid,
        null);
    private readonly SecurityIdentifier _administratorsSid = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);

    public GatewayReadyRecordAccessController(
        GatewayDirectoryLayout layout,
        SigningProfileRegistry profiles,
        SecurityIdentifier gatewaySid,
        SecurityIdentifier workerSid)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(gatewaySid);
        ArgumentNullException.ThrowIfNull(workerSid);
        if (gatewaySid == workerSid
            || gatewaySid == _systemSid
            || gatewaySid == _administratorsSid
            || workerSid == _systemSid
            || workerSid == _administratorsSid)
        {
            throw new ArgumentException(
                "Ready-record identities must be distinct service identities.");
        }

        _layout = layout;
        _profiles = profiles;
        _gatewaySid = gatewaySid;
        _workerSid = workerSid;
    }

    public bool PrepareForWorker(GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            ISigningProfile? profile = _profiles.Resolve(
                request.ProfileId,
                request.ProfileVersion);
            if (profile is null)
            {
                return false;
            }

            string ready = _layout.GetReadyRequestDirectory(
                request.RequestId);
            string bundle = Path.Combine(
                ready,
                GatewaySubmissionProcessor.BundleDirectoryName);
            string[] rootFiles =
            [
                GatewaySubmissionProcessor.RequestJsonFileName,
                GatewaySubmissionProcessor.RequestSignatureFileName,
                GatewayApprovalProcessor.ApprovalSignatureFileName,
            ];
            string[] artifactFiles = profile.Descriptor.Artifacts
                .Select(definition => definition.FileName)
                .ToArray();
            if (!HasExactEntries(
                    ready,
                    [
                        .. rootFiles,
                        GatewaySubmissionProcessor.BundleDirectoryName,
                    ])
                || !HasExactEntries(bundle, artifactFiles))
            {
                return false;
            }

            string[] files =
            [
                .. rootFiles.Select(name => Path.Combine(ready, name)),
                .. artifactFiles.Select(name =>
                    Path.Combine(bundle, name)),
            ];
            foreach (string file in files)
            {
                WindowsDirectFileReader.ValidateDirectSingleLinkFile(
                    file);
            }

            SetExactFileRules(files);
            SetExactDirectoryRules(bundle);
            SetExactDirectoryRules(ready);

            if (!HasExactEntries(
                    ready,
                    [
                        .. rootFiles,
                        GatewaySubmissionProcessor.BundleDirectoryName,
                    ])
                || !HasExactEntries(bundle, artifactFiles))
            {
                return false;
            }

            foreach (string file in files)
            {
                WindowsDirectFileReader.ValidateDirectSingleLinkFile(
                    file);
                if (!HasExactFileRules(file))
                {
                    return false;
                }
            }

            return HasExactDirectoryRules(bundle)
                && HasExactDirectoryRules(ready);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }

    [SuppressMessage(
        "Security",
        "CA3003:Review code for file path injection vulnerabilities",
        Justification =
            "The private caller derives every path from the validated UUID layout and compiled profile inventory, then verifies the exact direct tree before ACL mutation.")]
    private void SetExactFileRules(IEnumerable<string> paths)
    {
        foreach (string path in paths)
        {
            FileSecurity security = new();
            security.SetAccessRuleProtection(
                isProtected: true,
                preserveInheritance: false);
            AddExactRules(security, directory: false);
            new FileInfo(path).SetAccessControl(security);
        }
    }

    private void SetExactDirectoryRules(string path)
    {
        if (!IsDirectDirectory(path))
        {
            throw new InvalidDataException(
                "Ready-record directory is invalid.");
        }

        DirectorySecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        AddExactRules(security, directory: true);
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private void AddExactRules(
        FileSystemSecurity security,
        bool directory)
    {
        security.AddAccessRule(CreateRule(
            _systemSid,
            FileSystemRights.FullControl,
            directory));
        security.AddAccessRule(CreateRule(
            _administratorsSid,
            FileSystemRights.FullControl,
            directory));
        security.AddAccessRule(CreateRule(
            _gatewaySid,
            FileSystemRights.FullControl,
            directory));
        security.AddAccessRule(CreateRule(
            _workerSid,
            FileSystemRights.ReadAndExecute,
            directory));
    }

    [SuppressMessage(
        "Security",
        "CA3003:Review code for file path injection vulnerabilities",
        Justification =
            "The private caller derives every path from the validated UUID layout and compiled profile inventory, then revalidates each direct single-link file.")]
    private bool HasExactFileRules(string path)
    {
        FileSecurity security = new FileInfo(path)
            .GetAccessControl(
                AccessControlSections.Access
                    | AccessControlSections.Owner);
        return HasExactRules(security, directory: false);
    }

    private bool HasExactDirectoryRules(string path)
    {
        if (!IsDirectDirectory(path))
        {
            return false;
        }

        DirectorySecurity security = new DirectoryInfo(path)
            .GetAccessControl(
                AccessControlSections.Access
                    | AccessControlSections.Owner);
        return HasExactRules(security, directory: true);
    }

    private bool HasExactRules(
        FileSystemSecurity security,
        bool directory)
    {
        SecurityIdentifier? owner = security.GetOwner(
            typeof(SecurityIdentifier)) as SecurityIdentifier;
        FileSystemAccessRule[] actual = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        FileSystemAccessRule[] expected =
        [
            CreateRule(
                _systemSid,
                FileSystemRights.FullControl,
                directory),
            CreateRule(
                _administratorsSid,
                FileSystemRights.FullControl,
                directory),
            CreateRule(
                _gatewaySid,
                FileSystemRights.FullControl,
                directory),
            CreateRule(
                _workerSid,
                FileSystemRights.ReadAndExecute,
                directory),
        ];
        return security.AreAccessRulesProtected
            && owner is not null
            && (owner == _systemSid
                || owner == _administratorsSid
                || owner == _gatewaySid)
            && actual.Length == expected.Length
            && actual.All(rule =>
                !rule.IsInherited
                && rule.AccessControlType
                    is AccessControlType.Allow)
            && expected.All(expectedRule =>
                actual.Count(actualRule =>
                    RuleMatches(expectedRule, actualRule)) is 1);
    }

    private static FileSystemAccessRule CreateRule(
        SecurityIdentifier sid,
        FileSystemRights rights,
        bool directory)
    {
        return directory
            ? new FileSystemAccessRule(
                sid,
                rights,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow)
            : new FileSystemAccessRule(
                sid,
                rights,
                AccessControlType.Allow);
    }

    private static bool RuleMatches(
        FileSystemAccessRule expected,
        FileSystemAccessRule actual)
    {
        return actual.IdentityReference
                == expected.IdentityReference
            && actual.FileSystemRights
                == expected.FileSystemRights
            && actual.InheritanceFlags
                == expected.InheritanceFlags
            && actual.PropagationFlags
                == expected.PropagationFlags
            && actual.AccessControlType
                == expected.AccessControlType;
    }

    private static bool HasExactEntries(
        string directory,
        IEnumerable<string> expectedEntries)
    {
        if (!IsDirectDirectory(directory))
        {
            return false;
        }

        HashSet<string> expected = expectedEntries.ToHashSet(
            StringComparer.Ordinal);
        string?[] actual = Directory
            .EnumerateFileSystemEntries(directory)
            .Select(Path.GetFileName)
            .ToArray();
        return actual.Length == expected.Count
            && actual.All(name =>
                name is not null && expected.Contains(name));
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

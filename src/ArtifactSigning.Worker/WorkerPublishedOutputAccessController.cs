using System.Diagnostics.CodeAnalysis;
using System.Security.AccessControl;
using System.Security.Principal;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public interface IWorkerOutputPublisher
{
    bool TryPublish(WorkerJobRecord signingJob);
}

public sealed class WorkerPublishedOutputAccessController :
    IWorkerOutputPublisher
{
    private readonly WorkerDirectoryLayout _layout;
    private readonly SigningProfileRegistry _profiles;
    private readonly SecurityIdentifier _workerSid;
    private readonly SecurityIdentifier _gatewaySid;
    private readonly SecurityIdentifier _systemSid = new(
        WellKnownSidType.LocalSystemSid,
        null);
    private readonly SecurityIdentifier _administratorsSid = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);

    public WorkerPublishedOutputAccessController(
        WorkerDirectoryLayout layout,
        SigningProfileRegistry profiles,
        SecurityIdentifier workerSid,
        SecurityIdentifier gatewaySid)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(workerSid);
        ArgumentNullException.ThrowIfNull(gatewaySid);
        if (workerSid == gatewaySid
            || workerSid == _systemSid
            || workerSid == _administratorsSid
            || gatewaySid == _systemSid
            || gatewaySid == _administratorsSid)
        {
            throw new ArgumentException(
                "Published-output identities must be distinct service identities.");
        }

        _layout = layout;
        _profiles = profiles;
        _workerSid = workerSid;
        _gatewaySid = gatewaySid;
    }

    public bool TryPublish(WorkerJobRecord signingJob)
    {
        ArgumentNullException.ThrowIfNull(signingJob);
        if (!OperatingSystem.IsWindows()
            || signingJob.State is not (
                RequestState.Signing or RequestState.Signed))
        {
            return false;
        }

        if (signingJob.State is RequestState.Signing)
        {
            if (!_layout.TryPublish(signingJob.RequestId))
            {
                return false;
            }
        }
        else if (!_layout.HasSoleDirectOutputDirectory(
                     signingJob.RequestId))
        {
            return false;
        }

        try
        {
            string output = _layout.GetOutputDirectory(
                signingJob.RequestId);
            string bundle = Path.Combine(
                output,
                WorkerReadyRecordOperation.BundleDirectoryName);
            string receiptJsonPath = Path.Combine(
                output,
                WorkerReadyRecordOperation.ReceiptJsonFileName);
            string receiptSignaturePath = Path.Combine(
                output,
                WorkerReadyRecordOperation
                    .ReceiptSignatureFileName);
            if (!HasExactEntries(
                    output,
                    [
                        WorkerReadyRecordOperation.ReceiptJsonFileName,
                        WorkerReadyRecordOperation
                            .ReceiptSignatureFileName,
                        WorkerReadyRecordOperation.BundleDirectoryName,
                    ]))
            {
                return false;
            }

            byte[] receiptJson = WindowsDirectFileReader.ReadAllBytes(
                receiptJsonPath,
                ArtifactSigningReceiptJsonSerializer
                    .MaximumReceiptJsonBytes);
            ReceiptJsonParseResult parsed =
                ArtifactSigningReceiptJsonParser.Parse(receiptJson);
            if (!parsed.IsSuccess
                || parsed.Receipt is null
                || parsed.Receipt.RequestId != signingJob.RequestId
                || !FixedDigestEquals(
                    parsed.Receipt.RequestDigest,
                    signingJob.RequestDigest))
            {
                return false;
            }

            ISigningProfile? profile = _profiles.Resolve(
                parsed.Receipt.ProfileId,
                parsed.Receipt.ProfileVersion);
            if (profile is null)
            {
                return false;
            }

            SigningProfileArtifactDefinition[] resultDefinitions =
                profile.Descriptor.Artifacts
                    .Where(item => item.Kind is not
                        SigningProfileArtifactKind.JsonBuildEvidence)
                    .ToArray();
            if (!HasExactEntries(
                    bundle,
                    resultDefinitions.Select(item => item.FileName)))
            {
                return false;
            }

            string[] files =
            [
                receiptJsonPath,
                receiptSignaturePath,
                .. resultDefinitions.Select(item =>
                    Path.Combine(bundle, item.FileName)),
            ];
            foreach (string file in files)
            {
                WindowsDirectFileReader.ValidateDirectSingleLinkFile(
                    file);
            }

            SetExactFileRules(files);
            SetExactDirectoryRules(bundle);
            SetExactDirectoryRules(output);

            if (!HasExactEntries(
                    output,
                    [
                        WorkerReadyRecordOperation.ReceiptJsonFileName,
                        WorkerReadyRecordOperation
                            .ReceiptSignatureFileName,
                        WorkerReadyRecordOperation.BundleDirectoryName,
                    ])
                || !HasExactEntries(
                    bundle,
                    resultDefinitions.Select(item => item.FileName)))
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
                && HasExactDirectoryRules(output);
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
                "Published-output directory is invalid.");
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
            _workerSid,
            FileSystemRights.FullControl,
            directory));
        security.AddAccessRule(CreateRule(
            _gatewaySid,
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
                _workerSid,
                FileSystemRights.FullControl,
                directory),
            CreateRule(
                _gatewaySid,
                FileSystemRights.ReadAndExecute,
                directory),
        ];
        return security.AreAccessRulesProtected
            && owner is not null
            && (owner == _systemSid
                || owner == _administratorsSid
                || owner == _workerSid)
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

    private static bool FixedDigestEquals(
        string left,
        string right)
    {
        return left.Length == right.Length
            && System.Security.Cryptography.CryptographicOperations
                .FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(left),
                    System.Text.Encoding.ASCII.GetBytes(right));
    }
}

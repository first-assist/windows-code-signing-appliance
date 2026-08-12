using System.Diagnostics;
using System.Security.Cryptography;

namespace ArtifactSigning.Windows;

public enum MicrosoftArtifactSigningExecutionError
{
    None,
    PlatformUnsupported,
    SignToolInvalid,
    SignToolHashMismatch,
    SignToolVersionMismatch,
    DlibInvalid,
    DlibHashMismatch,
    DlibVersionMismatch,
    ClientToolsInventoryInvalid,
    ClientToolsInventoryMismatch,
    MetadataInvalid,
    ArtifactInvalid,
    DependencyChanged,
    ProcessStartFailed,
    ProcessTimedOut,
    ProcessCancelled,
    ProcessTerminationFailed,
    ProcessOutputLimitExceeded,
    SigningFailed,
}

public sealed record MicrosoftArtifactSigningExecutionResult(
    MicrosoftArtifactSigningExecutionError Error)
{
    public bool IsSuccess => Error is MicrosoftArtifactSigningExecutionError.None;
}

public sealed class HashPinnedMicrosoftArtifactSignTool
{
    private readonly MicrosoftArtifactSigningPolicy _policy;
    private readonly ISignToolProcessExecutor _processExecutor;

    public HashPinnedMicrosoftArtifactSignTool(
        MicrosoftArtifactSigningPolicy policy)
        : this(policy, new SignToolProcessExecutor())
    {
    }

    internal HashPinnedMicrosoftArtifactSignTool(
        MicrosoftArtifactSigningPolicy policy,
        ISignToolProcessExecutor processExecutor)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(processExecutor);
        _policy = policy;
        _processExecutor = processExecutor;
    }

    public async Task<MicrosoftArtifactSigningExecutionResult> SignAsync(
        string trustedAbsoluteArtifactPath,
        long expectedUnsignedSize,
        string expectedUnsignedSha256,
        string trustedAbsoluteMetadataPath,
        Guid trustedRequestId,
        string trustedArtifactRole,
        CancellationToken cancellationToken = default)
    {
        ValidateArtifactPath(trustedAbsoluteArtifactPath);
        ValidateExpectedArtifact(expectedUnsignedSize, expectedUnsignedSha256);
        ValidateMetadataPath(trustedAbsoluteMetadataPath);
        byte[] expectedMetadata = MicrosoftArtifactSigningMetadataSerializer.Serialize(
            _policy,
            trustedRequestId,
            trustedArtifactRole);
        if (!OperatingSystem.IsWindows())
        {
            return Failure(MicrosoftArtifactSigningExecutionError.PlatformUnsupported);
        }

        MicrosoftArtifactSigningExecutionError dependencyError =
            TryCreateAndValidateDependencies(
                trustedAbsoluteArtifactPath,
                expectedUnsignedSize,
                expectedUnsignedSha256,
                trustedAbsoluteMetadataPath,
                expectedMetadata,
                out ArtifactFileSnapshot? signToolBefore,
                out ArtifactFileSnapshot? dlibBefore,
                out ArtifactFileSnapshot? metadataBefore,
                out string? clientToolsInventoryBefore);
        if (dependencyError is not MicrosoftArtifactSigningExecutionError.None)
        {
            return Failure(dependencyError);
        }

        ProcessStartInfo startInfo = CreateStartInfo(
            _policy,
            trustedAbsoluteArtifactPath,
            trustedAbsoluteMetadataPath);
        SignToolProcessOutcome processResult = await _processExecutor.ExecuteAsync(
                startInfo,
                _policy.Timeout,
                HashPinnedSignTool.MaximumCapturedOutputBytes,
                cancellationToken)
            .ConfigureAwait(false);

        if (!DependenciesUnchanged(
                trustedAbsoluteMetadataPath,
                signToolBefore!,
                dlibBefore!,
                metadataBefore!,
                clientToolsInventoryBefore!))
        {
            return Failure(MicrosoftArtifactSigningExecutionError.DependencyChanged);
        }

        return MapProcessOutcome(processResult);
    }

    internal static ProcessStartInfo CreateStartInfo(
        MicrosoftArtifactSigningPolicy policy,
        string trustedAbsoluteArtifactPath,
        string trustedAbsoluteMetadataPath)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsoluteArtifactPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsoluteMetadataPath);

        ProcessStartInfo startInfo = new()
        {
            FileName = policy.SignToolAbsolutePath,
            WorkingDirectory = Path.GetDirectoryName(policy.SignToolAbsolutePath)!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("sign");
        startInfo.ArgumentList.Add("/fd");
        startInfo.ArgumentList.Add("SHA256");
        startInfo.ArgumentList.Add("/tr");
        startInfo.ArgumentList.Add(policy.TimestampUrl.AbsoluteUri);
        startInfo.ArgumentList.Add("/td");
        startInfo.ArgumentList.Add("SHA256");
        startInfo.ArgumentList.Add("/dlib");
        startInfo.ArgumentList.Add(policy.DlibAbsolutePath);
        startInfo.ArgumentList.Add("/dmdf");
        startInfo.ArgumentList.Add(trustedAbsoluteMetadataPath);
        startInfo.ArgumentList.Add(trustedAbsoluteArtifactPath);

        startInfo.Environment.Clear();
        string systemRoot = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);
        startInfo.Environment["SystemRoot"] = systemRoot;
        if (OperatingSystem.IsWindows())
        {
            string? systemDrive = Path.GetPathRoot(systemRoot)?.TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);
            string programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrWhiteSpace(systemDrive)
                || !Path.IsPathFullyQualified(programData))
            {
                throw new InvalidOperationException(
                    "Fixed Windows process directories are unavailable.");
            }

            // The managed Dlib uses SystemDrive while initializing its .NET
            // host and ProgramData for the Azure Arc HIMDS challenge flow.
            // Supply only the OS-derived values after clearing the inherited
            // environment; neither PATH nor user/developer state is needed.
            startInfo.Environment["SystemDrive"] = systemDrive;
            startInfo.Environment["ProgramData"] = programData;
        }

        string temporaryDirectory = Path.GetDirectoryName(
            trustedAbsoluteMetadataPath)!;
        startInfo.Environment["TEMP"] = temporaryDirectory;
        startInfo.Environment["TMP"] = temporaryDirectory;
        startInfo.Environment[
            AzureArcManagedIdentityEnvironment.IdentityEndpointEnvironmentVariable] =
            policy.AzureArcEnvironment.IdentityEndpoint.OriginalString;
        startInfo.Environment[
            AzureArcManagedIdentityEnvironment.ImdsEndpointEnvironmentVariable] =
            policy.AzureArcEnvironment.ImdsEndpoint.OriginalString;
        return startInfo;
    }

    internal static MicrosoftArtifactSigningExecutionResult MapProcessOutcome(
        SignToolProcessOutcome processResult)
    {
        if (!processResult.Started)
        {
            return Failure(MicrosoftArtifactSigningExecutionError.ProcessStartFailed);
        }

        if (processResult.TerminationFailed)
        {
            return Failure(MicrosoftArtifactSigningExecutionError.ProcessTerminationFailed);
        }

        if (processResult.Cancelled)
        {
            return Failure(MicrosoftArtifactSigningExecutionError.ProcessCancelled);
        }

        if (processResult.TimedOut)
        {
            return Failure(MicrosoftArtifactSigningExecutionError.ProcessTimedOut);
        }

        if (processResult.OutputLimitExceeded)
        {
            return Failure(MicrosoftArtifactSigningExecutionError.ProcessOutputLimitExceeded);
        }

        return processResult.ExitCode is 0
            ? new MicrosoftArtifactSigningExecutionResult(
                MicrosoftArtifactSigningExecutionError.None)
            : Failure(MicrosoftArtifactSigningExecutionError.SigningFailed);
    }

    private MicrosoftArtifactSigningExecutionError TryCreateAndValidateDependencies(
        string artifactPath,
        long expectedArtifactSize,
        string expectedArtifactSha256,
        string metadataPath,
        ReadOnlySpan<byte> expectedMetadata,
        out ArtifactFileSnapshot? signToolSnapshot,
        out ArtifactFileSnapshot? dlibSnapshot,
        out ArtifactFileSnapshot? metadataSnapshot,
        out string? clientToolsInventorySha256)
    {
        signToolSnapshot = null;
        dlibSnapshot = null;
        metadataSnapshot = null;
        clientToolsInventorySha256 = null;

        if (!ArtifactFileSnapshot.TryCreate(
                _policy.SignToolAbsolutePath,
                out signToolSnapshot)
            || signToolSnapshot is null)
        {
            return MicrosoftArtifactSigningExecutionError.SignToolInvalid;
        }

        if (!string.Equals(
                signToolSnapshot.Sha256,
                _policy.SignToolSha256,
                StringComparison.Ordinal))
        {
            return MicrosoftArtifactSigningExecutionError.SignToolHashMismatch;
        }

        if (!HasExpectedVersion(
                _policy.SignToolAbsolutePath,
                _policy.SignToolFileVersion))
        {
            return MicrosoftArtifactSigningExecutionError.SignToolVersionMismatch;
        }

        if (!ArtifactFileSnapshot.TryCreate(
                _policy.DlibAbsolutePath,
                out dlibSnapshot)
            || dlibSnapshot is null)
        {
            return MicrosoftArtifactSigningExecutionError.DlibInvalid;
        }

        if (!string.Equals(
                dlibSnapshot.Sha256,
                _policy.DlibSha256,
                StringComparison.Ordinal))
        {
            return MicrosoftArtifactSigningExecutionError.DlibHashMismatch;
        }

        if (!HasExpectedVersion(_policy.DlibAbsolutePath, _policy.DlibFileVersion))
        {
            return MicrosoftArtifactSigningExecutionError.DlibVersionMismatch;
        }

        string clientToolsDirectory = Path.GetDirectoryName(
            _policy.DlibAbsolutePath)!;
        if (!MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                clientToolsDirectory,
                out clientToolsInventorySha256)
            || clientToolsInventorySha256 is null)
        {
            return MicrosoftArtifactSigningExecutionError
                .ClientToolsInventoryInvalid;
        }

        if (!string.Equals(
                clientToolsInventorySha256,
                _policy.ClientToolsInventorySha256,
                StringComparison.Ordinal))
        {
            return MicrosoftArtifactSigningExecutionError
                .ClientToolsInventoryMismatch;
        }

        if (!ArtifactFileSnapshot.TryCreate(metadataPath, out metadataSnapshot)
            || metadataSnapshot is null
            || metadataSnapshot.Size != expectedMetadata.Length
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(metadataSnapshot.Sha256),
                SHA256.HashData(expectedMetadata)))
        {
            return MicrosoftArtifactSigningExecutionError.MetadataInvalid;
        }

        if (!ArtifactFileSnapshot.TryCreate(
                artifactPath,
                out ArtifactFileSnapshot? artifactSnapshot)
            || artifactSnapshot is null
            || !artifactSnapshot.Matches(expectedArtifactSize, expectedArtifactSha256))
        {
            return MicrosoftArtifactSigningExecutionError.ArtifactInvalid;
        }

        return MicrosoftArtifactSigningExecutionError.None;
    }

    private bool DependenciesUnchanged(
        string metadataPath,
        ArtifactFileSnapshot signToolBefore,
        ArtifactFileSnapshot dlibBefore,
        ArtifactFileSnapshot metadataBefore,
        string clientToolsInventoryBefore)
    {
        return ArtifactFileSnapshot.TryCreate(
                   _policy.SignToolAbsolutePath,
                   out ArtifactFileSnapshot? signToolAfter)
            && signToolAfter is not null
            && signToolBefore == signToolAfter
            && HasExpectedVersion(
                _policy.SignToolAbsolutePath,
                _policy.SignToolFileVersion)
            && ArtifactFileSnapshot.TryCreate(
                   _policy.DlibAbsolutePath,
                   out ArtifactFileSnapshot? dlibAfter)
            && dlibAfter is not null
            && dlibBefore == dlibAfter
            && HasExpectedVersion(_policy.DlibAbsolutePath, _policy.DlibFileVersion)
            && MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                Path.GetDirectoryName(_policy.DlibAbsolutePath)!,
                out string? clientToolsInventoryAfter)
            && string.Equals(
                clientToolsInventoryBefore,
                clientToolsInventoryAfter,
                StringComparison.Ordinal)
            && ArtifactFileSnapshot.TryCreate(
                   metadataPath,
                   out ArtifactFileSnapshot? metadataAfter)
            && metadataAfter is not null
            && metadataBefore == metadataAfter;
    }

    private static bool HasExpectedVersion(string path, Version expectedVersion)
    {
        try
        {
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            Version actual = new(
                version.FileMajorPart,
                version.FileMinorPart,
                version.FileBuildPart,
                version.FilePrivatePart);
            return actual == expectedVersion;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
    }

    private static void ValidateArtifactPath(string trustedAbsoluteArtifactPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsoluteArtifactPath);
        if (!Path.IsPathFullyQualified(trustedAbsoluteArtifactPath)
            || !string.Equals(
                Path.GetExtension(trustedAbsoluteArtifactPath),
                ".exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Worker artifact path must be a fully qualified executable path.",
                nameof(trustedAbsoluteArtifactPath));
        }
    }

    private static void ValidateExpectedArtifact(
        long expectedUnsignedSize,
        string expectedUnsignedSha256)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedUnsignedSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            expectedUnsignedSize,
            ArtifactFileSnapshot.MaximumArtifactBytes);
        ArgumentNullException.ThrowIfNull(expectedUnsignedSha256);
        if (!WindowsContractRules.IsLowerSha256(expectedUnsignedSha256))
        {
            throw new ArgumentException(
                "Expected unsigned digest must be canonical lowercase SHA-256.",
                nameof(expectedUnsignedSha256));
        }
    }

    private static void ValidateMetadataPath(string trustedAbsoluteMetadataPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsoluteMetadataPath);
        if (!WindowsContractRules.IsAbsoluteLeafPath(
                trustedAbsoluteMetadataPath,
                "metadata.json"))
        {
            throw new ArgumentException(
                "Worker metadata path must be absolute and end with metadata.json.",
                nameof(trustedAbsoluteMetadataPath));
        }

    }

    private static MicrosoftArtifactSigningExecutionResult Failure(
        MicrosoftArtifactSigningExecutionError error)
    {
        return new MicrosoftArtifactSigningExecutionResult(error);
    }
}

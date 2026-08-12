using System.Diagnostics;

namespace ArtifactSigning.Windows;

public sealed class HashPinnedSignTool
{
    internal const int MaximumCapturedOutputBytes = 16 * 1024;

    private readonly InstalledSignToolPolicy _policy;
    private readonly ISignToolProcessExecutor _processExecutor;

    public HashPinnedSignTool(InstalledSignToolPolicy policy)
        : this(policy, new SignToolProcessExecutor())
    {
    }

    internal HashPinnedSignTool(
        InstalledSignToolPolicy policy,
        ISignToolProcessExecutor processExecutor)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(processExecutor);
        _policy = policy;
        _processExecutor = processExecutor;
    }

    public async Task<SignToolExecutionResult> SignAsync(
        string trustedAbsoluteArtifactPath,
        long expectedUnsignedSize,
        string expectedUnsignedSha256,
        CancellationToken cancellationToken = default)
    {
        ValidateArtifactPath(trustedAbsoluteArtifactPath);
        ValidateExpectedArtifact(expectedUnsignedSize, expectedUnsignedSha256);
        if (!OperatingSystem.IsWindows())
        {
            return Failure(SignToolExecutionError.PlatformUnsupported);
        }

        if (!ArtifactFileSnapshot.TryCreate(
                _policy.AbsolutePath,
                out ArtifactFileSnapshot? toolBefore)
            || toolBefore is null)
        {
            return Failure(SignToolExecutionError.ToolInvalid);
        }

        if (!string.Equals(
                toolBefore.Sha256,
                _policy.Sha256,
                StringComparison.Ordinal))
        {
            return Failure(SignToolExecutionError.ToolHashMismatch);
        }

        if (!HasExpectedVersion(_policy.AbsolutePath, _policy.FileVersion))
        {
            return Failure(SignToolExecutionError.ToolVersionMismatch);
        }

        if (!ArtifactFileSnapshot.TryCreate(
                trustedAbsoluteArtifactPath,
                out ArtifactFileSnapshot? artifactBefore)
            || artifactBefore is null
            || !artifactBefore.Matches(
                expectedUnsignedSize,
                expectedUnsignedSha256))
        {
            return Failure(SignToolExecutionError.ArtifactInvalid);
        }

        ProcessStartInfo startInfo = CreateStartInfo(
            _policy,
            trustedAbsoluteArtifactPath);
        SignToolProcessOutcome processResult =
            await _processExecutor.ExecuteAsync(
                    startInfo,
                    _policy.Timeout,
                    MaximumCapturedOutputBytes,
                    cancellationToken)
                .ConfigureAwait(false);

        if (!ArtifactFileSnapshot.TryCreate(
                _policy.AbsolutePath,
                out ArtifactFileSnapshot? toolAfter)
            || toolAfter is null
            || toolBefore != toolAfter)
        {
            return Failure(SignToolExecutionError.ToolChanged);
        }

        return MapProcessOutcome(processResult);
    }

    internal static ProcessStartInfo CreateStartInfo(
        InstalledSignToolPolicy policy,
        string trustedAbsoluteArtifactPath)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = policy.AbsolutePath,
            WorkingDirectory = Path.GetDirectoryName(policy.AbsolutePath)!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("sign");
        startInfo.ArgumentList.Add("/fd");
        startInfo.ArgumentList.Add("SHA256");
        startInfo.ArgumentList.Add("/sm");
        startInfo.ArgumentList.Add("/s");
        startInfo.ArgumentList.Add("My");
        startInfo.ArgumentList.Add("/sha1");
        startInfo.ArgumentList.Add(policy.SignerThumbprint);
        startInfo.ArgumentList.Add("/tr");
        startInfo.ArgumentList.Add(policy.TimestampUrl.AbsoluteUri);
        startInfo.ArgumentList.Add("/td");
        startInfo.ArgumentList.Add("SHA256");
        startInfo.ArgumentList.Add(trustedAbsoluteArtifactPath);

        string systemRoot = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);
        string temporaryDirectory = Path.GetTempPath();
        startInfo.Environment.Clear();
        startInfo.Environment["SystemRoot"] = systemRoot;
        startInfo.Environment["TEMP"] = temporaryDirectory;
        startInfo.Environment["TMP"] = temporaryDirectory;
        return startInfo;
    }

    internal static SignToolExecutionResult MapProcessOutcome(
        SignToolProcessOutcome processResult)
    {
        if (!processResult.Started)
        {
            return Failure(SignToolExecutionError.ProcessStartFailed);
        }

        if (processResult.TerminationFailed)
        {
            return Failure(SignToolExecutionError.ProcessTerminationFailed);
        }

        if (processResult.Cancelled)
        {
            return Failure(SignToolExecutionError.ProcessCancelled);
        }

        if (processResult.TimedOut)
        {
            return Failure(SignToolExecutionError.ProcessTimedOut);
        }

        if (processResult.OutputLimitExceeded)
        {
            return Failure(SignToolExecutionError.ProcessOutputLimitExceeded);
        }

        return processResult.ExitCode is 0
            ? new SignToolExecutionResult(SignToolExecutionError.None)
            : Failure(SignToolExecutionError.SigningFailed);
    }

    private static bool HasExpectedVersion(
        string toolPath,
        Version expectedVersion)
    {
        try
        {
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(toolPath);
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

    private static SignToolExecutionResult Failure(SignToolExecutionError error)
    {
        return new SignToolExecutionResult(error);
    }
}

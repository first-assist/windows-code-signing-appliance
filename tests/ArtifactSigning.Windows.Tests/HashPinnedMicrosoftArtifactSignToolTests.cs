using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class HashPinnedMicrosoftArtifactSignToolTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void BuildsOnlyTheFixedManagedProviderSignToolGrammar()
    {
        MicrosoftArtifactSigningPolicy policy = CreatePolicy();
        string artifactPath = OperatingSystem.IsWindows()
            ? @"C:\ProgramData\ArtifactSigning\work\request\example-agent.exe"
            : "/var/lib/artifact-signing/work/request/example-agent.exe";
        string metadataPath = OperatingSystem.IsWindows()
            ? @"C:\ProgramData\ArtifactSigning\work\request\metadata.json"
            : "/var/lib/artifact-signing/work/request/metadata.json";

        ProcessStartInfo startInfo =
            HashPinnedMicrosoftArtifactSignTool.CreateStartInfo(
                policy,
                artifactPath,
                metadataPath);

        Assert.Equal(policy.SignToolAbsolutePath, startInfo.FileName);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.False(startInfo.RedirectStandardInput);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Equal(
            [
                "sign",
                "/fd",
                "SHA256",
                "/tr",
                MicrosoftArtifactSigningPolicy.MicrosoftTimestampUrl,
                "/td",
                "SHA256",
                "/dlib",
                policy.DlibAbsolutePath,
                "/dmdf",
                metadataPath,
                artifactPath,
            ],
            startInfo.ArgumentList);
        Assert.DoesNotContain("/v", startInfo.ArgumentList);
        Assert.DoesNotContain("/debug", startInfo.ArgumentList);
        Assert.DoesNotContain("/sha1", startInfo.ArgumentList);
        Assert.DoesNotContain("/sm", startInfo.ArgumentList);
        Assert.DoesNotContain("PATH", startInfo.Environment.Keys);
        Assert.Equal(
            OperatingSystem.IsWindows() ? 7 : 5,
            startInfo.Environment.Count);
        if (OperatingSystem.IsWindows())
        {
            string systemRoot = Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);
            Assert.Equal(
                Path.GetPathRoot(systemRoot)!.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                startInfo.Environment["SystemDrive"]);
            Assert.Equal(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                startInfo.Environment["ProgramData"]);
        }

        Assert.Equal(
            Path.GetDirectoryName(metadataPath),
            startInfo.Environment["TEMP"]);
        Assert.Equal(
            Path.GetDirectoryName(metadataPath),
            startInfo.Environment["TMP"]);
        Assert.Equal(
            AzureArcManagedIdentityEnvironment.IdentityEndpointValue,
            startInfo.Environment[
                AzureArcManagedIdentityEnvironment.IdentityEndpointEnvironmentVariable]);
        Assert.Equal(
            AzureArcManagedIdentityEnvironment.ImdsEndpointValue,
            startInfo.Environment[
                AzureArcManagedIdentityEnvironment.ImdsEndpointEnvironmentVariable]);
    }

    [Theory]
    [InlineData(false, false, false, false, false, 0, MicrosoftArtifactSigningExecutionError.ProcessStartFailed)]
    [InlineData(true, false, true, false, false, -1, MicrosoftArtifactSigningExecutionError.ProcessCancelled)]
    [InlineData(true, true, false, false, false, -1, MicrosoftArtifactSigningExecutionError.ProcessTimedOut)]
    [InlineData(true, true, false, true, false, -1, MicrosoftArtifactSigningExecutionError.ProcessTerminationFailed)]
    [InlineData(true, false, false, false, true, 0, MicrosoftArtifactSigningExecutionError.ProcessOutputLimitExceeded)]
    [InlineData(true, false, false, false, false, 1, MicrosoftArtifactSigningExecutionError.SigningFailed)]
    [InlineData(true, false, false, false, false, 0, MicrosoftArtifactSigningExecutionError.None)]
    public void MapsOnlyBoundedProcessOutcomes(
        bool started,
        bool timedOut,
        bool cancelled,
        bool terminationFailed,
        bool outputLimitExceeded,
        int exitCode,
        MicrosoftArtifactSigningExecutionError expected)
    {
        MicrosoftArtifactSigningExecutionResult result =
            HashPinnedMicrosoftArtifactSignTool.MapProcessOutcome(
                new SignToolProcessOutcome(
                    started,
                    timedOut,
                    cancelled,
                    terminationFailed,
                    outputLimitExceeded,
                    exitCode));

        Assert.Equal(expected, result.Error);
        Assert.Equal(expected is MicrosoftArtifactSigningExecutionError.None, result.IsSuccess);
    }

    [Fact]
    public async Task RejectsManagedSigningOnUnsupportedPlatform()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        byte[] artifact = [0x4d, 0x5a, 0x00, 0x00];
        MicrosoftArtifactSigningExecutionResult result =
            await new HashPinnedMicrosoftArtifactSignTool(CreatePolicy()).SignAsync(
                "/var/lib/artifact-signing/work/request/example-agent.exe",
                artifact.Length,
                Convert.ToHexStringLower(SHA256.HashData(artifact)),
                "/var/lib/artifact-signing/work/request/metadata.json",
                Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                "Agent",
                TestContext.Current.CancellationToken);

        Assert.Equal(
            MicrosoftArtifactSigningExecutionError.PlatformUnsupported,
            result.Error);
    }

    [Fact]
    public async Task AllowsTheSigningProcessToReplaceUnsignedArtifactBytesOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-managed-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        string toolsDirectory = Path.Combine(temporaryDirectory, "tools");
        string workDirectory = Path.Combine(temporaryDirectory, "work");
        Directory.CreateDirectory(toolsDirectory);
        Directory.CreateDirectory(workDirectory);
        string toolPath = Path.Combine(toolsDirectory, "signtool.exe");
        string dlibPath = Path.Combine(
            toolsDirectory,
            "Azure.CodeSigning.Dlib.dll");
        string artifactPath = Path.Combine(workDirectory, "example-agent.exe");
        string metadataPath = Path.Combine(workDirectory, "metadata.json");
        try
        {
            string systemWhere = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "where.exe");
            File.Copy(systemWhere, toolPath);
            File.Copy(systemWhere, dlibPath);
            byte[] artifact = [0x4d, 0x5a, 0x00, 0x00];
            await File.WriteAllBytesAsync(
                artifactPath,
                artifact,
                TestContext.Current.CancellationToken);

            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(toolPath);
            Version version = new(
                versionInfo.FileMajorPart,
                versionInfo.FileMinorPart,
                versionInfo.FileBuildPart,
                versionInfo.FilePrivatePart);
            string toolDigest = await HashFileAsync(toolPath);
            string dlibDigest = await HashFileAsync(dlibPath);
            Assert.True(
                MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                    toolsDirectory,
                    out string? inventoryDigest));
            MicrosoftArtifactSigningPolicy policy = new(
                MicrosoftArtifactSigningRegion.JapanEast,
                "exampleartifactsigning",
                "Example-PublicTrust",
                toolPath,
                toolDigest,
                version,
                dlibPath,
                dlibDigest,
                version,
                inventoryDigest!,
                TimeSpan.FromSeconds(5));
            Guid requestId = Guid.Parse(
                "018f84a7-2f4c-7d8e-a123-123456789abc");
            await File.WriteAllBytesAsync(
                metadataPath,
                MicrosoftArtifactSigningMetadataSerializer.Serialize(
                    policy,
                    requestId,
                    "Agent"),
                TestContext.Current.CancellationToken);

            HashPinnedMicrosoftArtifactSignTool runner = new(
                policy,
                new MutatingSuccessProcessExecutor());
            MicrosoftArtifactSigningExecutionResult result = await runner.SignAsync(
                artifactPath,
                artifact.Length,
                Convert.ToHexStringLower(SHA256.HashData(artifact)),
                metadataPath,
                requestId,
                "Agent",
                TestContext.Current.CancellationToken);

            Assert.True(result.IsSuccess);
            Assert.Equal(artifact.Length + 1, new FileInfo(artifactPath).Length);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static async Task<string> HashFileAsync(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexStringLower(
            await SHA256.HashDataAsync(
                stream,
                TestContext.Current.CancellationToken)
                .ConfigureAwait(false));
    }

    private sealed class MutatingSuccessProcessExecutor : ISignToolProcessExecutor
    {
        public async Task<SignToolProcessOutcome> ExecuteAsync(
            ProcessStartInfo startInfo,
            TimeSpan timeout,
            int maximumOutputBytes,
            CancellationToken cancellationToken)
        {
            _ = timeout;
            _ = maximumOutputBytes;
            string artifactPath = startInfo.ArgumentList[^1];
            using FileStream stream = new(
                artifactPath,
                FileMode.Append,
                FileAccess.Write,
                FileShare.None);
            await stream.WriteAsync(new byte[] { 0x01 }, cancellationToken)
                .ConfigureAwait(false);
            return new SignToolProcessOutcome(
                Started: true,
                TimedOut: false,
                Cancelled: false,
                TerminationFailed: false,
                OutputLimitExceeded: false,
                ExitCode: 0);
        }
    }

    private static MicrosoftArtifactSigningPolicy CreatePolicy()
    {
        return new MicrosoftArtifactSigningPolicy(
            MicrosoftArtifactSigningRegion.JapanEast,
            "exampleartifactsigning",
            "Example-PublicTrust",
            MicrosoftArtifactSigningPolicyTests.GetSignToolPath(),
            Sha256,
            new Version(10, 0, 26100, 4188),
            MicrosoftArtifactSigningPolicyTests.GetDlibPath(),
            Sha256,
            new Version(1, 2, 3, 4),
            Sha256,
            TimeSpan.FromSeconds(120));
    }
}

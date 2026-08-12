using System.Diagnostics;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class HashPinnedSignToolTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Thumbprint =
        "0123456789ABCDEF0123456789ABCDEF01234567";

    [Fact]
    public void BuildsOnlyTheFixedSignToolGrammar()
    {
        InstalledSignToolPolicy policy = CreatePolicy();
        string artifactPath = OperatingSystem.IsWindows()
            ? @"C:\ProgramData\ArtifactSigning\work\request\example-agent.exe"
            : "/var/lib/artifact-signing/work/request/example-agent.exe";

        ProcessStartInfo startInfo = HashPinnedSignTool.CreateStartInfo(
            policy,
            artifactPath);

        Assert.Equal(policy.AbsolutePath, startInfo.FileName);
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
                "/sm",
                "/s",
                "My",
                "/sha1",
                Thumbprint,
                "/tr",
                "https://timestamp.example.invalid/rfc3161",
                "/td",
                "SHA256",
                artifactPath,
            ],
            startInfo.ArgumentList);
        Assert.DoesNotContain("PATH", startInfo.Environment.Keys);
        Assert.Equal(3, startInfo.Environment.Count);
    }

    [Theory]
    [InlineData(false, false, false, false, false, 0, SignToolExecutionError.ProcessStartFailed)]
    [InlineData(true, false, true, false, false, -1, SignToolExecutionError.ProcessCancelled)]
    [InlineData(true, true, false, false, false, -1, SignToolExecutionError.ProcessTimedOut)]
    [InlineData(true, true, false, true, false, -1, SignToolExecutionError.ProcessTerminationFailed)]
    [InlineData(true, false, false, false, true, 0, SignToolExecutionError.ProcessOutputLimitExceeded)]
    [InlineData(true, false, false, false, false, 1, SignToolExecutionError.SigningFailed)]
    [InlineData(true, false, false, false, false, 2, SignToolExecutionError.SigningFailed)]
    [InlineData(true, false, false, false, false, 0, SignToolExecutionError.None)]
    public void MapsOnlyBoundedProcessOutcomes(
        bool started,
        bool timedOut,
        bool cancelled,
        bool terminationFailed,
        bool outputLimitExceeded,
        int exitCode,
        SignToolExecutionError expected)
    {
        SignToolExecutionResult result = HashPinnedSignTool.MapProcessOutcome(
            new SignToolProcessOutcome(
                started,
                timedOut,
                cancelled,
                terminationFailed,
                outputLimitExceeded,
                exitCode));

        Assert.Equal(expected, result.Error);
        Assert.Equal(expected is SignToolExecutionError.None, result.IsSuccess);
    }

    private static InstalledSignToolPolicy CreatePolicy()
    {
        string toolPath = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\signtool.exe"
            : "/opt/windows-sdk/signtool.exe";
        return new InstalledSignToolPolicy(
            toolPath,
            Sha256,
            new Version(10, 0, 26100, 4188),
            Thumbprint,
            new Uri("https://timestamp.example.invalid/rfc3161"),
            TimeSpan.FromSeconds(120));
    }
}

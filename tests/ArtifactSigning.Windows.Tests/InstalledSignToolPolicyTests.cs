using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class InstalledSignToolPolicyTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Thumbprint =
        "0123456789ABCDEF0123456789ABCDEF01234567";

    [Fact]
    public void AcceptsClosedInstalledPolicy()
    {
        InstalledSignToolPolicy policy = CreatePolicy();

        Assert.Equal(GetToolPath(), policy.AbsolutePath);
        Assert.Equal(Sha256, policy.Sha256);
        Assert.Equal(new Version(10, 0, 26100, 4188), policy.FileVersion);
        Assert.Equal(Thumbprint, policy.SignerThumbprint);
        Assert.Equal(
            "https://timestamp.example.invalid/rfc3161",
            policy.TimestampUrl.AbsoluteUri);
        Assert.Equal(TimeSpan.FromSeconds(120), policy.Timeout);
    }

    [Theory]
    [InlineData("signtool.exe")]
    [InlineData("/opt/windows-sdk/not-signtool.exe")]
    public void RejectsUnpinnedToolPath(string path)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(absolutePath: path));
    }

    [Fact]
    public void RejectsShortToolVersion()
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(fileVersion: new Version(10, 0)));
    }

    [Theory]
    [InlineData("ftp://timestamp.example.invalid/rfc3161")]
    [InlineData("https://user@timestamp.example.invalid/rfc3161")]
    [InlineData("https://timestamp.example.invalid/rfc3161?mode=test")]
    [InlineData("https://timestamp.example.invalid/rfc3161#fragment")]
    public void RejectsUnsafeTimestampUrl(string value)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(timestampUrl: new Uri(value)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    public void RejectsTimeoutOutsideClosedRange(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreatePolicy(timeout: TimeSpan.FromSeconds(seconds)));
    }

    private static InstalledSignToolPolicy CreatePolicy(
        string? absolutePath = null,
        Version? fileVersion = null,
        Uri? timestampUrl = null,
        TimeSpan? timeout = null)
    {
        return new InstalledSignToolPolicy(
            absolutePath ?? GetToolPath(),
            Sha256,
            fileVersion ?? new Version(10, 0, 26100, 4188),
            Thumbprint,
            timestampUrl
                ?? new Uri("https://timestamp.example.invalid/rfc3161"),
            timeout ?? TimeSpan.FromSeconds(120));
    }

    private static string GetToolPath()
    {
        return OperatingSystem.IsWindows()
            ? @"C:\Program Files (x86)\Windows Kits\10\bin\signtool.exe"
            : "/opt/windows-sdk/signtool.exe";
    }
}

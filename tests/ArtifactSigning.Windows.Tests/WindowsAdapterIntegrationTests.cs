using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class WindowsAdapterIntegrationTests
{
    private const string Thumbprint =
        "0123456789ABCDEF0123456789ABCDEF01234567";

    [Fact]
    public void UnsignedInspectionUsesWindowsCatalogApiWhenAvailable()
    {
        WindowsAuthenticodeFileVerifier verifier = new();
        byte[] portableExecutable = OperatingSystem.IsWindows()
            ? File.ReadAllBytes(typeof(WindowsAdapterIntegrationTests).Assembly.Location)
            : [0x4d, 0x5a, 0x00, 0x00];
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(portableExecutable));

        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                AuthenticodeVerificationError.PlatformUnsupported,
                verifier.VerifyUnsigned(
                    "/tmp/disposable-unsigned.exe",
                    portableExecutable.Length,
                    digest));
            return;
        }

        string temporaryFile = Path.Combine(
            Path.GetTempPath(),
            $"{Guid.NewGuid():D}.exe");
        try
        {
            File.WriteAllBytes(temporaryFile, portableExecutable);

            AuthenticodeVerificationError result = verifier.VerifyUnsigned(
                temporaryFile,
                portableExecutable.Length,
                digest);

            Assert.Equal(AuthenticodeVerificationError.None, result);
        }
        finally
        {
            File.Delete(temporaryFile);
        }
    }

    [Fact]
    public async Task SignToolRunnerExecutesPinnedBinaryDirectlyWhenAvailable()
    {
        if (!OperatingSystem.IsWindows())
        {
            InstalledSignToolPolicy unsupportedPolicy = new(
                "/opt/windows-sdk/signtool.exe",
                new string('0', 64),
                new Version(1, 0, 0, 0),
                Thumbprint,
                new Uri("https://timestamp.example.invalid/rfc3161"),
                TimeSpan.FromSeconds(5));
            SignToolExecutionResult unsupported =
                await new HashPinnedSignTool(unsupportedPolicy)
                    .SignAsync(
                        "/tmp/disposable.exe",
                        4,
                        Convert.ToHexStringLower(
                            SHA256.HashData(
                                new byte[] { 0x4d, 0x5a, 0x00, 0x00 })),
                        TestContext.Current.CancellationToken);
            Assert.Equal(
                SignToolExecutionError.PlatformUnsupported,
                unsupported.Error);
            return;
        }

        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        string toolPath = Path.Combine(temporaryDirectory, "signtool.exe");
        string artifactPath = Path.Combine(temporaryDirectory, "artifact.exe");
        try
        {
            string systemWhere = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "where.exe");
            File.Copy(systemWhere, toolPath);
            byte[] artifact = [0x4d, 0x5a, 0x00, 0x00];
            await File.WriteAllBytesAsync(
                artifactPath,
                artifact,
                TestContext.Current.CancellationToken);
            string toolDigest;
            using (FileStream stream = File.OpenRead(toolPath))
            {
                toolDigest = Convert.ToHexStringLower(
                    await SHA256.HashDataAsync(
                        stream,
                        TestContext.Current.CancellationToken));
            }

            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(toolPath);
            Version toolVersion = new(
                versionInfo.FileMajorPart,
                versionInfo.FileMinorPart,
                versionInfo.FileBuildPart,
                versionInfo.FilePrivatePart);
            InstalledSignToolPolicy policy = new(
                toolPath,
                toolDigest,
                toolVersion,
                Thumbprint,
                new Uri("https://timestamp.example.invalid/rfc3161"),
                TimeSpan.FromSeconds(5));

            SignToolExecutionResult result =
                await new HashPinnedSignTool(policy).SignAsync(
                    artifactPath,
                    artifact.Length,
                    Convert.ToHexStringLower(SHA256.HashData(artifact)),
                    TestContext.Current.CancellationToken);

            Assert.Equal(SignToolExecutionError.SigningFailed, result.Error);
        }
        finally
        {
            File.Delete(artifactPath);
            File.Delete(toolPath);
            Directory.Delete(temporaryDirectory);
        }
    }

    [Fact]
    public async Task SignToolRunnerRejectsHardLinkedToolOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-link-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        string sourceToolPath = Path.Combine(temporaryDirectory, "source.exe");
        string linkedToolPath = Path.Combine(temporaryDirectory, "signtool.exe");
        string artifactPath = Path.Combine(temporaryDirectory, "artifact.exe");
        try
        {
            string systemWhere = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "where.exe");
            File.Copy(systemWhere, sourceToolPath);
            Assert.True(
                CreateHardLink(linkedToolPath, sourceToolPath, IntPtr.Zero));
            byte[] artifact = [0x4d, 0x5a, 0x00, 0x00];
            await File.WriteAllBytesAsync(
                artifactPath,
                artifact,
                TestContext.Current.CancellationToken);
            string toolDigest;
            using (FileStream stream = File.OpenRead(linkedToolPath))
            {
                toolDigest = Convert.ToHexStringLower(
                    await SHA256.HashDataAsync(
                        stream,
                        TestContext.Current.CancellationToken));
            }

            InstalledSignToolPolicy policy = new(
                linkedToolPath,
                toolDigest,
                new Version(1, 0, 0, 0),
                Thumbprint,
                new Uri("https://timestamp.example.invalid/rfc3161"),
                TimeSpan.FromSeconds(5));

            SignToolExecutionResult result =
                await new HashPinnedSignTool(policy).SignAsync(
                    artifactPath,
                    artifact.Length,
                    Convert.ToHexStringLower(SHA256.HashData(artifact)),
                    TestContext.Current.CancellationToken);

            Assert.Equal(SignToolExecutionError.ToolInvalid, result.Error);
        }
        finally
        {
            File.Delete(linkedToolPath);
            File.Delete(sourceToolPath);
            File.Delete(artifactPath);
            Directory.Delete(temporaryDirectory);
        }
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateHardLinkW",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

}

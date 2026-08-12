using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.TestProfile;
using ArtifactSigning.TestProfile.Tests;
using ArtifactSigning.Windows;
using ArtifactSigning.Worker;
using Xunit;

namespace ArtifactSigning.Acceptance.Tests;

public sealed class GeneratedWindowsSigningMatrixTests
{
    private const string MatrixEnabledEnvironment =
        "ARTIFACT_SIGNING_RUN_GENERATED_MATRIX";

    private const string SignToolEnvironment =
        "ARTIFACT_SIGNING_TEST_SIGNTOOL";

    private static readonly DateTimeOffset ValidationTime =
        new(2026, 7, 28, 10, 1, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset TimestampTime =
        new(2026, 7, 28, 10, 4, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset FinalizationTime =
        new(2026, 7, 28, 10, 5, 0, TimeSpan.Zero);

    private static readonly (string Role, string FileName)[] Payloads =
    [
        (ExampleEndpointBundleV1.AgentRole, ExampleEndpointBundleV1.AgentFileName),
        (ExampleEndpointBundleV1.MediaRole, ExampleEndpointBundleV1.MediaFileName),
        (
            ExampleEndpointBundleV1.DesktopWorkerRole,
            ExampleEndpointBundleV1.DesktopWorkerFileName),
    ];

    [Fact]
    public async Task SignsTimestampsVerifiesAndFinalizesGeneratedExampleBundle()
    {
        string? signToolPath = GetConfiguredSignToolPath();
        if (signToolPath is null)
        {
            return;
        }

        using DisposableWindowsTestPki pki = DisposableWindowsTestPki.Create();
        pki.AssertCodeSigningKeyIsMachineBoundAndNonExportable();
        using LoopbackRfc3161Authority timestampAuthority = new(
            pki.TimestampCertificate,
            TimestampTime);
        InstalledSignToolPolicy signToolPolicy = await CreateSignToolPolicyAsync(
            signToolPath,
            pki.CodeSigningThumbprint,
            timestampAuthority.Endpoint).ConfigureAwait(true);
        HashPinnedSignTool signTool = new(signToolPolicy);
        WindowsAuthenticodeFileVerifier verifier = new();
        AuthenticodeTrustPolicy trustPolicy = new(
            pki.CodeSigningThumbprint,
            WindowsTrustRevocationPolicy.DisposableTestNoCheck);
        WorkerAuthenticodeArtifactSigner artifactSigner = new(
            verifier,
            signTool,
            trustPolicy);
        ExampleBundleTestData unsignedBundle = ExampleBundleTestData.Create(
            signerThumbprint: pki.CodeSigningThumbprint);

        SigningProfileValidationResult unsignedValidation =
            ExampleEndpointBundleV1.Instance.ValidateUnsignedBundle(
                new SigningProfileValidationContext(
                    unsignedBundle.Request,
                    unsignedBundle,
                    ValidationTime));
        Assert.True(unsignedValidation.IsSuccess);

        string workingDirectory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-acceptance-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workingDirectory);
        try
        {
            Dictionary<string, byte[]> signedArtifacts =
                new(StringComparer.Ordinal);
            List<VerifiedAuthenticodeArtifact> evidence = [];
            foreach ((string role, string fileName) in Payloads)
            {
                byte[] unsignedBytes = unsignedBundle.ReadAllBytes(fileName);
                string artifactPath = Path.Combine(workingDirectory, fileName);
                await File.WriteAllBytesAsync(
                    artifactPath,
                    unsignedBytes,
                    TestContext.Current.CancellationToken).ConfigureAwait(true);
                string unsignedDigest = Sha256(unsignedBytes);
                WorkerArtifactSigningResult signingResult =
                    await artifactSigner.SignAndVerifyAsync(
                        Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                        workingDirectory,
                        role,
                        fileName,
                        artifactPath,
                        unsignedBytes.LongLength,
                        unsignedDigest,
                        TestContext.Current.CancellationToken).ConfigureAwait(true);
                Assert.True(signingResult.IsSuccess);
                Assert.NotNull(signingResult.Evidence);
                Assert.Equal(
                    pki.CodeSigningThumbprint,
                    signingResult.Evidence.SignerThumbprint);
                Assert.Equal(
                    TimestampTime,
                    signingResult.Evidence.TimestampedAt);

                byte[] signedBytes = await File.ReadAllBytesAsync(
                    artifactPath,
                    TestContext.Current.CancellationToken).ConfigureAwait(true);
                signedArtifacts.Add(fileName, signedBytes);
                evidence.Add(signingResult.Evidence);
            }

            Assert.Equal(Payloads.Length, timestampAuthority.RequestCount);
            ExampleBundleTestData signedBundle =
                unsignedBundle.WithArtifactBytes(signedArtifacts);
            SigningProfileFinalizationResult finalization =
                ExampleEndpointBundleV1.Instance.FinalizeSignedBundle(
                    new SigningProfileFinalizationContext(
                        unsignedBundle.Request,
                        unsignedBundle,
                        signedBundle,
                        evidence,
                        FinalizationTime));
            Assert.True(finalization.IsSuccess);

            ExampleBundleTestData finalizedBundle = signedBundle
                .WithManifestBytesPreservingRequest(
                    finalization.GetFinalizedManifestBytes());
            SigningProfileValidationResult finalizedValidation =
                ExampleEndpointBundleV1.Instance.ValidateFinalizedBundle(
                    new SigningProfileFinalizedValidationContext(
                        unsignedBundle.Request,
                        finalizedBundle,
                        evidence,
                        FinalizationTime.AddSeconds(1)));
            Assert.True(finalizedValidation.IsSuccess);

            string tamperedPath = Path.Combine(
                workingDirectory,
                "tampered.exe");
            byte[] tampered =
                signedArtifacts[ExampleEndpointBundleV1.AgentFileName].ToArray();
            tampered[0x40] ^= 0xff;
            await File.WriteAllBytesAsync(
                tamperedPath,
                tampered,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            AuthenticodeVerificationResult tamperedResult =
                verifier.VerifySigned(
                    tamperedPath,
                    tampered.LongLength,
                    Sha256(tampered),
                    trustPolicy);
            Assert.False(tamperedResult.IsSuccess);
            Assert.NotEqual(
                AuthenticodeVerificationError.None,
                tamperedResult.Error);
        }
        finally
        {
            Directory.Delete(workingDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task TimestampOutageCannotProduceTrustedSignedEvidence()
    {
        string? signToolPath = GetConfiguredSignToolPath();
        if (signToolPath is null)
        {
            return;
        }

        using DisposableWindowsTestPki pki = DisposableWindowsTestPki.Create();
        Uri unavailableTimestampEndpoint = ReserveClosedLoopbackEndpoint();
        InstalledSignToolPolicy signToolPolicy = await CreateSignToolPolicyAsync(
            signToolPath,
            pki.CodeSigningThumbprint,
            unavailableTimestampEndpoint,
            TimeSpan.FromSeconds(5)).ConfigureAwait(true);
        ExampleBundleTestData unsignedBundle = ExampleBundleTestData.Create(
            signerThumbprint: pki.CodeSigningThumbprint);
        byte[] unsignedBytes = unsignedBundle.ReadAllBytes(
            ExampleEndpointBundleV1.AgentFileName);
        string workingDirectory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-outage-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workingDirectory);
        string artifactPath = Path.Combine(
            workingDirectory,
            ExampleEndpointBundleV1.AgentFileName);
        try
        {
            await File.WriteAllBytesAsync(
                artifactPath,
                unsignedBytes,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            string unsignedDigest = Sha256(unsignedBytes);
            WindowsAuthenticodeFileVerifier verifier = new();
            AuthenticodeTrustPolicy trustPolicy = new(
                pki.CodeSigningThumbprint,
                WindowsTrustRevocationPolicy.DisposableTestNoCheck);
            WorkerAuthenticodeArtifactSigner artifactSigner = new(
                verifier,
                new HashPinnedSignTool(signToolPolicy),
                trustPolicy);
            WorkerArtifactSigningResult signingResult =
                await artifactSigner.SignAndVerifyAsync(
                    Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                    workingDirectory,
                    ExampleEndpointBundleV1.AgentRole,
                    ExampleEndpointBundleV1.AgentFileName,
                    artifactPath,
                    unsignedBytes.LongLength,
                    unsignedDigest,
                    TestContext.Current.CancellationToken).ConfigureAwait(true);
            Assert.False(signingResult.IsSuccess);
            Assert.Equal(WorkerArtifactSigningError.SignToolFailed, signingResult.Error);
            Assert.Null(signingResult.Evidence);

            byte[] resultingBytes = await File.ReadAllBytesAsync(
                artifactPath,
                TestContext.Current.CancellationToken).ConfigureAwait(true);
            AuthenticodeVerificationResult verification =
                verifier.VerifySigned(
                    artifactPath,
                    resultingBytes.LongLength,
                    Sha256(resultingBytes),
                    trustPolicy);
            Assert.False(verification.IsSuccess);
            Assert.Null(verification.Evidence);
        }
        finally
        {
            Directory.Delete(workingDirectory, recursive: true);
        }
    }

    private static async Task<InstalledSignToolPolicy> CreateSignToolPolicyAsync(
        string signToolPath,
        string signerThumbprint,
        Uri timestampEndpoint,
        TimeSpan? timeout = null)
    {
        string toolDigest;
        using (FileStream stream = File.OpenRead(signToolPath))
        {
            toolDigest = Convert.ToHexStringLower(
                await SHA256.HashDataAsync(
                    stream,
                    TestContext.Current.CancellationToken).ConfigureAwait(true));
        }

        FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(signToolPath);
        Version toolVersion = new(
            versionInfo.FileMajorPart,
            versionInfo.FileMinorPart,
            versionInfo.FileBuildPart,
            versionInfo.FilePrivatePart);
        return new InstalledSignToolPolicy(
            signToolPath,
            toolDigest,
            toolVersion,
            signerThumbprint,
            timestampEndpoint,
            timeout ?? TimeSpan.FromSeconds(30));
    }

    private static string Sha256(byte[] content)
    {
        return Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(content));
    }

    private static string? GetConfiguredSignToolPath()
    {
        if (!OperatingSystem.IsWindows()
            || !string.Equals(
                Environment.GetEnvironmentVariable(MatrixEnabledEnvironment),
                "1",
                StringComparison.Ordinal))
        {
            return null;
        }

        string signToolPath = Assert.IsType<string>(
            Environment.GetEnvironmentVariable(SignToolEnvironment));
        Assert.True(Path.IsPathFullyQualified(signToolPath));
        Assert.True(File.Exists(signToolPath));
        return signToolPath;
    }

    private static Uri ReserveClosedLoopbackEndpoint()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        try
        {
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            return new Uri(
                $"http://127.0.0.1:{port.ToString(System.Globalization.CultureInfo.InvariantCulture)}/rfc3161");
        }
        finally
        {
            listener.Dispose();
        }
    }
}

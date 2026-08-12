using System.Security.Cryptography;
using ArtifactSigning.Windows;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerMicrosoftArtifactSigningArtifactSignerTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string SubscriberEku =
        "1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699";

    [Fact]
    public async Task RemovesPerJobMetadataAfterProviderFailure()
    {
        string work = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-managed-worker-{Guid.NewGuid():N}");
        string bundle = Path.Combine(
            work,
            WorkerReadyRecordOperation.BundleDirectoryName);
        Directory.CreateDirectory(bundle);
        string artifact = Path.Combine(bundle, "agent.exe");
        byte[] unsigned = [0x4d, 0x5a, 0x00, 0x00];
        await File.WriteAllBytesAsync(
            artifact,
            unsigned,
            TestContext.Current.CancellationToken);
        try
        {
            MicrosoftArtifactSigningPolicy providerPolicy = CreateProviderPolicy();
            AuthenticodeTrustPolicy trustPolicy = AuthenticodeTrustPolicy
                .CreateMicrosoftArtifactSigningPublisher(
                    new string('a', 64),
                    SubscriberEku,
                    [new string('A', 40)],
                    WindowsTrustRevocationPolicy.DisposableTestNoCheck,
                    WindowsTrustRevocationPolicy.DisposableTestNoCheck);
            WorkerMicrosoftArtifactSigningArtifactSigner signer = new(
                new AcceptingUnsignedVerifier(),
                new HashPinnedMicrosoftArtifactSignTool(providerPolicy),
                providerPolicy,
                trustPolicy);

            WorkerArtifactSigningResult result = await signer.SignAndVerifyAsync(
                Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                work,
                "Agent",
                "agent.exe",
                artifact,
                unsigned.LongLength,
                Convert.ToHexStringLower(SHA256.HashData(unsigned)),
                TestContext.Current.CancellationToken);

            Assert.Equal(WorkerArtifactSigningError.SignToolFailed, result.Error);
            Assert.False(File.Exists(Path.Combine(work, "metadata.json")));
            Assert.Equal(
                [
                    WorkerReadyRecordOperation.BundleDirectoryName,
                ],
                Directory.EnumerateFileSystemEntries(work)
                    .Select(Path.GetFileName));
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    [Fact]
    public async Task RefusesToOverwritePreexistingMetadata()
    {
        string work = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-managed-worker-{Guid.NewGuid():N}");
        string bundle = Path.Combine(
            work,
            WorkerReadyRecordOperation.BundleDirectoryName);
        Directory.CreateDirectory(bundle);
        string artifact = Path.Combine(bundle, "agent.exe");
        string metadata = Path.Combine(work, "metadata.json");
        byte[] unsigned = [0x4d, 0x5a, 0x00, 0x00];
        await File.WriteAllBytesAsync(
            artifact,
            unsigned,
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            metadata,
            "untrusted",
            TestContext.Current.CancellationToken);
        try
        {
            MicrosoftArtifactSigningPolicy providerPolicy = CreateProviderPolicy();
            AuthenticodeTrustPolicy trustPolicy = AuthenticodeTrustPolicy
                .CreateMicrosoftArtifactSigningPublisher(
                    new string('a', 64),
                    SubscriberEku,
                    [new string('A', 40)],
                    WindowsTrustRevocationPolicy.DisposableTestNoCheck,
                    WindowsTrustRevocationPolicy.DisposableTestNoCheck);
            WorkerMicrosoftArtifactSigningArtifactSigner signer = new(
                new AcceptingUnsignedVerifier(),
                new HashPinnedMicrosoftArtifactSignTool(providerPolicy),
                providerPolicy,
                trustPolicy);

            WorkerArtifactSigningResult result = await signer.SignAndVerifyAsync(
                Guid.Parse("018f84a7-2f4c-7d8e-a123-123456789abc"),
                work,
                "Agent",
                "agent.exe",
                artifact,
                unsigned.LongLength,
                Convert.ToHexStringLower(SHA256.HashData(unsigned)),
                TestContext.Current.CancellationToken);

            Assert.Equal(
                WorkerArtifactSigningError.UnsignedInspectionFailed,
                result.Error);
            Assert.Equal(
                "untrusted",
                await File.ReadAllTextAsync(
                    metadata,
                    TestContext.Current.CancellationToken));
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    private static MicrosoftArtifactSigningPolicy CreateProviderPolicy()
    {
        return new MicrosoftArtifactSigningPolicy(
            MicrosoftArtifactSigningRegion.JapanEast,
            "example-signing-account",
            "Example-PublicTrust-Test",
            @"C:\Program Files\Windows Kits\10\bin\signtool.exe",
            Sha256,
            new Version(10, 0, 26100, 4188),
            @"C:\Program Files\ArtifactSigning\Tools\Azure.CodeSigning.Dlib.dll",
            Sha256,
            new Version(1, 0, 128, 0),
            Sha256,
            TimeSpan.FromSeconds(5));
    }

    private sealed class AcceptingUnsignedVerifier : IAuthenticodeFileVerifier
    {
        public AuthenticodeVerificationError VerifyUnsigned(
            string trustedAbsolutePath,
            long expectedSize,
            string expectedSha256)
        {
            _ = trustedAbsolutePath;
            _ = expectedSize;
            _ = expectedSha256;
            return AuthenticodeVerificationError.None;
        }

        public AuthenticodeVerificationResult VerifySigned(
            string trustedAbsolutePath,
            long expectedSize,
            string expectedSha256,
            AuthenticodeTrustPolicy trustPolicy)
        {
            throw new InvalidOperationException(
                "Provider failure must occur before signed verification.");
        }
    }
}

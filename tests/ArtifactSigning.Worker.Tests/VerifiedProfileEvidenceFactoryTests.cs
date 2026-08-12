using ArtifactSigning.Profiles;
using ArtifactSigning.Windows;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class VerifiedProfileEvidenceFactoryTests
{
    [Fact]
    public void MapsOnlyBoundedWindowsEvidenceIntoProfileEvidence()
    {
        DateTimeOffset timestamp = DateTimeOffset.Parse(
            "2026-07-29T10:00:00Z",
            System.Globalization.CultureInfo.InvariantCulture);
        VerifiedAuthenticodeFile windowsEvidence = new(
            4096,
            new string('a', 64),
            new string('B', 40),
            new string('C', 40),
            timestamp);
        AuthenticodeVerificationResult verification = new(
            windowsEvidence,
            AuthenticodeVerificationError.None);

        VerifiedAuthenticodeArtifact profileEvidence =
            VerifiedProfileEvidenceFactory.Create(
                "Agent",
                "example-agent.exe",
                verification);

        Assert.Equal("Agent", profileEvidence.Role);
        Assert.Equal("example-agent.exe", profileEvidence.FileName);
        Assert.Equal(windowsEvidence.Size, profileEvidence.Size);
        Assert.Equal(windowsEvidence.Sha256, profileEvidence.Sha256);
        Assert.Equal(
            windowsEvidence.SignerThumbprint,
            profileEvidence.SignerThumbprint);
        Assert.Equal(timestamp, profileEvidence.TimestampedAt);
    }

    [Fact]
    public void RejectsFailedWindowsVerification()
    {
        AuthenticodeVerificationResult failure = new(
            null,
            AuthenticodeVerificationError.WindowsTrustFailed);

        Assert.Throws<InvalidOperationException>(
            () => VerifiedProfileEvidenceFactory.Create(
                "Agent",
                "example-agent.exe",
                failure));
    }
}

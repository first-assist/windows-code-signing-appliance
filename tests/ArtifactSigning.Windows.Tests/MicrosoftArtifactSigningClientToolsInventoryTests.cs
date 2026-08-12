using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class MicrosoftArtifactSigningClientToolsInventoryTests
{
    [Fact]
    public async Task InventoryIsCanonicalAndContentBound()
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-client-tools-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string first = Path.Combine(directory, "Azure.CodeSigning.Dlib.dll");
        string second = Path.Combine(directory, "Azure.Identity.dll");
        try
        {
            await File.WriteAllBytesAsync(
                second,
                [0x02],
                TestContext.Current.CancellationToken);
            await File.WriteAllBytesAsync(
                first,
                [0x01],
                TestContext.Current.CancellationToken);

            Assert.True(
                MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                    directory,
                    out string? before));
            Assert.NotNull(before);
            Assert.Equal(64, before.Length);

            await File.WriteAllBytesAsync(
                second,
                [0x03],
                TestContext.Current.CancellationToken);
            Assert.True(
                MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                    directory,
                    out string? after));
            Assert.NotEqual(before, after);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void InventoryRejectsNestedOrEmptyDirectories()
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-client-tools-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            Assert.False(
                MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                    directory,
                    out _));
            Directory.CreateDirectory(Path.Combine(directory, "nested"));
            File.WriteAllBytes(
                Path.Combine(directory, "Azure.CodeSigning.Dlib.dll"),
                [0x01]);
            Assert.False(
                MicrosoftArtifactSigningClientToolsInventory.TryComputeSha256(
                    directory,
                    out _));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

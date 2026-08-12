using System.Security.Cryptography;

namespace ArtifactSigning.Windows;

internal sealed record ArtifactFileSnapshot(long Size, string Sha256)
{
    internal const long MaximumArtifactBytes = 100L * 1024 * 1024;

    internal static bool TryCreate(
        string trustedAbsolutePath,
        out ArtifactFileSnapshot? snapshot)
    {
        snapshot = null;
        if (string.IsNullOrWhiteSpace(trustedAbsolutePath)
            || !Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            return false;
        }

        try
        {
            FileAttributes attributes = File.GetAttributes(trustedAbsolutePath);
            if (attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return false;
            }

            FileInfo file = new(trustedAbsolutePath);
            if (!file.Exists || file.Length is <= 0 or > MaximumArtifactBytes)
            {
                return false;
            }

            using FileStream stream = new(
                trustedAbsolutePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            if (stream.Length != file.Length)
            {
                return false;
            }

            if (!WindowsFileHandleInspector.IsDirectSingleLinkFile(
                    stream.SafeFileHandle))
            {
                return false;
            }

            snapshot = Create(stream);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    internal static ArtifactFileSnapshot Create(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek
            || stream.Length is <= 0 or > MaximumArtifactBytes)
        {
            throw new InvalidDataException();
        }

        stream.Position = 0;
        string sha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        return new ArtifactFileSnapshot(stream.Length, sha256);
    }

    internal bool Matches(long expectedSize, string expectedSha256)
    {
        return Size == expectedSize
            && string.Equals(Sha256, expectedSha256, StringComparison.Ordinal);
    }
}

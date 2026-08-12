using ArtifactSigning.Profiles;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

internal sealed class WorkerProfileArtifactReader : IProfileArtifactReader
{
    private readonly Dictionary<string, string> _paths;

    internal WorkerProfileArtifactReader(
        string trustedArtifactRoot,
        SigningProfileDescriptor descriptor)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedArtifactRoot);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!Path.IsPathFullyQualified(trustedArtifactRoot))
        {
            throw new ArgumentException(
                "Artifact root must be fully qualified.",
                nameof(trustedArtifactRoot));
        }

        string root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(trustedArtifactRoot));
        _paths = descriptor.Artifacts.ToDictionary(
            definition => definition.FileName,
            definition => Path.Combine(root, definition.FileName),
            StringComparer.Ordinal);
    }

    public Stream OpenRead(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        if (!_paths.TryGetValue(fileName, out string? path))
        {
            throw new FileNotFoundException(
                "Profile requested an artifact outside its compiled inventory.");
        }

        return WorkerDirectFile.OpenRead(path);
    }
}

internal static class WorkerDirectFile
{
    internal static FileStream OpenRead(string trustedAbsolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsolutePath);
        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Worker file path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        FileAttributes attributes = File.GetAttributes(trustedAbsolutePath);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "Worker input is not a direct regular file.");
        }

        FileStream stream = new(
            trustedAbsolutePath,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                BufferSize = 64 * 1024,
                Options = FileOptions.SequentialScan,
            });
        if (!WindowsFileHandleInspector.IsDirectSingleLinkFile(
                stream.SafeFileHandle))
        {
            stream.Dispose();
            throw new InvalidDataException(
                "Worker input is not a direct single-link file.");
        }

        return stream;
    }

    internal static byte[] ReadBounded(
        string trustedAbsolutePath,
        int maximumBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        using FileStream stream = OpenRead(trustedAbsolutePath);
        if (stream.Length is <= 0 || stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Worker input exceeds its fixed bound.");
        }

        byte[] content = new byte[checked((int)stream.Length)];
        stream.ReadExactly(content);
        if (stream.ReadByte() is not -1)
        {
            throw new InvalidDataException(
                "Worker input changed while being read.");
        }

        return content;
    }
}

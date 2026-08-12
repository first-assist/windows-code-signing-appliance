namespace ArtifactSigning.Windows;

public static class WindowsDirectFileReader
{
    public static FileStream OpenReadDirectSingleLinkFile(
        string trustedAbsolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            trustedAbsolutePath);
        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Installed file path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        FileAttributes attributes =
            File.GetAttributes(trustedAbsolutePath);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "Installed file is not a direct regular file.");
        }

        FileStream stream = new(
            trustedAbsolutePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        if (!WindowsFileHandleInspector.IsDirectSingleLinkFile(
                stream.SafeFileHandle))
        {
            stream.Dispose();
            throw new InvalidDataException(
                "Installed file is linked or indirect.");
        }

        return stream;
    }

    public static void ValidateDirectSingleLinkFile(
        string trustedAbsolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsolutePath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Direct installed-file validation is Windows-only.");
        }

        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Installed file path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        try
        {
            FileAttributes attributes =
                File.GetAttributes(trustedAbsolutePath);
            if (attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException(
                    "Installed file is not a direct regular file.");
            }

            using FileStream stream = new(
                trustedAbsolutePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 1,
                FileOptions.RandomAccess);
            if (!WindowsFileHandleInspector.IsDirectSingleLinkFile(
                    stream.SafeFileHandle))
            {
                throw new InvalidDataException(
                    "Installed file is linked or indirect.");
            }
        }
        catch (IOException exception)
        {
            throw new InvalidDataException(
                "Installed file could not be validated.",
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidDataException(
                "Installed file could not be validated.",
                exception);
        }
    }

    public static byte[] ReadAllBytes(
        string trustedAbsolutePath,
        int maximumBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsolutePath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Direct installed-file validation is Windows-only.");
        }

        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Installed file path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        try
        {
            FileAttributes attributes =
                File.GetAttributes(trustedAbsolutePath);
            if (attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException(
                    "Installed file is not a direct regular file.");
            }

            using FileStream stream = new(
                trustedAbsolutePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 16 * 1024,
                FileOptions.SequentialScan);
            if (stream.Length is <= 0
                || stream.Length > maximumBytes
                || !WindowsFileHandleInspector.IsDirectSingleLinkFile(
                    stream.SafeFileHandle))
            {
                throw new InvalidDataException(
                    "Installed file is empty, oversized, linked, or indirect.");
            }

            byte[] bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.Position != stream.Length)
            {
                throw new InvalidDataException(
                    "Installed file length changed during validation.");
            }

            return bytes;
        }
        catch (IOException exception)
        {
            throw new InvalidDataException(
                "Installed file could not be validated.",
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidDataException(
                "Installed file could not be validated.",
                exception);
        }
    }
}

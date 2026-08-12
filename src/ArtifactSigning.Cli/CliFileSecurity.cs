using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ArtifactSigning.Cli;

internal static class CliFileSecurity
{
    private const UnixFileMode OwnerFileMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerDirectoryMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite
        | UnixFileMode.UserExecute;

    internal static string RequireAbsolutePath(
        string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)
            || path.Length > 1024)
        {
            throw new InvalidDataException(
                "A configured path is invalid.");
        }

        return Path.GetFullPath(path);
    }

    internal static void RequireOwnerOnlyFile(
        string path,
        int maximumBytes)
    {
        ValidateDirectRegularFile(path, maximumBytes);
        if (!OperatingSystem.IsWindows()
            && File.GetUnixFileMode(path)
                != OwnerFileMode)
        {
            throw new UnauthorizedAccessException(
                "A private client file is not owner-only.");
        }

        if (OperatingSystem.IsLinux())
        {
            LinuxStatx stat = GetLinuxStat(path);
            if (stat.UserId != GetEffectiveUserId()
                || stat.HardLinkCount is not 1)
            {
                throw new UnauthorizedAccessException(
                    "A private client file has an unsafe owner or link count.");
            }
        }
    }

    internal static void ValidateDirectRegularFile(
        string path,
        long maximumBytes)
    {
        FileInfo file = new(path);
        file.Refresh();
        if (!file.Exists)
        {
            throw new FileNotFoundException(
                "A client input file is unavailable.",
                path);
        }

        if (file.Length is <= 0
            || file.Length > maximumBytes
            || file.Attributes.HasFlag(
                FileAttributes.Directory)
            || file.Attributes.HasFlag(
                FileAttributes.ReparsePoint)
            || file.LinkTarget is not null)
        {
            throw new InvalidDataException(
                "A client input file is invalid.");
        }
    }

    internal static byte[] ReadBounded(
        string path,
        int maximumBytes)
    {
        ValidateDirectRegularFile(path, maximumBytes);
        using FileStream input = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan);
        if (input.Length is <= 0
            || input.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "A client input file is invalid.");
        }

        byte[] content =
            new byte[checked((int)input.Length)];
        input.ReadExactly(content);
        return content;
    }

    internal static FileStream CreateOwnerOnlyFile(
        string path)
    {
        string fullPath = RequireAbsolutePath(path);
        FileStreamOptions options = new()
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 64 * 1024,
            Options = FileOptions.SequentialScan,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = OwnerFileMode;
        }

        FileStream output = new(fullPath, options);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                fullPath,
                OwnerFileMode);
        }

        return output;
    }

    internal static string CreateOwnerOnlyTemporaryDirectory()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signctl-{Guid.NewGuid():N}");
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(
                path,
                OwnerDirectoryMode);
        }

        return path;
    }

    internal static string Sha256File(
        string path,
        long maximumBytes,
        out long size)
    {
        ValidateDirectRegularFile(path, maximumBytes);
        using FileStream input = File.OpenRead(path);
        size = input.Length;
        return Convert.ToHexStringLower(
            SHA256.HashData(input));
    }

    internal static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)
                && !File.GetAttributes(path).HasFlag(
                    FileAttributes.ReparsePoint))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Owner-private temporary data is removed best effort.
        }
        catch (UnauthorizedAccessException)
        {
            // Owner-private temporary data is removed best effort.
        }
    }

    private static LinuxStatx GetLinuxStat(string path)
    {
        const int currentWorkingDirectory = -100;
        const int doNotFollowSymlink = 0x100;
        const uint basicStats = 0x000007ff;
        const uint requiredMask = 0x0000000c;
        int result = Statx(
            currentWorkingDirectory,
            path,
            doNotFollowSymlink,
            basicStats,
            out LinuxStatx stat);
        if (result is not 0
            || (stat.Mask & requiredMask)
                != requiredMask)
        {
            throw new UnauthorizedAccessException(
                "Private client file ownership could not be verified.");
        }

        return stat;
    }

    [DllImport(
        "libc",
        EntryPoint = "geteuid",
        ExactSpelling = true)]
    [DefaultDllImportSearchPaths(
        DllImportSearchPath.System32)]
    private static extern uint GetEffectiveUserId();

    [DllImport(
        "libc",
        EntryPoint = "statx",
        BestFitMapping = false,
        CharSet = CharSet.Ansi,
        ExactSpelling = true,
        SetLastError = true,
        ThrowOnUnmappableChar = true)]
    [DefaultDllImportSearchPaths(
        DllImportSearchPath.System32)]
    private static extern int Statx(
        int directoryFileDescriptor,
        string path,
        int flags,
        uint mask,
        out LinuxStatx stat);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(0)]
        internal uint Mask;

        [FieldOffset(16)]
        internal uint HardLinkCount;

        [FieldOffset(20)]
        internal uint UserId;
    }
}

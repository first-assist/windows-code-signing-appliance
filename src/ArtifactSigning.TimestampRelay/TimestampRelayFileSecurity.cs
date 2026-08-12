using System.Runtime.InteropServices;

namespace ArtifactSigning.TimestampRelay;

internal static class TimestampRelayFileSecurity
{
    private const UnixFileMode OwnerFileMode =
        UnixFileMode.UserRead
        | UnixFileMode.UserWrite;

    internal static byte[] ReadOwnerOnly(
        string path,
        int maximumBytes)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Timestamp relay file validation is Linux-only.");
        }

        FileInfo file = new(path);
        file.Refresh();
        if (!file.Exists
            || file.Length is <= 0
            || file.Length > maximumBytes
            || file.Attributes.HasFlag(
                FileAttributes.Directory)
            || file.Attributes.HasFlag(
                FileAttributes.ReparsePoint)
            || file.LinkTarget is not null
            || File.GetUnixFileMode(path)
                != OwnerFileMode)
        {
            throw new UnauthorizedAccessException(
                "Timestamp relay configuration is not protected.");
        }

        LinuxStatx stat = GetLinuxStat(path);
        if (stat.UserId != GetEffectiveUserId()
            || stat.HardLinkCount is not 1)
        {
            throw new UnauthorizedAccessException(
                "Timestamp relay configuration is not protected.");
        }

        using FileStream input = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan);
        if (input.Length != file.Length)
        {
            throw new InvalidDataException(
                "Timestamp relay configuration changed while opening.");
        }

        byte[] content =
            new byte[checked((int)input.Length)];
        input.ReadExactly(content);
        return content;
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
                "Timestamp relay configuration ownership is unavailable.");
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

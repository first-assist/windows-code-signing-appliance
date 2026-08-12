using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArtifactSigning.Windows;

internal static class WindowsFileHandleInspector
{
    internal static bool IsDirectSingleLinkFile(SafeFileHandle fileHandle)
    {
        ArgumentNullException.ThrowIfNull(fileHandle);
        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        if (!GetFileInformationByHandle(fileHandle, out ByHandleFileInformation info))
        {
            return false;
        }

        FileAttributes attributes = (FileAttributes)info.FileAttributes;
        return info.NumberOfLinks is 1
            && !attributes.HasFlag(FileAttributes.Directory)
            && !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    [DllImport(
        "kernel32.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }
}

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArtifactSigning.Windows;

internal enum WindowsTrustStatus
{
    Trusted,
    NotTrusted,
}

internal interface IWindowsNativeTrust
{
    WindowsTrustStatus VerifyEmbeddedSignature(
        string trustedAbsolutePath,
        SafeFileHandle fileHandle,
        WindowsTrustRevocationPolicy revocationPolicy);
}

internal sealed class WindowsNativeTrust : IWindowsNativeTrust
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x80;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint WtdDisableMd2Md4 = 0x2000;

    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public WindowsTrustStatus VerifyEmbeddedSignature(
        string trustedAbsolutePath,
        SafeFileHandle fileHandle,
        WindowsTrustRevocationPolicy revocationPolicy)
    {
        IntPtr path = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            path = Marshal.StringToCoTaskMemUni(trustedAbsolutePath);
            WinTrustFileInfo fileInfo = new()
            {
                StructureSize = checked((uint)Marshal.SizeOf<WinTrustFileInfo>()),
                FilePath = path,
                FileHandle = fileHandle.DangerousGetHandle(),
            };
            fileInfoPointer = Marshal.AllocCoTaskMem(
                Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);

            WinTrustData trustData = new()
            {
                StructureSize = checked((uint)Marshal.SizeOf<WinTrustData>()),
                UiChoice = WtdUiNone,
                RevocationChecks = revocationPolicy
                    is WindowsTrustRevocationPolicy.DisposableTestNoCheck
                        or WindowsTrustRevocationPolicy.RetainedLabPinned
                        ? 0U
                        : WtdRevokeWholeChain,
                UnionChoice = WtdChoiceFile,
                UnionData = fileInfoPointer,
                StateAction = WtdStateActionVerify,
                ProviderFlags = GetProviderFlags(revocationPolicy),
            };

            Guid policy = GenericVerifyV2;
            int status = WinVerifyTrust(
                new IntPtr(-1),
                ref policy,
                ref trustData);
            try
            {
                return status is 0
                    ? WindowsTrustStatus.Trusted
                    : WindowsTrustStatus.NotTrusted;
            }
            finally
            {
                trustData.StateAction = WtdStateActionClose;
                _ = WinVerifyTrust(
                    new IntPtr(-1),
                    ref policy,
                    ref trustData);
            }
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }

            if (path != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(path);
            }
        }
    }

    private static uint GetProviderFlags(WindowsTrustRevocationPolicy policy)
    {
        return policy switch
        {
            WindowsTrustRevocationPolicy.Online =>
                WtdRevocationCheckChainExcludeRoot | WtdDisableMd2Md4,
            WindowsTrustRevocationPolicy.OfflineCache =>
                WtdRevocationCheckChainExcludeRoot
                | WtdCacheOnlyUrlRetrieval
                | WtdDisableMd2Md4,
            WindowsTrustRevocationPolicy.DisposableTestNoCheck =>
                WtdRevocationCheckNone | WtdDisableMd2Md4,
            WindowsTrustRevocationPolicy.RetainedLabPinned =>
                WtdRevocationCheckNone | WtdDisableMd2Md4,
            _ => throw new ArgumentOutOfRangeException(nameof(policy)),
        };
    }

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(
        IntPtr window,
        ref Guid actionId,
        ref WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        internal uint StructureSize;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        internal uint StructureSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr UnionData;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal IntPtr SignatureSettings;
    }
}

internal enum CatalogSignatureState
{
    None,
    Present,
    InspectionFailed,
}

internal interface IWindowsCatalogInspector
{
    CatalogSignatureState Inspect(SafeFileHandle fileHandle);
}

internal sealed class WindowsCatalogInspector : IWindowsCatalogInspector
{
    private static readonly string[] CatalogHashAlgorithms = ["SHA256", "SHA1"];

    public CatalogSignatureState Inspect(SafeFileHandle fileHandle)
    {
        foreach (string algorithm in CatalogHashAlgorithms)
        {
            CatalogSignatureState result = Inspect(
                fileHandle,
                algorithm);
            if (result is not CatalogSignatureState.None)
            {
                return result;
            }
        }

        return CatalogSignatureState.None;
    }

    private static CatalogSignatureState Inspect(
        SafeFileHandle fileHandle,
        string hashAlgorithm)
    {
        if (!CryptCATAdminAcquireContext2(
                out IntPtr catalogAdmin,
                IntPtr.Zero,
                hashAlgorithm,
                IntPtr.Zero,
                0))
        {
            return CatalogSignatureState.InspectionFailed;
        }

        try
        {
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(
                    catalogAdmin,
                    fileHandle,
                    ref hashSize,
                    null,
                    0)
                || hashSize is 0 or > 128)
            {
                return CatalogSignatureState.InspectionFailed;
            }

            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(
                    catalogAdmin,
                    fileHandle,
                    ref hashSize,
                    hash,
                    0))
            {
                return CatalogSignatureState.InspectionFailed;
            }

            IntPtr catalog = CryptCATAdminEnumCatalogFromHash(
                catalogAdmin,
                hash,
                hashSize,
                0,
                IntPtr.Zero);
            if (catalog == IntPtr.Zero)
            {
                return CatalogSignatureState.None;
            }

            try
            {
                return CatalogSignatureState.Present;
            }
            finally
            {
                _ = CryptCATAdminReleaseCatalogContext(
                    catalogAdmin,
                    catalog,
                    0);
            }
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(catalogAdmin, 0);
        }
    }

    [DllImport(
        "wintrust.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catalogAdmin,
        IntPtr subsystem,
        string hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catalogAdmin,
        SafeFileHandle file,
        ref uint hashSize,
        byte[]? hash,
        uint flags);

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catalogAdmin,
        byte[] hash,
        uint hashSize,
        uint flags,
        IntPtr previousCatalog);

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr catalogAdmin,
        IntPtr catalogInfo,
        uint flags);

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr catalogAdmin,
        uint flags);
}

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LocalGateKeys.PasskeyProvider.Protocol;

internal static partial class NativeMethods
{
    public const uint GenericRead = 0x80000000;
    public const uint GenericWrite = 0x40000000;
    public const uint OpenExisting = 3;
    public const uint FileFlagOverlapped = 0x40000000;
    // SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION: the server may identify this client, never impersonate it
    // (pipe_transport.PIPE_CLIENT_SQOS_FLAGS).
    public const uint SecuritySqosPresent = 0x00100000;
    public const uint SecurityIdentification = 0x00010000;
    public const uint ProcessQueryLimitedInformation = 0x1000;

    public const int ErrorFileNotFound = 2;
    public const int ErrorPathNotFound = 3;
    public const int ErrorSemTimeout = 121;
    public const int ErrorPipeBusy = 231;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafePipeHandle CreateFile(string fileName, uint desiredAccess, uint shareMode,
                                                    IntPtr securityAttributes, uint creationDisposition,
                                                    uint flagsAndAttributes, IntPtr templateFile);

    [LibraryImport("kernel32.dll", EntryPoint = "WaitNamedPipeW", SetLastError = true,
                   StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WaitNamedPipe(string name, uint timeoutMs);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeServerProcessId(SafeHandle pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inherit,
                                                        uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char* exeName,
                                                                ref uint size);

    // -- Package identity (appmodel.h) ---------------------------------------------------------------------

    public const int ErrorInsufficientBuffer = 122;
    public const int AppModelErrorNoPackage = 15700;

    [LibraryImport("kernel32.dll")]
    public static unsafe partial int GetCurrentPackageFamilyName(ref uint packageFamilyNameLength,
                                                                 char* packageFamilyName);

    [LibraryImport("kernel32.dll")]
    public static unsafe partial int GetPackageFamilyName(SafeProcessHandle process, ref uint packageFamilyNameLength,
                                                          char* packageFamilyName);

    // -- WinVerifyTrust ---------------------------------------------------------------------------------------

    public static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    public const uint WtdUiNone = 2;
    public const uint WtdRevokeNone = 0;
    public const uint WtdChoiceFile = 1;
    public const uint WtdStateActionVerify = 1;
    public const uint WtdStateActionClose = 2;
    public const uint WtdRevocationCheckNone = 0x10;
    public const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    public struct WintrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WintrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    public static unsafe partial int WinVerifyTrust(IntPtr hwnd, Guid* action, WintrustData* data);
}

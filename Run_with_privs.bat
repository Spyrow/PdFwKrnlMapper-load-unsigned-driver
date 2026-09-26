@echo off
REM Enable SeLoadDriverPrivilege via PowerShell then run mapper
powershell -Command "& { Add-Type @'
using System;
using System.Runtime.InteropServices;
public class PrivHelper {
    [DllImport(\"advapi32.dll\", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport(\"advapi32.dll\", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
    [DllImport(\"advapi32.dll\", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport(\"kernel32.dll\")]
    public static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }
    const uint SE_PRIVILEGE_ENABLED = 0x2;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    const uint TOKEN_QUERY = 0x8;
    public static void EnableLoadDriver() {
        IntPtr token;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) {
            long luid;
            if (LookupPrivilegeValue(null, \"SeLoadDriverPrivilege\", out luid)) {
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Luid = luid;
                tp.Attributes = (int)SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
    }
}
'@
 [PrivHelper]::EnableLoadDriver()
 }"; cd /d C:\Users\Megaport\Mapper\PdFwKrnlMapper-load-unsigned-driver; .\PdfwKrnlMapper.exe
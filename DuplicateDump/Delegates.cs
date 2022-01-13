using System;
using System.Runtime.InteropServices;
using System.Text;
using DInvoke.Data;

namespace DuplicateDump
{
    public class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS RtlAdjustPrivilege(int privilege, bool bEnablePrivilege, bool isThreadPrivilege, out bool previousValue);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void AddSecurityPackage(string pszPackageName, Structs.SECURITY_PACKAGE_OPTIONS Options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int GetProcessId(IntPtr hProcess);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtQuerySystemInformation(Structs.SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlCopyMemory(byte[] Destination, IntPtr Source, uint Length);


    }
}

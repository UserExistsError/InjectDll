# DLL Inject

Injects a DLL into a process without loading from disk by using CreateRemoteThread. Injection works Wow64 <=> Native 64.

Works by prepending the loader from https://github.com/UserExistsError/DllLoaderShellcode to a DLL.

## usage

```usage: InjectDll.exe <DLL> [PID]```

If no PID is provided, load DLL in current process.

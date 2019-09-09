#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shellapi.h>
#include "InjectDll.h"

#if defined(_M_IX86)
# if defined(_DEBUG)
// debug code is broken
//#  include "InjectWow64toNative64d.h"
#  include "InjectWow64toNative64.h"
# else
#  include "InjectWow64toNative64.h"
# endif
#endif

// Loader shellcode from https ://github.com/UserExistsError/DllLoaderShellcode
#include "loaders.h"

const IMAGE_NT_HEADERS* GetNtHeader(const BYTE* image, const DWORD imageSize);
BOOL ReadFileData(WCHAR *filename, BYTE **buff, DWORD *size);
int GetCurrentProcessBits();
int GetProcessBits(HANDLE);
void ExecuteNative64(void *shellcode, void *arg);

typedef LONG(NTAPI * RTLCREATEUSERTHREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PTHREAD_START_ROUTINE, PVOID, PHANDLE, LPVOID);
typedef DWORD(WINAPI * GETTHREADID)(HANDLE);


DWORD GetThreadIdFromHandle(HANDLE hThread)
{
	// vista+ only
	GETTHREADID fpGetThreadId = (GETTHREADID)GetProcAddress(GetModuleHandleA("kernel32"), "GetThreadId");
	if (fpGetThreadId)
		return fpGetThreadId(hThread);
	return 0;
}

BOOL wcs2dw(WCHAR *wp, DWORD *dp)
{
	if (wp == NULL || dp == NULL)
		return FALSE;
	WCHAR *endp = NULL;
	DWORD dw = wcstoul(wp, &endp, 10);
	if (*endp != L'\x00')
		return FALSE;
	*dp = dw;
	return TRUE;
}


int wmain(int argc, WCHAR *argv[])
{
	if (argc < 2) {
		wprintf(L"usage: InjectDll.exe <DLL> [PID]\n");
		return 1;
	}

	// read in the dll
	BYTE *image = NULL;
	DWORD imageSize = 0;
	if (!ReadFileData(argv[1], &image, &imageSize)) {
		wprintf(L"Failed to read image file: %s\n", argv[1]);
		return 1;
	}

	// convert pid to DWORD
	DWORD pid = 0;
	if (argc > 2) {
		if (!wcs2dw(argv[2], &pid)) {
			wprintf(L"Invalid ProcessID: %s\n", argv[2]);
			return 1;
		}
	}
	else {
		pid = GetCurrentProcessId();
	}

	// open process for injection
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
	if (hProc == NULL) {
		wprintf(L"Failed to open process for injection: %lu\n", pid);
		return 1;
	}

	// get remote process arch
	const int bits = GetProcessBits(hProc);
	if (bits == 0) {
		wprintf(L"Failed to get process architecture\n");
		return 1;
	}

	// ensure inject process is same arch as dll
	const IMAGE_NT_HEADERS *ntHeader = GetNtHeader(image, imageSize);
	if (ntHeader == NULL) {
		wprintf(L"DLL does not have a valid PE header\n");
		return 1;
	}
	if ((ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && bits != 32) ||
		(ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && bits != 64)) {
		wprintf(L"Inject process arch does not match DLL\n");
		return 1;
	}

	// choose correct loader arch for remote process
	BYTE *loader = NULL;
	size_t loaderSize = 0;
	if (bits == 32) {
		loaderSize = sizeof(loader_x86);
		loader = (BYTE*)loader_x86;
	}
	else {
		loaderSize = sizeof(loader_x64);
		loader = (BYTE*)loader_x64;
	}

	wprintf(L"Injecting %s -> %s\n", GetCurrentProcessBits() == 32 ? L"Wow64" : L"x64", bits == 32 ? L"Wow64" : L"x64");

	// allocate remote memory for loader shellcode + dll
	const size_t remoteShellcodeSize = loaderSize + imageSize;
	void *remoteShellcode = VirtualAllocEx(hProc, 0, remoteShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteShellcode == NULL) {
		wprintf(L"Failed to allocate remote memory\n");
		return 1;
	}
	wprintf(L"Writing %lu bytes into process at %p\n", (DWORD)remoteShellcodeSize, remoteShellcode);

	// write shellcode to remote process
	SIZE_T numWritten = 0;
	if (!WriteProcessMemory(hProc, remoteShellcode, loader, loaderSize, &numWritten) ||
		!WriteProcessMemory(hProc, (BYTE*)remoteShellcode + loaderSize, image, imageSize, &numWritten)) {
		wprintf(L"Failed to write remote process memory\n");
		return 1;
	}

	DWORD tid = 0;
	HANDLE hThread = NULL;
	if ((GetCurrentProcessBits() == 64) || (GetCurrentProcessBits() == bits)) {
		RTLCREATEUSERTHREAD fpRtlCreateUserThread = (RTLCREATEUSERTHREAD)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread");
		if (fpRtlCreateUserThread == NULL) {
			wprintf(L"Failed to resolve ntdll!RtlCreateUserThread\n");
			return 1;
		}
		wprintf(L"Calling RtlCreateUserThread\n");
		fpRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)remoteShellcode, NULL, &hThread, NULL);
		if (hThread != NULL)
			wprintf(L"Created remote thread %lu\n", GetThreadIdFromHandle(hThread));
	}
#if defined(_M_IX86)
	else {
		// wow64 -> native 64
		wprintf(L"Switching from Wow64 -> native 64 to run RtlCreateUserThread\n");
		InjectArgs args = { 0 };
		args.start = (UINT64)remoteShellcode;
		args.hProcess = (UINT64)hProc;
		void *rwx = VirtualAlloc(0, sizeof(injectWow64toNative64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		CopyMemory(rwx, injectWow64toNative64, sizeof(injectWow64toNative64));
		ExecuteNative64(rwx, &args);
		if (args.hThread) {
			hThread = (HANDLE)args.hThread;
			wprintf(L"Created remote thread %lu\n", GetThreadIdFromHandle(hThread));
		}
	}
#endif
	if (hThread != NULL)
		return 0;
	return 1;
}

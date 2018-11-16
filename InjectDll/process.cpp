#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef BOOL(WINAPI * FP_IsWow64Process)(HANDLE, BOOL*);

int GetProcessBits(HANDLE hProc)
/* hProc must be opened with PROCESS_QUERY_LIMITED_INFORMATION */
{
	BOOL iswow64 = FALSE;
	FP_IsWow64Process fpIsWow64Process = (FP_IsWow64Process)(GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process"));
	if (fpIsWow64Process == NULL)
		return 32;
	if (fpIsWow64Process(hProc, &iswow64)) {
		return iswow64 ? 32 : 64;
	}
	return 0;
}

int GetCurrentProcessBits()
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		return 64;
	else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return 32;
	return 0;
}

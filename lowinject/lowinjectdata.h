
#include <Windows.h>

#ifndef LOW_INJECT_DATA_H
#define LOW_INJECT_DATA_H

typedef struct _LowData
{
	BOOLEAN has_Initialized;
	ULONG64 ntdll_base;
	ULONG64 nt_wow64_base;
	ULONG64 kernelbase;
	ULONG64 getprocaddress;
	ULONG64 loadlibraryexw;

	ULONG offset_ntdll;
	ULONG offset_kernelbase;
	ULONG offset_wow64_ntdll;
	ULONG offset_wow64_kernelbase;
	ULONG offset_getmodulehandle;
	ULONG offset_loadlibraryexw;
	ULONG offset_injectdll;
	//ULONG* str_LdrLoadDll;

	//PVOID* 
	BOOLEAN wow64;
}LowData, * PLowData;

#endif // !LOW_INJECT_DATA_H


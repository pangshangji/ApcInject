#ifndef DLL_H
#define DLL_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifdef INJECT_EXPORTS
#define DllExports __declspec(dllexport)
#else
#define DllExports __declspec(dllimport)
#endif //INJECT_EXPORTS

DllExports BOOLEAN Inject_SetRootPid(ULONG root_pid);
//DllExports BOOLEAN Inject_SetRootPid(PBYTE *data, int* len, ULONG offset);

DllExports BOOLEAN Inject_SetShellCode(BOOLEAN arch_64bit);

#ifdef __cplusplus
}
#endif


#endif // !DLL_H



#include <Windows.h>
#include <winternl.h>
#include "dll.h"
#include "../lowinject/lowinjectdata.h"
#include "../common/drvdata.h"

HMODULE Dll_Instance = NULL;

BOOL DeviceControlSend(ULONG IoControlCode, PVOID senddata, ULONG datalen);
BOOLEAN Inject_SetRootPid(ULONG root_pid)
{
    return DeviceControlSend(IOCTL_REGISTER_ROOT, &root_pid, sizeof(ULONG));    
}

BOOL DeviceControlSend(ULONG IoControlCode, PVOID senddata, ULONG datalen)
{    
    // 打开设备
    HANDLE deviceHandle = CreateFileW(USERLINK_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // 发送IOCTL请求    
    BOOL ret =  DeviceIoControl(deviceHandle, IoControlCode, senddata, datalen, NULL,0,NULL,NULL);
    

    // 关闭设备
    CloseHandle(deviceHandle);
    return ret;
    //return NT_SUCCESS(status);
}

BOOLEAN Inject_SetShellCode(BOOLEAN arch_64bit)
{
    IMAGE_DOS_HEADER* dos_hdr = 0;
    IMAGE_NT_HEADERS* nt_hdrs = 0;
    IMAGE_SECTION_HEADER* section = 0;
    IMAGE_DATA_DIRECTORY* data_dirs = 0;
    ULONG_PTR imageBase = 0;
    DWORD   AddressOfEntryPoint = 0;
    ULONG controlcode = IOCTL_SETSHELLCODE_64;
    
    HRSRC hrsrc = FindResource(Dll_Instance, TRUE == arch_64bit ? L"LOWLEVEL64" : L"LOWLEVEL32", RT_RCDATA);
    if (!hrsrc) {
        return false;
    }
    ULONG binsize = SizeofResource(Dll_Instance, hrsrc);
    if (!binsize)
        return FALSE;

    HGLOBAL hglob = LoadResource(Dll_Instance, hrsrc);
    if (!hglob)
        return FALSE;

    UCHAR* bindata = (UCHAR*)LockResource(hglob);
    if (!bindata)
        return FALSE;

    
    dos_hdr = (IMAGE_DOS_HEADER*)bindata;

    if (dos_hdr->e_magic == 'MZ' || dos_hdr->e_magic == 'ZM') {
        nt_hdrs = (IMAGE_NT_HEADERS*)((UCHAR*)dos_hdr + dos_hdr->e_lfanew);

        if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)   // 'PE\0\0'
            return FALSE;
        if (nt_hdrs->OptionalHeader.Magic != (arch_64bit ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC))
            return FALSE;

        if (!arch_64bit) {
            IMAGE_NT_HEADERS32* nt_hdrs_32 = (IMAGE_NT_HEADERS32*)nt_hdrs;
            IMAGE_OPTIONAL_HEADER32* opt_hdr_32 = &nt_hdrs_32->OptionalHeader;
            data_dirs = &opt_hdr_32->DataDirectory[0];
            imageBase = opt_hdr_32->ImageBase;
            AddressOfEntryPoint = opt_hdr_32->AddressOfEntryPoint;
        }
        else {
            IMAGE_NT_HEADERS64* nt_hdrs_64 = (IMAGE_NT_HEADERS64*)nt_hdrs;
            IMAGE_OPTIONAL_HEADER64* opt_hdr_64 = &nt_hdrs_64->OptionalHeader;
            data_dirs = &opt_hdr_64->DataDirectory[0];
            imageBase = (ULONG_PTR)opt_hdr_64->ImageBase;
            AddressOfEntryPoint = opt_hdr_64->AddressOfEntryPoint;
        }
    }
    
    if (imageBase != 0) // x64 or x86
        return FALSE;

    section = IMAGE_FIRST_SECTION(nt_hdrs);

    UCHAR* lowcode = bindata + section[0].PointerToRawData;
    DWORD  sizeOfRawData = section[0].SizeOfRawData;
    AddressOfEntryPoint -= section[0].VirtualAddress;
    
    UCHAR code_data[4096 * 2] = {0};
    ULONG offset = 0;
    memcpy(code_data, bindata + section[0].PointerToRawData, sizeOfRawData);
    offset += sizeOfRawData;
    

    LowData data = {0};
    data.has_Initialized = TRUE;
    data.ntdll_base = (ULONG64)GetModuleHandle(L"ntdll.dll");
    data.kernelbase = (ULONG64)GetModuleHandle(L"kernelbase.dll");
    data.getprocaddress = (ULONG64)GetProcAddress((HMODULE)data.kernelbase, "GetProcAddress");
    data.loadlibraryexw = (ULONG64)GetProcAddress((HMODULE)data.kernelbase, "LoadLibrayExW");
    if (TRUE == arch_64bit)
    {
        data.wow64 = FALSE;
        controlcode = IOCTL_SETSHELLCODE_64;
    }
    else
    {
        data.wow64 = TRUE;
        controlcode = IOCTL_SETSHELLCODE_32;
    }
    
    UCHAR* data_start = code_data + sizeOfRawData;
    
    memcpy(data_start, &data, sizeof(LowData));
    UCHAR* data_current = data_start + sizeof(LowData);
    
    data.offset_injectdll = (ULONG)(data_current - data_start);
    WCHAR dll_name[MAX_PATH] = { 0 };
    GetModuleFileName(Dll_Instance, dll_name, ARRAYSIZE(dll_name) - 1);

    if (FALSE == arch_64bit)
    {
        WCHAR* temp = wcsrchr(dll_name, L'\\');
        if (NULL != temp)
        {
            *(temp + 1) = 0;
            wcscat(temp, L"32\\");
            wcscat(temp, L"inject.dll");
        }
    }
    ULONG dll_name_len = (ULONG)wcslen(dll_name);
    wcscpy((WCHAR*)data_current, dll_name);
    data_current += dll_name_len * sizeof(WCHAR) + sizeof(WCHAR);

    

    data.offset_ntdll = (ULONG)(data_current - data_start);
    wcscpy((WCHAR*)data_current, L"\\system32\\ntdll.dll");
    data_current += wcslen(L"\\system32\\ntdll.dll") * sizeof(WCHAR) + sizeof(WCHAR);

    data.offset_kernelbase = (ULONG)(data_current - data_start);
    wcscpy((WCHAR*)data_current, L"\\system32\\kernelbase.dll");
    data_current += wcslen(L"\\system32\\kernelbase.dll") * sizeof(WCHAR) + sizeof(WCHAR);

    data.offset_wow64_ntdll = (ULONG)(data_current - data_start);
    wcscpy((WCHAR*)data_current, L"\\syswow64\\ntdll.dll");
    data_current += wcslen(L"\\syswow64\\ntdll.dll") * sizeof(WCHAR) + sizeof(WCHAR);

    data.offset_wow64_kernelbase = (ULONG)(data_current - data_start);
    wcscpy((WCHAR*)data_current, L"\\syswow64\\kernelbase.dll");
    data_current += wcslen(L"\\syswow64\\kernelbase.dll") * sizeof(WCHAR) + sizeof(WCHAR);

    ULONG all_data_len = (ULONG)(data_current - code_data);
    
    Inject_Code_Data inject_code_data = {0};    
    inject_code_data.code_data = (ULONG64)&code_data;
    inject_code_data.code_data_len = all_data_len;
    inject_code_data.entrypoint_offset = AddressOfEntryPoint;
    inject_code_data.data_offset = sizeOfRawData;
    
    
    return DeviceControlSend(controlcode, &inject_code_data, sizeof(Inject_Code_Data));
    
    return TRUE;   
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Dll_Instance = hModule;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


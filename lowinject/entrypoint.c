#include <Windows.h>
#include <winternl.h>
#include "lowinjectdata.h"




// ��ȡPE�ļ���DOSͷ
PIMAGE_DOS_HEADER GetDosHeader(BYTE* pImageBase) {
    return (PIMAGE_DOS_HEADER)pImageBase;
}

// ��ȡPE�ļ���NTͷ
PIMAGE_NT_HEADERS GetNtHeaders(BYTE* pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = GetDosHeader(pImageBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    return (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);
}

// ��ȡPE�ļ��ĵ�����
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(BYTE* pImageBase) {
    PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(pImageBase);
    if (pNtHeaders == NULL) {
        return NULL;
    }
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return NULL;
    }
    return (PIMAGE_EXPORT_DIRECTORY)(pImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

// ���ݺ���������Ų��ҵ��������ĵ�ַ
FARPROC GetFunctionAddress(BYTE* pImageBase, const char* szFunctionName) {
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = GetExportDirectory(pImageBase);
    if (pExportDirectory == NULL) {
        return NULL;
    }

    DWORD* pAddressOfFunctions = (DWORD*)(pImageBase + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)(pImageBase + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)(pImageBase + pExportDirectory->AddressOfNameOrdinals);

    // ����Ƿ�Ϊ���
    if ((DWORD_PTR)szFunctionName <= 0xFFFF) {
        WORD ordinal = (WORD)(DWORD_PTR)szFunctionName - pExportDirectory->Base;
        if (ordinal < pExportDirectory->NumberOfFunctions) {
            return (FARPROC)(pImageBase + pAddressOfFunctions[ordinal]);
        }
        return NULL;
    }

    // ���ݺ���������
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        const char* szName = (const char*)(pImageBase + pAddressOfNames[i]);
        if (strcmp(szName, szFunctionName) == 0) {
            WORD ordinal = pAddressOfNameOrdinals[i];
            return (FARPROC)(pImageBase + pAddressOfFunctions[ordinal]);
        }
    }

    return NULL;
}

// ��TEB��λ��PEB
PPEB GetPEB() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb;
}

// �Զ���� towlower ����
wchar_t my_towlower(wchar_t ch) {
    if (ch >= L'A' && ch <= L'Z') {
        return ch + (L'a' - L'A');
    }
    return ch;
}

// �Զ���� wcsicmp ����
int my_wcsicmp(const wchar_t* str1, const wchar_t* str2) {
    while (*str1 && *str2) {
        wchar_t ch1 = my_towlower(*str1);
        wchar_t ch2 = my_towlower(*str2);
        if (ch1 != ch2) {
            return (ch1 < ch2) ? -1 : 1;
        }
        str1++;
        str2++;
    }
    if (*str1) return 1; // str1 �� str2 ��
    if (*str2) return -1; // str2 �� str1 ��
    return 0; // �����ַ������
}


// ����DLL���Ʋ���DLL����ַ
HMODULE GetModuleBaseAddress(const wchar_t* szModuleName) {
    PPEB pPeb = GetPEB();
    if (pPeb == NULL) {
        return NULL;
    }

    PLIST_ENTRY pLdr = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    while (pLdr != &pPeb->Ldr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pLdr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->FullDllName.Length > 0) {
            const wchar_t* szName = pEntry->FullDllName.Buffer;
            if (my_wcsicmp(szName, szModuleName) == 0) { // ��Сд�����бȽ�
                return (HMODULE)pEntry->DllBase;
            }
        }
        pLdr = pLdr->Flink;
    }

    return NULL;
}

int main() {
    const wchar_t* szModuleName = L"C:\\Windows\\System32\\kernelbase.dll"; // ָ������·��
    const char* szFunctionName = (LPCSTR)2; // ʹ�����2

    HMODULE hModule = GetModuleBaseAddress(szModuleName);
    if (hModule == NULL) {        
        return 1;
    }

    BYTE* pImageBase = (BYTE*)hModule;
    FARPROC funcAddress = GetFunctionAddress(pImageBase, szFunctionName);
    if (funcAddress == NULL) {    
        return 1;
    }

    
}

BOOLEAN CheckParam(PLowData data)
{
	if (NULL == data)
	{
		return FALSE;
	}
	if (NULL == data->kernelbase)
	{
		data->kernelbase= NtCurrentTeb();
		
	}
	return TRUE;
}

VOID NTAPI EntryPointC(VOID* param)
{	
	PLowData data = (PLowData)param;
	if (FALSE == data->has_Initialized)
	{
		//initialize;
	}
	data->kernelbase = data->ntdll_base;
	CheckParam(data);

	typedef FARPROC	(*PfnGetProcAddress)(HMODULE hModule,LPCSTR lpProcName);
	
	PfnGetProcAddress getproc = (PfnGetProcAddress)data->getprocaddress;
	getproc(data->kernelbase, (PBYTE)data + data->offset_getmodulehandle);


	getproc(data->kernelbase, (PBYTE)data + data->offset_loadlibraryexw);


	return;
}

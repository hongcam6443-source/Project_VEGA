/* halo_gate.h */
#ifndef HALO_GATE_H // Include Guard，防止重复引用
#define HALO_GATE_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ==========================================
// 1. 结构体定义(均为简化版本)
// ==========================================

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    BYTE Padding[4]; 
    PVOID Reserved3[2];
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, *PMY_PEB;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

// Halo Gate 专用结构
typedef struct _HALO_ENTRY {
    DWORD SSN;
    PVOID SyscallAddress;  // 真正的 syscall 指令地址
} HALO_ENTRY, *PHALO_ENTRY;

// ==========================================
// 2. 函数原型声明 (告诉编译器这些函数存在)
// ==========================================

// 工具类
DWORD djb2_hash(WCHAR* str);
DWORD djb2_hash_a(char* str);

// Halo Gate 核心功能
void InitApiTable(PVOID DllBase);
PVOID GetApi(DWORD TargetHash);
BOOL GetHaloEntry(PVOID FunctionAddress, PHALO_ENTRY pEntry);

// 汇编函数声明
extern void SetSSN(DWORD ssn);
extern void SetSyscallAddr(PVOID SyscallAddr);
extern NTSTATUS RunSyscall(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId
);

#endif // HALO_GATE_H
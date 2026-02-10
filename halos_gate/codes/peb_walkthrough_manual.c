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

// djb2 Hash Algorithm (Case Insensitive)
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

#define NTDLL_HASH 0x22d3b5ed

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

            }
        }
        //移动到下一节点
        pCurrentEntry = pCurrentEntry->Flink;
    }

    printf("\n[*] Walkthrough Finished\n");
    getchar();
    return 0;

}//编译： x86_64-w64-mingw32-gcc peb_walkthrough_manual -o ghost_walker.exe -static -w
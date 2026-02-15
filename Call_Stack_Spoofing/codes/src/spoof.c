#include <windows.h>
#include <stdio.h>
#include "spoof.h"
//定一个函数，解析PE文件：dos header->nt header->optional header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]->IMAGE_RUNTIME_FUNCTION_ENTRY
PVOID getRuntimeFunctionEntry(PVOID dllBase, PDWORD pOutFunctionCount){
    // 将基址转化为单字节指针，这是后续所有 RVA 计算的“尺子”
    PBYTE pBase = (PBYTE)dllBase; 
    // 强转获取 DOS 头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        return NULL;
    }
    //利用Dos里面的e_lfanew偏移跳转到Nt header
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE){
        return NULL;
    }
    // 提取异常目录的 RVA
    DWORD exceptionRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    // 提取异常目录的总大小
    DWORD exceptionSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    // 强转为 RUNTIME_FUNCTION 指针数组
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncs = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pBase + exceptionRva);
    // 计算数组里到底有多少个函数条目
    DWORD functionCount = exceptionSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    *pOutFunctionCount = functionCount;
    printf(".pdata walkthrough finished, %d runtime function found...\n", functionCount);
    return pRuntimeFuncs;
}

// 定义在文件顶部或全局范围
SPOOF_GADGET GoldenGadgets[100]; 
DWORD g_GadgetCount = 0; // 全局计数器，记录我们到底找到了多少个合格的傀儡
//搜集傀儡Gadget
void unWindInfoResolution(PBYTE pBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncAddr, PDWORD pFuncCount){
    for(int i=0; i<*pFuncCount; i++){
        PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)(pBase + pRuntimeFuncAddr[i].UnwindInfoAddress);//我们只关注IMAGE_RUNTIME_FUNCTION_ENTRY的第三个成员：UnwindInfoAddress。这样我们就可以去读取没一个UnwindInfo结构体了
        if(pUnwindInfo->Flags !=0 || pUnwindInfo->FrameRegister != 0){
            continue;//排除掉包含异常处理机制的函数以及依赖rbp的复杂栈帧
        }
        //现在我们要遍历检查pUnwindInfo->UnwindCode，寻找特定的操作码
        int idx = 0; //逻辑变量
        int size = 0; //储存栈大小
        while(idx < (pUnwindInfo->CountOfCodes)){
            // 提前提取出 OpCode 和 OpInfo，让代码更干净
            BYTE opCode = pUnwindInfo->UnwindCode[idx].UnwindOp;
            BYTE opInfo = pUnwindInfo->UnwindCode[idx].OpInfo;

            switch(opCode){
                case UWOP_PUSH_NONVOL:
                    idx += 1;
                    size += 8;
                    break;
                case UWOP_ALLOC_SMALL:
                    idx += 1;
                    size += (opInfo * 8) + 8;
                    break;
                case UWOP_SET_FPREG:
                    idx += 1;
                    size += 0;
                    break;
                case UWOP_ALLOC_LARGE:
                    // 修正 4：把两个 LARGE 合并，通过 opInfo 分支判断
                    if(opInfo == 0){
                        // 大小记录在下一个节点的 FrameOffset 中，且需乘以 8
                        size += (pUnwindInfo->UnwindCode[idx + 1].FrameOffset * 8);
                        idx += 2; // 消耗 2 个节点
                    } 
                    else if (opInfo == 1){
                        // 终极大小：占用后两个节点，需要做 Bitwise OR (按位或) 拼成 32 位整数
                        // 注意 Endianness (字节序) 拼接
                        size += (pUnwindInfo->UnwindCode[idx + 1].FrameOffset | 
                                (pUnwindInfo->UnwindCode[idx + 2].FrameOffset << 16));
                        idx += 3; // 消耗 3 个节点
                    }
                    break;
                case UWOP_SAVE_NONVOL:
                case UWOP_SAVE_XMM128:
                    idx += 2;
                    size += 0;
                    break;
                case UWOP_SAVE_NONVOL_FAR:
                case UWOP_SAVE_XMM128_FAR:
                    idx += 3;
                    size += 0;
                    break;
                default:
                    //printf("[-] 未知机器码，强行+1");
                    idx += 1;
                    break;
            }
        }
        if(size<32 || size>1024){
            continue;//过滤栈的大小
        }
        //内存搜索逻辑
        PBYTE pFuncCode = pBase + pRuntimeFuncAddr[i].BeginAddress;//当前函数真实的起始位置
        DWORD dwFuncSize = pRuntimeFuncAddr[i].EndAddress - pRuntimeFuncAddr[i].BeginAddress;//函数范围
        PVOID pFoundGadget = NULL; //Gadget地址
        for(DWORD j=0; j<dwFuncSize-8; j++){//预留尾部空间
            if(size <= 0x7F){
                if(pFuncCode[j] == 0x48 && pFuncCode[j+1] == 0x83 && pFuncCode[j+2] == 0xC4 && pFuncCode[j+3] == (BYTE)(size) && pFuncCode[j+4] == 0xC3){
                    pFoundGadget = (PVOID)(pFuncCode + j);
                    break;
                }
            }
            else{
                if(pFuncCode[j] == 0x48 && pFuncCode[j+1] == 0x81 && pFuncCode[j+2] == 0xC4 && *(PDWORD)(&pFuncCode[j+3]) == (DWORD)size && pFuncCode[j+7] == 0xC3){
                    pFoundGadget = (PVOID)(pFuncCode + j);
                    break;
                }
            }
        }
        //入库
        if(pFoundGadget != NULL){
            if (g_GadgetCount < 100) {
                GoldenGadgets[g_GadgetCount].pGadgetAddress = pFoundGadget;
                GoldenGadgets[g_GadgetCount].dwStackSize = size;
                g_GadgetCount++;
                
                // 找到一个打印一个，享受丰收的喜悦
                printf("[+] Found Gadget: Address 0x%p, Stack Size: %d bytes\n", pFoundGadget, size);
            }
        }
    }
}
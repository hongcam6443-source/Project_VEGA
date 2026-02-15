#pragma once
#include <windows.h>

// -----------------------------------------------------------------
// Unwind Operation Codes (回溯操作码)
// 解释：这些宏定义指示了函数在 Prologue (序言) 中是如何修改 RSP (栈指针寄存器) 的。
// -----------------------------------------------------------------
#define UWOP_PUSH_NONVOL      0  // 压入非易失性寄存器 (如 RBX, RDI)，每次占用 8 字节栈空间
#define UWOP_ALLOC_LARGE      1  // 分配大块栈空间 (占用后续 1 到 2 个节点来记录大小)
#define UWOP_ALLOC_SMALL      2  // 分配小块栈空间 (公式：大小 = OpInfo * 8 + 8)
#define UWOP_SET_FPREG        3  // 设置帧指针 (如将 RBP 指向 RSP)
#define UWOP_SAVE_NONVOL      4  // 保存非易失性寄存器到栈上 (仅移动数据，不改变 RSP)
#define UWOP_SAVE_NONVOL_FAR  5  // 同上，但偏移量更大 (占用后续 2 个节点)
#define UWOP_SAVE_XMM128      8  // 保存 XMM (128位扩展多媒体) 寄存器 (不改变 RSP)
#define UWOP_SAVE_XMM128_FAR  9  // 同上，远偏移 (占用后续 2 个节点)
#define UWOP_PUSH_MACHFRAME   10 // 压入硬件机器帧 (通常在发生硬件异常中断时出现)

// ---------    --------------------------------------------------------
// UNWIND_CODE (回溯代码节点，固定为 2 字节 / 16 位)
// -----------------------------------------------------------------
typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;        // 指令在 Prologue (序言) 中的偏移量
        BYTE UnwindOp : 4;      // 操作码 (低 4 位，对应上面的 UWOP_ 宏)
        BYTE OpInfo   : 4;      // 操作附加信息 (高 4 位，用于寄存器编号或小块分配的计算)
    };
    USHORT FrameOffset;         // 某些操作 (如大块分配) 会跨节点，此处用于直接读取 16 位数据
} UNWIND_CODE, *PUNWIND_CODE;

// -----------------------------------------------------------------
// UNWIND_INFO (回溯信息主结构体)
// -----------------------------------------------------------------
typedef struct _UNWIND_INFO {
    BYTE Version       : 3;     // 版本号 (低 3 位)
    BYTE Flags         : 5;     // 标志位 (高 5 位)；0 表示没有异常处理函数 (这是我们的黄金目标)
    BYTE SizeOfProlog;          // Prologue (序言) 的总字节数
    BYTE CountOfCodes;          // UnwindCode 数组的元素个数 (注意：是节点数量，不是字节数)
    BYTE FrameRegister : 4;     // 如果使用了帧指针(如 RBP)，这里记录其编号；0 表示未使用
    BYTE FrameOffset   : 4;     // 帧指针距离 RSP (栈指针寄存器) 的偏移量 (计算时需乘以 16)
    
    // Variable-Length Array (变长数组，紧跟在结构体后面)
    UNWIND_CODE UnwindCode[1];  
} UNWIND_INFO, *PUNWIND_INFO;

// 存放合适的傀儡函数
typedef struct _SPOOF_GADGET {
    PVOID pGadgetAddress;  // 完美的返回地址：指向 "add rsp, size; ret" 的绝对内存地址
    DWORD dwStackSize;     // 栈大小：告诉我们的汇编引擎需要 sub rsp 多少字节
} SPOOF_GADGET, *PSPOOF_GADGET;

extern SPOOF_GADGET GoldenGadgets[100]; 
extern DWORD g_GadgetCount;

// 在 spoof.h 中添加原型声明
PVOID getRuntimeFunctionEntry(PVOID dllBase, PDWORD pOutFunctionCount);
void unWindInfoResolution(PBYTE pBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncAddr, PDWORD pFuncCount);
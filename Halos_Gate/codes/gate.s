.intel_syntax noprefix
.global SetSSN
.global RunSyscall
.global SetSyscallAddr

.data
    wSystemCall: .long 0
    qSyscallAddr: .quad 0

.text
SetSSN:
    xor eax, eax
    mov dword ptr [rip + wSystemCall], ecx
    ret
    
SetSyscallAddr:
    mov [rip + qSyscallAddr], rcx
    ret

RunSyscall:
    mov r10, rcx
    mov eax, dword ptr [rip + wSystemCall]
    jmp qword ptr [rip + qSyscallAddr] 
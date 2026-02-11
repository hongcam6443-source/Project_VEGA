# 📂 Project VEGA: Strategic Roadmap (Archive 2026)

> **"Slow is smooth, smooth is fast."**
> **当前状态:** Phase 1 Completed (Halo's Gate V1)
> **挂起原因:** 主线任务优先 (毕业论文)

---

## 🏁 Phase 1: The Foundation (已完成)
**Module:** `Halo's Gate V1 (Direct Execution)`
* **核心成就:**
    * [x] **无 API 解析:** 抛弃 `GetProcAddress`，使用 PEB 遍历 + DJB2 Hash 查找导出表。
    * [x] **动态 SSN 获取:** 实现 Halo's Gate 双向搜索逻辑 (Down/Up Search)，在邻居函数中自动推导被 Hook 函数的 SSN。
    * [x] **手动发射:** 使用汇编 (`gate.s`) 直接构建 syscall 指令，绕过 Ring 3 API 入口。
* **当前特征:**
    * User Mode Dropper。
    * RIP 指针指向 EXE 自身 (High Risk)。
    * 调用栈回溯异常 (High Risk)。

---

## 🚀 Phase 1.5: The Trampoline (下一步计划)
**Module:** `Indirect Halo's Gate`
**优先级:** ⭐⭐⭐⭐⭐ (最高 - 必须做的生存升级)

* **战术目标:**
    * 解决 "RIP Betrayal" 问题。让系统调用的来源看起来是从合法的 `ntdll.dll` 发出的，而不是我们的未知内存。
* **技术原理:**
    * **寻找蹦床 (Trampoline Hunting):** 在 `ntdll.dll` 中搜索合法的 `syscall; ret;` 指令序列（机器码 `0F 05 C3`）。
    * **借刀杀人:** 在汇编中不再直接写 `syscall`，而是将 SSN 放入 `eax` 后，使用 `jmp [ntdll_syscall_address]` 跳转过去执行。
* **预期效果:**
    * EDR 看到的 RIP 指针位于 `ntdll.dll` 合法区域。
    * 大幅降低“异常系统调用”的启发式检出率。

---

## 👔 Phase 1.8: The Suit (进阶伪装)
**Module:** `Call Stack Spoofing`
**优先级:** ⭐⭐⭐ (中 - 增强隐蔽性)

* **战术目标:**
    * 解决 "Stack Unwinding" 问题。欺骗 EDR 的栈回溯扫描 (Stack Walking)。
* **技术原理:**
    * **栈帧伪造 (Frame Faking):** 在进行系统调用前，手动修改栈上的返回地址 (Return Address)，使其指向某个合法的系统模块 (如 `kernel32.dll` 或 `rpcrt4.dll`) 的代码间隙。
    * **ROP 链:** 利用 Return-Oriented Programming 技术维持控制流。
* **预期效果:**
    * 在 EDR 进行内存扫描时，线程的调用栈看起来完全合法（例如：`kernel32 -> ntdll -> kernel`），掩盖 payload 的存在。

---

## 👻 Phase 2: The Silence (终极目标)
**Module:** `Kernel Rootkit`
**优先级:** ⭐ (远期 - 降维打击)

* **战术目标:**
    * 从 Ring 0 层面抹除痕迹，实现完美隐身。
* **技术原理:**
    * **DKOM (Direct Kernel Object Manipulation):** 直接操作内核对象。
    * **断链 (Unlinking):** 从 `ActiveProcessLinks` 链表中摘除进程结构体 (`EPROCESS`)，让任务管理器和普通 EDR 无法列出进程。
    * **回调摘除 (Callback Removal):** 移除杀软注册的内核回调 (Process/Image/Thread Callbacks)，致盲杀软。

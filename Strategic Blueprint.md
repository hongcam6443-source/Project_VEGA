# 📂 Project VEGA: Strategic Blueprint 

> **Target:** Top-Tier CS Graduate Program Application Portfolio
> **Codename:** "The Faceless God" (Identity Module)
> **Status:** 🧊 Frozen (Pending Thesis Completion)

---

## 🏛️ The Philosophy (设计哲学)

**"We don't break the door; we become the key."**

我们要构建的不是一个简单的恶意软件，而是一个**高级系统对抗框架 (Advanced System Evasion Framework)**。它利用 Halo's Gate (间接系统调用) 绕过 EDR 的监控，通过精密的令牌操作 (Token Manipulation) 实现权限的静默流转，最终为内核级 Rootkit 打开大门。

---

## 🎭 Module II: The Faceless God (身份模块)

**核心概念:** `Token Stealing & Impersonation` (令牌窃取与模拟)
**技术定位:** 连接 User Mode (Halo's Gate) 与 Kernel Mode (Rootkit) 的桥梁。

### 1. The Objective (战术目标)
不依赖任何漏洞 (Exploit)，仅通过滥用合法的系统机制 (Native API)，将当前进程从普通用户权限 (User) 提升至系统最高权限 (SYSTEM)。这是加载后续 Rootkit 驱动的必要前置条件。

### 2. The Architecture (技术架构)

本模块将完全基于 **Halo's Gate (Indirect Syscalls)** 构建，实现“无文件、无痕迹”的提权。

#### Step 1: Hunter (猎杀)
* **Action:** 遍历系统进程，寻找持有 SYSTEM 令牌的目标（通常是 `winlogon.exe` 或 `lsass.exe`）。
* **Tech:** 不使用 `CreateToolhelp32Snapshot` (太吵)。
* **Implementation:** 手动解析 `NtQuerySystemInformation` 系统调用，在内存中过滤 PID。

#### Step 2: Breach (渗透)
* **Action:** 获取目标进程的句柄。
* **Tech:** `NtOpenProcess` via **Indirect Halo's Gate**。
* **Evasion:** 利用 `ntdll.dll` 中的 `syscall; ret` 跳板指令，规避 EDR 对 `OpenProcess` 的高危行为监控。

#### Step 3: Theft (窃取)
* **Action:** 打开并复制目标进程的 Access Token。
* **Tech:**
    * `NtOpenProcessToken` (获取原始令牌)
    * `NtDuplicateToken` (复制令牌，并设置 `SecurityImpersonation` 级别)

#### Step 4: Masquerade (伪装)
* **Action:** 将窃取来的 SYSTEM 令牌“戴”在当前线程头上。
* **Tech:** `NtSetInformationThread` (ThreadImpersonationToken)。
* **Result:** 线程身份瞬间变更。操作系统将把你看作 `SYSTEM` 用户。

---

## 🗓️ Execution Roadmap (执行路线)

### Phase 0: The Pause (当前)
* **任务:** 完成毕业论文。
* **意义:** 获得通往学术界的合法“句柄” (Degree)。

### Phase 1: The Awakening (回归)
* **任务:** 实现 **Indirect Halo's Gate** (解决 RIP 指针问题)。
* **产出:** `ghost_walker_v4.exe` (具备蹦床机制的 Loader)。

### Phase 2: The Heist (开发)
* **任务:** 编写 `The Faceless God` 模块。
* **产出:** 实现从普通用户到 SYSTEM 的提权演示。

### Phase 3: The Crown (终局)
* **任务:** 利用 SYSTEM 权限加载自写驱动 (Rootkit)。
* **产出:** 实现进程隐藏 (DKOM)。完成 Project VEGA 闭环。

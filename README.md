# 🎯 PROJECT: VEGA
**Objective**: A low-level Windows in-process stealth framework in C, focusing on EDR evasion via direct syscalls, memory manipulation, and telemetry disruption.
**Environment**: Kali Linux (Cross-compile) / Windows 11 Physical Machine (with Windows 10 VM).

## 1. CURRENT VECTOR (Completed Operations & Mechanics)
- [x] **Halo's Gate + Indirect Syscall**: Implemented via manual parsing of the `ntdll.dll` PE headers in memory to dynamically resolve syscall numbers, bypassing user-land hooks, and executing them through legitimate `ntdll` memory addresses to spoof the call source.
- [x] **Call Stack Spoofing**: Achieved by parsing the `.pdata` section (Exception Directory) of legitimate modules to dynamically locate valid ROP gadgets, reconstructing a synthetic, legitimate-looking call frame prior to the syscall execution.
- [x] **ETW Blinding**: Executed via direct memory overwrite (patching) of the corresponding Event Tracing for Windows (ETW) functions (e.g., `EtwEventWrite`) to silence user-mode telemetry generation.

## 2. ACTIVE ROADBLOCKS (Tactical Bottlenecks)
- **The PIC Dependency Hell**: Attempting cross-process operations (Process Hollowing/Module Stomping) introduced exponential code redundancy and unmanageable Position-Independent Code (PIC) assembly requirements.
- **The Anomaly of Perfection**: Bypassing all user-land hooks for high-level APIs (like `WinHTTP`) creates a behavioral "black hole." EDRs view the absolute absence of telemetry during a network connection as a critical red flag.

## 3. COMMANDER DIRECTIVES (Strategic Memory)
- **Tactical Downgrade (In-Process Only)**: Abandon cross-process injection. VEGA must operate as a standalone, self-contained in-process framework to maximize developer sanity and execution stability.
- **The "Good Citizen" Camouflage**: Stop trying to be completely invisible on the network layer. Accept standard EDR API hook scrutiny for network calls, but utilize traffic shaping and timing jitter to blend in with legitimate system noise.
- **Zero Script-Kiddie Payloads**: Absolute prohibition of MSFvenom or other heavily signature-based payloads. 
- **Core Philosophy**: "Perfection is the enemy of execution in cyber warfare. We don't build invisible ghosts; we build anomalies that are too expensive for the Blue Team to analyze."
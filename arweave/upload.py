"""
upload.py — Upload combined data.enc to Arweave.

The file must be in the combined format produced by Encrypt.py:
    hex_key|hex_nonce|size|compressed|<binary encrypted payload>

The loader finds the TX via GraphQL (owners + App-Name=zero-loader tag)
and extracts the key/nonce from the embedded header — no separate key TX needed.

Usage:
    python upload.py <data.enc> [wallet.json] [--json]

    --json   Machine-readable output (used by web console / server.py)

Requirements:
    pip install arweave-python-client
"""

import json
import os
import re
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from arweave.arweave_lib import Wallet, Transaction
except ImportError:
    raise SystemExit("Run: pip install arweave-python-client")

_COMBINED_HDR_RE = re.compile(rb'^[0-9a-f]{32}\|[0-9a-f]{24}\|\d+\|[01]\|')
_TX_ID_RE        = re.compile(r'^[A-Za-z0-9_-]{43}$')


def _upload(wallet: Wallet, data: bytes, extra_tags: dict | None = None) -> str:
    tx = Transaction(wallet, data=data)
    tx.add_tag("Content-Type", "application/octet-stream")
    tx.add_tag("App-Name",     "ArSync")
    tx.add_tag("Content-Class", "bundle")
    if extra_tags:
        for k, v in extra_tags.items():
            tx.add_tag(k, v)
    tx.sign()
    resp = tx.send()
    if hasattr(resp, "status_code") and resp.status_code not in (200, 208):
        try:
            detail = resp.text[:200]
        except Exception:
            detail = str(resp)
        raise RuntimeError(f"Node rejected TX (HTTP {resp.status_code}): {detail}")
    return tx.id


def publish(data_enc_path: str, wallet_path: str, json_mode: bool = False) -> dict:
    def log(msg):
        if not json_mode:
            print(msg)

    if not os.path.exists(data_enc_path):
        return {"ok": False, "error": f"File not found: {data_enc_path}"}
    if not os.path.exists(wallet_path):
        return {"ok": False, "error": f"Wallet not found: {wallet_path}"}

    data = open(data_enc_path, "rb").read()

    if not _COMBINED_HDR_RE.match(data[:120]):
        return {"ok": False, "error": "Not a combined-format file. Re-run Encrypt.py."}

    log(f"[*] File   : {data_enc_path} ({len(data):,} bytes)")

    try:
        wallet  = Wallet(wallet_path)
        balance = wallet.balance
        log(f"[*] Wallet : {wallet.address}")
        log(f"[*] Balance: {balance} AR")
    except Exception as e:
        return {"ok": False, "error": f"Failed to load wallet: {e}"}

    if float(balance) == 0.0:
        return {"ok": False, "error": f"Wallet has 0 AR — fund {wallet.address} first."}

    log("[*] Uploading to Arweave …")
    try:
        tx_id = _upload(wallet, data)
    except Exception as e:
        return {"ok": False, "error": f"Upload failed: {e}"}

    if not _TX_ID_RE.match(tx_id):
        return {"ok": False, "error": f"Unexpected TX ID format: {tx_id}"}

    url = f"https://arweave.net/{tx_id}"
    log(f"\n[+] Upload complete")
    log(f"    TX ID  : {tx_id}")
    log(f"    URL    : {url}")
    log(f"    Note   : confirmation takes 10-30 min; C loader retries automatically.")

    return {"ok": True, "wallet_address": wallet.address, "tx_id": tx_id, "data_url": url}


if __name__ == "__main__":
    args      = sys.argv[1:]
    json_mode = "--json" in args
    args      = [a for a in args if a != "--json"]

    if not args:
        print("Usage: python upload.py <data.enc> [wallet.json] [--json]")
        sys.exit(1)

    data_enc    = args[0]
    wallet_path = args[1] if len(args) > 1 else os.path.join(_SCRIPT_DIR, "wallet.json")

    result = publish(data_enc, wallet_path, json_mode)

    if json_mode:
        print(json.dumps(result))
    elif not result["ok"]:
        print(f"[!] {result['error']}", file=sys.stderr)
        sys.exit(1)

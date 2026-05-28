#!/usr/bin/env python3
"""
create_wallet.py — Generate a new Solana Ed25519 keypair.

CLI usage:
    python create_wallet.py [--out wallet]

    Writes:
      <out>.json      — 64-byte keypair as a JSON int array
                        (Solana CLI / Phantom / Backpack import compatible)
      <out>.info.txt  — human-readable: public address + base58 private key

JSON mode (used by the web console / server):
    python create_wallet.py --json
    → prints one-line JSON to stdout:
      {"public_key": "...", "keypair_bytes": [0..255, ...64 values...]}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from solders.keypair import Keypair
except ImportError:
    sys.exit("ERROR: solders not installed.  Run: pip install -r requirements.txt")


# ---------------------------------------------------------------------------
# Minimal base58 encoder (no external dep needed for wallet creation output)
# ---------------------------------------------------------------------------
_B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHA[r])
    for byte in data:
        if byte == 0:
            out.append(_B58_ALPHA[0])
        else:
            break
    return "".join(reversed(out))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Create a new Solana wallet keypair")
    ap.add_argument("--out",  default="wallet",
                    help="Output filename stem (default: wallet)")
    ap.add_argument("--json", dest="json_mode", action="store_true",
                    help="Print JSON to stdout instead of writing files")
    args = ap.parse_args()

    kp  = Keypair()
    raw = bytes(kp)         # 64 bytes: 32-byte seed || 32-byte compressed pubkey
    pub = str(kp.pubkey())  # base58 Solana address

    if args.json_mode:
        print(json.dumps({"public_key": pub, "keypair_bytes": list(raw)}))
        return

    # ---- write files ----
    json_path = Path(f"{args.out}.json")
    info_path = Path(f"{args.out}.info.txt")

    json_path.write_text(json.dumps(list(raw)))
    info_path.write_text(
        f"Public key (address) : {pub}\n"
        f"Private key (base58) : {b58encode(raw)}\n"
        f"Keypair JSON file    : {json_path.resolve()}\n"
    )

    print(f"[+] Address     : {pub}")
    print(f"[+] Keypair JSON: {json_path.resolve()}")
    print(f"[+] Info file   : {info_path.resolve()}")
    print()
    print("Keep the keypair JSON secret — it contains your full private key.")
    print("Fund the address before publishing (~0.000005 SOL per transaction).")


if __name__ == "__main__":
    main()

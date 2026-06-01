"""
create.py — Generate a new Arweave wallet and save it to wallet.json.

Usage:
    python create.py [output.json]
    python create.py --json        (machine-readable, used by web console)

Requirements:
    pip install arweave-python-client python-jose pycryptodome
"""

import json
import os
import sys

from Crypto.PublicKey import RSA
from jose.utils import base64url_encode

try:
    from arweave.arweave_lib import Wallet
except ImportError:
    raise SystemExit("Run: pip install arweave-python-client python-jose pycryptodome")


def _int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64url_encode(n.to_bytes(length, "big")).decode()


def generate_jwk(silent: bool = False) -> dict:
    if not silent:
        print("Generating RSA-4096 key pair …")
    key = RSA.generate(4096)
    return {
        "kty": "RSA",
        "n":   _int_to_b64url(key.n),
        "e":   _int_to_b64url(key.e),
        "d":   _int_to_b64url(key.d),
        "p":   _int_to_b64url(key.p),
        "q":   _int_to_b64url(key.q),
        "dp":  _int_to_b64url(key.d % (key.p - 1)),
        "dq":  _int_to_b64url(key.d % (key.q - 1)),
        "qi":  _int_to_b64url(pow(key.q, -1, key.p)),
    }


def create_wallet(output_path: str = "wallet.json") -> dict:
    jwk  = generate_jwk()
    addr = Wallet.from_data(jwk).address
    with open(output_path, "w") as f:
        json.dump(jwk, f, indent=2)
    print(f"\n[+] Wallet created")
    print(f"    Address : {addr}")
    print(f"    Key file: {os.path.abspath(output_path)}")
    print(f"\n[!] Keep your key file safe — it cannot be recovered if lost.")
    return {"address": addr, "key_file": output_path}


def create_wallet_json() -> dict:
    """Return address + JWK as dict (used by server.py --json mode)."""
    jwk = generate_jwk(silent=True)
    return {"public_key": Wallet.from_data(jwk).address, "wallet_jwk": jwk}


if __name__ == "__main__":
    if "--json" in sys.argv:
        print(json.dumps(create_wallet_json()))
    else:
        args = [a for a in sys.argv[1:] if not a.startswith("-")]
        create_wallet(args[0] if args else "wallet.json")

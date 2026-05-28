#!/usr/bin/env python3
"""
lookup_memo.py — Scan a Solana wallet's recent transactions for an SPL Memo
                  posted BY that wallet (fee payer verification included).

How it works
────────────
1. getSignaturesForAddress(wallet, limit=N)
   Each result entry already contains a "memo" field — the SPL Memo program
   text — so we can filter for our 4-pipe format without calling getTransaction
   on every entry.

2. For each entry whose "memo" matches <url>|<key>|<nonce>|<size>|<flag>:
   Call getTransaction(sig) once and check accountKeys[0] == wallet.
   The fee payer (index 0) is always the transaction sender.
   This rejects memos sent TO the wallet by third parties and prevents
   forged-memo attacks (attacker cannot pass the fee payer check).

CLI usage:
    python lookup_memo.py <wallet_address> [options]

Options:
    --rpc   <url>   Solana RPC endpoint (default: api.mainnet-beta.solana.com)
    --limit <N>     Max transaction signatures to scan (default 10, max 1000).
                    Raise this only if your wallet has many non-memo transactions
                    interleaved with the memo you are looking for.
    --json          Print result as one-line JSON to stdout.
                    {"found": true, "memo": "...", "signature": "..."}
                    {"found": false}

Examples:
    # Show latest verified memo (human-readable)
    python lookup_memo.py AbCd1234...44chars

    # Custom RPC, JSON output
    python lookup_memo.py AbCd1234...44chars --rpc https://api.devnet.solana.com --json
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed.  Run: pip install -r requirements.txt")

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def rpc_post(rpc_url: str, method: str, params: list) -> dict:
    try:
        r = requests.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"_net_error": str(e)}


def verify_fee_payer(rpc_url: str, signature: str, wallet: str) -> bool:
    """Return True if the fee payer (accountKeys[0]) of `signature` is `wallet`."""
    data = rpc_post(rpc_url, "getTransaction", [
        signature,
        {"encoding": "json", "maxSupportedTransactionVersion": 0},
    ])
    if "_net_error" in data:
        return False
    result = (data.get("result") or {})
    msg    = (result.get("transaction") or {}).get("message") or {}
    keys   = msg.get("accountKeys") or []
    return bool(keys) and keys[0] == wallet


# ---------------------------------------------------------------------------
# Core lookup
# ---------------------------------------------------------------------------

def lookup(address: str, rpc_url: str, limit: int) -> dict:
    """
    Scan up to `limit` recent transactions from `address` for a valid
    SPL Memo in our 4-pipe format that was sent BY `address` (fee payer check).

    Returns newest-first; stops at the first verified match.
    """
    data = rpc_post(rpc_url, "getSignaturesForAddress", [
        address, {"limit": limit}
    ])
    if "_net_error" in data:
        return {"found": False, "error": data["_net_error"], "memo": None, "signature": None}
    if "error" in data:
        return {"found": False, "error": data["error"], "memo": None, "signature": None}

    sigs = data.get("result") or []
    if not sigs:
        return {"found": False, "memo": None, "signature": None, "scanned": 0}

    # getSignaturesForAddress returns newest-first; iterate in that order.
    for i, entry in enumerate(sigs):
        # Each entry has a "memo" field containing the SPL Memo text,
        # or null if the transaction has no memo.
        memo_text = entry.get("memo")
        if not memo_text:
            continue

        # Our format: <url>|<32hex-key>|<24hex-nonce>|<decimal-size>|<0-or-1>
        if memo_text.count("|") < 4:
            continue

        sig = entry["signature"]

        # Fee payer check: only accept transactions WE sent.
        # This prevents: (1) inbox spam pushing our memo out of the window,
        # (2) someone crafting a matching memo and sending it to our wallet.
        if not verify_fee_payer(rpc_url, sig, address):
            continue

        return {
            "found":     True,
            "memo":      memo_text,
            "signature": sig,
            "slot":      entry.get("slot"),
            "scanned":   i + 1,
        }

    return {"found": False, "memo": None, "signature": None, "scanned": len(sigs)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Look up a verified SPL Memo from a Solana wallet's transactions"
    )
    ap.add_argument("address",       help="Solana wallet address (base58)")
    ap.add_argument("--rpc",         default=DEFAULT_RPC, help="Solana RPC endpoint URL")
    ap.add_argument("--limit",       type=int, default=10,
                    help="Max signatures to scan (default 10)")
    ap.add_argument("--json",        dest="json_mode", action="store_true",
                    help="Print result as one-line JSON to stdout")
    args = ap.parse_args()

    limit  = min(max(args.limit, 1), 1000)
    result = lookup(args.address, args.rpc, limit)

    if args.json_mode:
        print(json.dumps(result))
        return

    if result.get("found"):
        print(f"[+] Memo found  (scanned {result.get('scanned', '?')} tx(s))")
        print(f"    Signature : {result['signature']}")
        if result.get("slot"):
            print(f"    Slot      : {result['slot']}")
        print(f"    Memo text :")
        print(f"    {result['memo']}")
    else:
        scanned = result.get("scanned", 0)
        print(f"[-] No verified memo found in last {scanned} transaction(s)")
        if result.get("error"):
            print(f"    Error: {result['error']}")


if __name__ == "__main__":
    main()

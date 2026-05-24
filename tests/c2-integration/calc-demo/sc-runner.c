// Minimal shellcode runner — no loader, just VirtualAlloc + cast + call.
// If this pops calc, shellcode bytes are fine and the bug is in our loader path.
#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE hFile = CreateFileA("calc-shellcode.bin", GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("open fail\n"); return 1; }
    DWORD sz = GetFileSize(hFile, NULL);
    LPVOID mem = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD got = 0;
    ReadFile(hFile, mem, sz, &got, NULL);
    CloseHandle(hFile);
    printf("loaded %lu bytes at %p\n", got, mem);
    ((void(*)(void))mem)();
    return 0;
}

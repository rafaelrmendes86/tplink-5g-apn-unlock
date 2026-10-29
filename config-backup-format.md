# Config backup format (`conf.bin`) — reverse-engineering notes

> Status: **fully reversed and verified end-to-end** — a real unit's `conf.bin`
> decrypts to its `DslCpeConfig` XML. The DES is standard; the per-device key value
> (`DEVVAL`) is recoverable by brute force with the oracle below, or read from a root
> shell. Config-level analysis of a device you own — no vendor code, keys or device
> values are redistributed here.

The NX511v / NX510v family (Qualcomm IPQ + Aginet/`libcmm` userspace) lets you
**Backup / Restore** the configuration from the web UI as an encrypted `conf.bin`.
This is interesting because a *config* Restore is accepted by the web UI **without a
root shell** — so if the format is understood, it is a modification path that could
survive on the hardened, shell-less builds (1.3.0 / 1.30.0) where the runtime method
no longer applies. The config format is independent of the firmware signing/encryption.

## Pipeline

Backup does, in order (`rsl_sys_backupCfg` → `dm_backupCfg` in `libcmm.so`):

1. **Serialize** the running datamodel to **XML** — `<?xml version="1.0"?><DslCpeConfig>…</DslCpeConfig>` (this is the plaintext). Note it is *pseudo*-XML: attributes are unquoted integers (`val=180`) alongside quoted strings, so a strict XML parser will reject it.
2. **Compress** with a custom **LZSS** (`cen_compressBuff` in `libcutil.so`). Output `C` layout:
   `[4-byte little-endian uncompressed length][LZSS stream]`.
3. **Prepend a 16-byte header/digest** `H`, giving `H || C`.
4. **Encrypt** the whole thing with **DES** in **ECB** mode (`cen_desMinDo` in `libcutil.so`). `libcutil`
   bundles the stock OpenSSL DES `SP-box` table, so this is **standard DES**, not a custom
   cipher — it decrypts with `openssl enc -d -des-ecb` (on OpenSSL 3.x add
   `-provider legacy -provider default`).

So on disk: `conf.bin = DES_ECB_encrypt( H[16] || C )`, length a multiple of 8 with no
plaintext header before the ciphertext. Restore reverses it (DES-decrypt, then
`cen_uncompressBuff` on `C`, which is the plaintext **starting at offset +16**).

> ⚠️ **The gotcha that costs you days:** the 16-byte prefix `H` is **not** part of the
> LZSS stream, and it is **not** `MD5(C)` (that natural guess is wrong — it does not
> match). `C` — and therefore the 4-byte length field — begins at **offset 16**, not 0.
> If you feed the LZSS decompressor from offset 0, or validate a key by checking the
> first 4 bytes as the length, it fails for *every* key including the correct one. Decrypt,
> then skip 16 bytes.

## Key derivation (`getBackNRestoreK`)

The 8-byte DES key is **not** fixed and **not** a login password. Disassembled
byte-for-byte, it is:

```
key[i] = CONST8[i]  XOR  ascii("%08x" % DEVVAL)[i]      for i = 0..7
```

- `CONST8` = `74 8d a5 0b f9 3e 2d cf` — a fixed 8-byte constant embedded in `libcmm.so`
  (same for every unit of the model).
- `DEVVAL` = a **per-device 32-bit value** read from the datamodel device-info object
  (`dm_getObj(type=2, objId=0x698)`; the value lands at offset `0x4e0` of the returned
  object), formatted as **8 lowercase hex characters**. The code logs
  `"Get dev info for BNR key"` on failure. This is what makes each unit's backup
  decryptable only with that unit's value (anti-cloning).

So a full decrypt needs `DEVVAL` for *your* unit. In testing it is **not** a plain CRC32
of the serial or MAC; it is a factory/datamodel value. On a build where you still have a
root shell you can read it off the device; without one it is brute-forceable — the full
2³² space takes a couple of hours on a desktop (≈0.6 M keys/s across 4 cores) using the
oracle below, which both filters cheaply and confirms cryptographically.

## Decrypting your own `conf.bin` (once you have `DEVVAL`)

```python
import struct
CONST8 = bytes.fromhex("748da50bf93e2dcf")
hexd   = ("%08x" % (DEVVAL & 0xffffffff)).encode()        # 8 lowercase hex chars
key    = bytes(CONST8[i] ^ hexd[i] for i in range(8))
# plano = DES-ECB-decrypt(conf.bin, key)       # standard DES, no IV, no padding
#   openssl enc -d -des-ecb -K <key.hex()> -nopad -provider legacy -provider default -in conf.bin
# plano = H[0:16] || C                         # 16-byte header, THEN the compressed blob
# C     = plano[16:] = [4-byte LE uncompressed length][LZSS stream]
# xml   = LZSS_decompress(C)                   # cen_uncompressBuff; decompress from offset +16
```

## Brute-forcing `DEVVAL` (two-stage oracle)

Per candidate key you only need to DES-decrypt **one block** for the cheap filter:

1. **Cheap filter** — decrypt the 8 bytes at ciphertext offset 16 (the start of `C`).
   - `plano[16:20]` (LE) must be a plausible uncompressed length (larger than the
     compressed payload; tens to a few hundred KB), **and**
   - `plano[20]` must be `0x3c` (`'<'`) — the LZSS stream's first literal is the first
     byte of the XML, which is always `<`.
   This passes only ~1 in 10⁵–10⁶ keys.
2. **Confirm** — for a filter hit, decrypt the whole file, LZSS-decompress from +16, and
   require the result to start with `<?xml` / contain `<DslCpeConfig`. This is the
   definitive check (do **not** rely on an MD5 of the 16-byte prefix — see the gotcha
   above).

## Symbols / offsets (firmware 1.26.0, for orientation — check your own build)

- `libcmm.so`: `rsl_sys_backupCfg` `@0x4afcc`, `rsl_sys_restoreCfg` `@0x4bc10`,
  `dm_backupCfg` `@0x1ce7d4`, `getBackNRestoreK` `@0x48454`, `CONST8` `@.rodata 0x251010`,
  `"%08x"` `@.rodata 0x251008`.
- `libcutil.so`: `cen_desMinDo` `@0x1cc1c` (key is arg 5, DES block loop),
  `cen_compressBuff` `@0x1e010`, `cen_uncompressBuff` `@0x1e38c`, OpenSSL `des_SPtrans`
  `@0x25730`.

## Why this is here

It is the same device family as the APN / perso-unlock work in this repo, and it is the
most promising **shell-independent** modification path for the encrypted/hardened builds:
edit the decrypted XML, recompress (LZSS) and re-encrypt (reverse the pipeline), then
Restore from the web UI. Contributions welcome — in particular, confirming the exact
semantics of the 16-byte header `H` (it is verified on Restore; its construction is the
last unknown) and whether `DEVVAL` can be computed from printed device identifiers
instead of read/brute-forced.

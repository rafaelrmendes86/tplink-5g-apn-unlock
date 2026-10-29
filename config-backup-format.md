# Config backup format (`conf.bin`) — reverse-engineering notes

> Status: **fully reversed, verified, and reversible** — a real unit's `conf.bin`
> decrypts to its `DslCpeConfig` XML, and an edited XML can be re-packed into a `conf.bin`
> the device accepts. The DES is standard, the digest is a plain MD5 with **no secret**, so
> the format is **forgeable**. The only per-unit input is `DEVVAL` (readable with a root
> shell, or brute-forceable). Config-level analysis of a device you own — no vendor code,
> keys or device values are redistributed here.

The NX511v / NX510v family (Qualcomm IPQ + Aginet/`libcmm` userspace) lets you
**Backup / Restore** the configuration from the web UI as an encrypted `conf.bin`.
This is interesting because a *config* Restore is accepted by the web UI **without a
root shell** — so with the format understood it is a **persistent, shell-independent**
modification path that should survive on the hardened, shell-less builds (1.3.0 / 1.30.0)
where the runtime patch methods no longer apply. The config format is independent of the
firmware signing/encryption.

## Pipeline

Backup does, in order (`rsl_sys_backupCfg` → `dm_backupCfg` in `libcmm.so`):

1. **Serialize** the running datamodel to **XML** — `<?xml version="1.0"?><DslCpeConfig>…</DslCpeConfig>` (this is the plaintext). Note it is *pseudo*-XML: attributes are unquoted integers (`val=180`) alongside quoted strings, so a strict XML parser will reject it.
2. **Compress** with a custom **LZSS** (`cen_compressBuff` in `libcutil.so`). Output `C`:
   `[4-byte little-endian uncompressed length][LZSS stream]`.
3. **Digest**: `H = MD5(C)` (16 bytes), prepended — giving `H || C`.
4. **Encrypt** the whole thing with **DES** in **ECB** mode (`cen_desMinDo` in `libcutil.so`). `libcutil`
   bundles the stock OpenSSL DES `SP-box` table, so this is **standard DES**, not a custom
   cipher — it decrypts with `openssl enc -d -des-ecb` (on OpenSSL 3.x add
   `-provider legacy -provider default`).

So on disk: `conf.bin = DES_ECB_encrypt( MD5(C) || C )`, zero-padded to a multiple of 8
(DES block size), with no plaintext header before the ciphertext. Restore reverses it
(`rsl_sys_restoreCfg`): DES-decrypt, verify the digest, then `cen_uncompressBuff` on `C`.

> ⚠️ **The gotcha that costs you days:** `C` — and therefore the 4-byte length field —
> begins at **offset 16**, not 0; the first 16 bytes are the digest. If you feed the LZSS
> decompressor from offset 0, it fails. And the digest is `MD5(C)` over `C`'s **real**
> length, which is **not** `len(plaintext) - 16`: the last 1–7 bytes of the decrypted blob
> are DES zero-padding, *outside* `C`. So `MD5(plaintext[16:])` does **not** match — you
> must trim the padding. The restore itself does this by appending 0 bytes while checking
> (see below), so a brute/validator should trim up to 7 trailing bytes when testing the MD5,
> or just validate by LZSS-decompressing and checking for `<?xml` / `<DslCpeConfig`.

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
of the serial or MAC; it is a factory/datamodel value. With a root shell you read it off
the device; without one it is brute-forceable — the full 2³² space takes a couple of hours
on a desktop (≈0.6 M keys/s across 4 cores) using the oracle below.

## The digest `H` (`cen_md5VerifyDigest`) — no secret

Both the backup digest and the restore check are **canonical MD5**, with no salt, key or
HMAC:

- `cen_md5MakeDigest` = `MD5_Init; MD5_Update(C, clen); MD5_Final` — standard IV
  (`0x67452301 / 0xefcdab89 / 0x98badcfe / 0x10325476`). `H = MD5(C)`, nothing else.
- `cen_md5VerifyDigest` recomputes it and `memcmp`s 16 bytes. Restore wraps this in a
  **tolerance loop** that appends 0–7 trailing `0x00` bytes and retries, which is exactly
  what absorbs the DES padding — so you do **not** have to reproduce the padding length.

Because there is no secret, **a valid `conf.bin` is forgeable** with only `DEVVAL`.

## Decrypting / forging (scripts in this repo)

- `lzss.py` — the LZSS decompressor (port of `cen_uncompressBuff`).
- `lzss_compress.py` — an LZSS compressor compatible with it (all-literals; ~1.125× size).
- `decrypt_config.py conf.bin (--key <hex> | --devval <int>)` — `conf.bin` → XML.
- `forge_conf.py xml_in conf_out (--key <hex> | --devval <int>)` — edited XML → `conf.bin`,
  and self-verifies the digest + round-trip.

Forge recipe (what `forge_conf.py` does):

```
C         = lzss_compress(xml)              # [4-byte LE length][LZSS stream]
H         = md5(C)                          # 16 bytes, standard MD5
plaintext = H + C                           # then zero-pad to a multiple of 8
conf.bin  = DES_ECB_encrypt(plaintext, key) # standard DES, no IV
```

> **Size caveat:** the all-literals compressor produces a ~1.125× blob (e.g. 114 KB XML →
> 128 KB), far larger than the vendor's real-match output (~19 KB). If a device rejects an
> oversized restore, implement `cen_compressBuff`'s match search to shrink it.

## Brute-forcing `DEVVAL` (two-stage oracle)

Per candidate key you only need to DES-decrypt **one block** for the cheap filter:

1. **Cheap filter** — decrypt the 8 bytes at ciphertext offset 16 (the start of `C`).
   - `plano[16:20]` (LE) must be a plausible uncompressed length (larger than the
     compressed payload; tens to a few hundred KB), **and**
   - `plano[20]` must be `0x3c` (`'<'`) — the LZSS stream's first literal is the first
     byte of the XML, which is always `<`.
   This passes only ~1 in 10⁵–10⁶ keys.
2. **Confirm** — for a filter hit, decrypt the whole file, LZSS-decompress from +16, and
   require the result to start with `<?xml` / contain `<DslCpeConfig`. (Confirming via the
   MD5 digest also works, but remember to trim the DES padding first — see the gotcha.)

## Symbols / offsets (firmware 1.26.0, for orientation — check your own build)

- `libcmm.so`: `rsl_sys_backupCfg` `@0x4afcc`, `rsl_sys_restoreCfg` `@0x4bc10`,
  `dm_backupCfg` `@0x1ce7d4`, `getBackNRestoreK` `@0x48454`, `CONST8` `@.rodata 0x251010`,
  `"%08x"` `@.rodata 0x251008`.
- `libcutil.so`: `cen_desMinDo` `@0x1cc1c` (key is arg 5, DES block loop),
  `cen_compressBuff` `@0x1e010`, `cen_uncompressBuff` `@0x1e38c`,
  `cen_md5MakeDigest` `@0x1b850`, `cen_md5VerifyDigest` `@0x1ba00`,
  `MD5_Init` `@0x19bd8`, OpenSSL `des_SPtrans` `@0x25730`.

## Why this is here

It is the same device family as the APN / perso-unlock work in this repo, and it is the
most promising **persistent, shell-independent** modification path for the encrypted/
hardened builds: decrypt your config, edit the XML, re-pack with `forge_conf.py`, and
Restore from the web UI. Useful datamodel fields live right in the XML — e.g.
`X_TP_AppCfg/SSHCfg/LocalEnabled` and `TelnetCfg/TelnetLocalEnabled` toggle the SSH/telnet
daemons, which on a shell-less build is a route back to a root shell. Contributions
welcome — in particular a size-efficient `cen_compressBuff`-compatible compressor, and
confirming whether `DEVVAL` can be computed from printed device identifiers.

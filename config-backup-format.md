# Config backup format (`conf.bin`) — reverse-engineering notes

> Status: **algorithm reversed and DES confirmed standard; the per-device key
> value is not yet pinned down.** This is a research note, not a finished tool.
> Config-level analysis of a device you own — no vendor code or keys are redistributed.

The NX511v / NX510v family (Qualcomm IPQ + Aginet/`libcmm` userspace) lets you
**Backup / Restore** the configuration from the web UI as an encrypted `conf.bin`.
This is interesting because a *config* Restore is accepted by the web UI **without a
root shell** — so if the format is understood, it is a modification path that could
survive on the hardened, shell-less builds (1.3.0 / 1.30.0) where the runtime method
no longer applies. The config format is independent of the firmware signing/encryption.

## Pipeline

Backup does, in order (`rsl_sys_backupCfg` → `dm_backupCfg` in `libcmm.so`):

1. **Serialize** the running datamodel to **XML** — `<?xml version="1.0"?><DslCpeConfig>…</DslCpeConfig>` (this is the plaintext).
2. **Compress** with a custom **LZSS** (`cen_compressBuff` in `libcutil.so`). Output layout:
   `[4-byte little-endian uncompressed length][LZSS stream]`.
3. **Encrypt** with **DES** in **ECB** mode (`cen_desMinDo` in `libcutil.so`). `libcutil`
   bundles the stock OpenSSL DES `SP-box` table, so this is **standard DES**, not a custom
   cipher — it decrypts with `openssl enc -d -des-ecb` (on OpenSSL 3.x add
   `-provider legacy -provider default`).

Restore reverses it (`cen_uncompressBuff` for step 2).

## Key derivation (`getBackNRestoreK`)

The 8-byte DES key is **not** fixed and **not** a login password. It is:

```
key[i] = CONST8[i]  XOR  ascii("%08x" % DEVVAL)[i]      for i = 0..7
```

- `CONST8` = `74 8d a5 0b f9 3e 2d cf` — a fixed 8-byte constant embedded in `libcmm.so`
  (same for every unit of the model).
- `DEVVAL` = a **per-device 32-bit value** read from the datamodel device-info object
  (`dm_getObj(2, …)`, field at offset `0x4e0`), formatted as 8 lowercase hex characters.
  The code logs `"Get dev info for BNR key"` on failure. This is what makes each unit's
  backup decryptable only with that unit's value (anti-cloning).

So a full decrypt needs `DEVVAL` for *your* unit. In testing it is **not** a plain CRC32
of the serial or MAC; it is a factory/datamodel value. On a build where you still have a
root shell you can read it off the device; without one it must be derived or brute-forced
(2³² against the known-plaintext oracle below).

## Decrypting your own `conf.bin` (once you have `DEVVAL`)

```python
import struct
CONST8 = bytes.fromhex("748da50bf93e2dcf")
hexd   = ("%08x" % (DEVVAL & 0xffffffff)).encode()
key    = bytes(CONST8[i] ^ hexd[i] for i in range(8))
# openssl enc -d -des-ecb -K <key.hex()> -nopad -provider legacy -provider default -in conf.bin
# plaintext = [4-byte LE uncompressed length][LZSS stream]  -> LZSS-decompress -> XML
```

**Known-plaintext oracle** (to confirm a candidate `DEVVAL`): after DES-decrypt, the
first 4 bytes (little-endian) must be the uncompressed XML size — a sane value larger
than the compressed payload (tens to a few hundred KB). A wrong key gives a random
32-bit number there, so this cleanly validates a guess.

## Symbols / offsets (firmware 1.26.0, for orientation — check your own build)

- `libcmm.so`: `rsl_sys_backupCfg` `@0x4afcc`, `dm_backupCfg` `@0x1ce7d4`,
  `getBackNRestoreK` `@0x48454`, `CONST8` `@.rodata 0x251010`.
- `libcutil.so`: `cen_desMinDo` `@0x1cc1c` (key is arg 5, DES block loop),
  `cen_compressBuff` `@0x1e010`, `cen_uncompressBuff` `@0x1e38c`, OpenSSL `des_SPtrans`
  `@0x25730`.

## Why this is here

It is the same device family as the APN / perso-unlock work in this repo, and it is the
most promising **shell-independent** modification path for the encrypted/hardened builds.
Contributions welcome — in particular, identifying exactly which datamodel field feeds
`DEVVAL` so it can be computed instead of read off the device.

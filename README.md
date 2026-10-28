# NX511v / NX510v — initial-attach APN unlock (use your own SIM)

ISP-branded builds of the TP-Link **NX511v** / **NX510v** 5G/LTE routers (e.g. the
SFR units in France) refuse to carry data with a **non-home SIM** (e.g. a MEO SIM in
an SFR box): you get registered on the network but with **no Internet** — only a
"signalling" bearer (an address like `10.x.x.x/29`, DNS `0.0.0.0`, no default route).
The web UI won't let you type an APN, and setting it over AT / TR-069 gets reverted.

This repo explains **why**, and gives a tool to fix it on **your own device**.

> ⚠️ Use only on hardware you own, with a SIM/data plan you own. This modifies the
> device at runtime; it voids your warranty. **No vendor firmware or binaries are
> distributed here** — you run the tool on the binary you extract from your own router.

## Root cause

The modem manager daemon (`/usr/sbin/mobile`) builds the **initial-attach profile**
(PDN context 1) with a **blank APN on purpose**. It has three code paths in the
attach-profile builder, and all three set the APN field to the **empty string `""`**.

With the operator's *home* SIM the network tolerates a blank attach and grants a real
bearer. With a *foreign* SIM the daemon treats it as roaming/non-home and the network
answers the blank attach with a signalling-only bearer → no Internet. The displayed
ISP profile may say `apn:internet`, but that profile is used for the *dial*, not for
the *attach* — the attach APN is the blank one, and that's what decides the bearer.

Proof: forcing `AT+CGDCONT=1,"IPV4V6","internet"` + `AT+CFUN=0/1` yields a real IP, but
the daemon reverts it. The fix makes the daemon itself put a real APN in the attach.

## The fix

`nx_attach_apn_patch.py` finds those three empty-APN assignments in **your** extracted
`mobile` binary (by code-pattern, not fixed offsets) and rewrites them to use a real
APN (default `internet`). It injects the APN string into free `.rodata` padding and
repoints the three loads; `user`/`password` are left empty (no auth), exactly as a
normal `internet` attach expects.

This is a **runtime** fix. The rootfs is read-only and the firmware flash is gated by
an RSA signature + OEM-ID, so you **cannot** reflash a modified image. Instead you run
the patched `mobile` from a writable tmpfs. It is therefore **not persistent** across
reboots by itself — see *Persistence* below.

## Requirements

- Root shell on the router (see *Getting a shell*).
- On your PC: `python3` and `capstone` (`pip install --user capstone`).
- A way to move a file to/from the router. These busybox builds are stripped (no
  `wget`/`curl`/`scp`), but `tftp` (client) is present — run a small TFTP server on
  your PC.

## Getting a shell

SSH to the router as `admin` (your admin password), then at the TP-Link CLI type:

```
sh
```

That drops to a busybox **root** shell (the CLI command `sh` → `doFshell`). `telnetd`
and a serial console are also available on these builds.

## Steps

1. **Extract** the daemon from the router to your PC (TFTP push from the router):

   ```sh
   # on your PC: serve a writable dir on udp/69xx (any minimal TFTP server)
   # on the router shell:
   tftp -p -l /usr/sbin/mobile -r mobile <YOUR_PC_IP> 6969
   ```

2. **Patch** it on your PC (dry-run first, then apply):

   ```sh
   python3 nx_attach_apn_patch.py mobile              # shows the 3 sites it will patch
   python3 nx_attach_apn_patch.py mobile --apply -o mobile.patched
   # different APN?  --apn myapn
   ```

   You should see exactly **3** sites. If you see more/none, **stop** and review — do
   not deploy a binary whose dry-run looks wrong.

3. **Deploy** at runtime (from the router shell; see `deploy.md`):

   ```sh
   # pull the patched file back from your PC:
   tftp -g -l /var/tmp/mobile.new -r mobile.patched <YOUR_PC_IP> 6969
   chmod 755 /var/tmp/mobile.new
   kill $(pidof mobiledog) 2>/dev/null     # watchdog that would respawn the stock daemon
   kill $(pidof mobile)    2>/dev/null
   sleep 2
   cd / && /var/tmp/mobile.new >/var/tmp/mob.log 2>&1 &
   ```

4. **Verify** (wait ~45 s for the re-attach):

   ```sh
   ifconfig rmnet_mhi0.1 | grep inet     # should now be a real IP, not 10.x
   ping -c3 8.8.8.8
   ```

## Persistence

The patch lives in tmpfs, so it's gone after a reboot. Options:

- **Portable / manual:** keep `mobile.patched` on the device's persistent config
  partition (`/var/run/misc/misc_rw`, a few MB free) plus a one-line apply script, and
  run it after each power-on. See `apply_runtime.sh`.
- **Automatic (at home):** a watchdog on an always-on box on the LAN that SSHes in and
  re-applies whenever it detects the stock daemon running. See `deploy.md`.

There is **no on-device boot hook** (rootfs & `/etc` are read-only, no cron, no
`rc.local`), so fully-unattended on-device persistence isn't possible without signed
firmware.

## Notes & limits

- Tested on **NX511v 1.10.0 Build 240419** (SFR) with a real data session (ping 0% loss).
  **Also confirmed on NX511v 1.26.0 Build 250807**: the pattern matcher auto-found the
  same three sites at *different* offsets and produced a clean 20-byte patch — which is
  the whole point of matching by code-pattern instead of hardcoding offsets (it survives
  firmware updates). The same functions (`GetInitialAttachApn` / `SetInitialAttachApn` /
  `SyncInitialAttachProfileToModem`) are also present in NX510v 1.2.0. Always run the
  dry-run on your own binary first.
- Your data IP may be **CGNAT** (100.64.0.0/10). That's your operator's doing, not this
  patch.
- **Bridge / passthrough mode** is compiled *out* of the NX511v builds
  (`# INCLUDE_LTE_BRIDGE_MODE is not set`) but *in* on the NX510v 1.2.0
  (`INCLUDE_LTE_BRIDGE_MODE=y`), same modem (Quectel RG520N). A runtime path to enable
  it on the 511v is under investigation; not included here yet.
- This needs admin access to **your own** device; it is not a remote exploit.

## License

MIT — see `LICENSE`.

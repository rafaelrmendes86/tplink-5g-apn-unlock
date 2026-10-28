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

## Newer firmware: a second lock (SFR network-personalization / `PH-NET PIN`)

On **NX511v 1.26.0** the OTA also **updates the modem firmware** (observed: Quectel
RG520N `...A04...` → `...A06...`), and that build arms a modem-level
**network-personalization lock**. The symptom is different from the APN one: the SIM
won't register **at all**.

```
AT+CPIN?      -> +CPIN: PH-NET PIN
AT+QSIMLOCK?  -> +QSIMLOCK: "PN",<n>     (locked; no registration, "No Service")
```

The daemon does know how to clear it — it sends `AT+QSIMLOCK="PN","<password>"` — but
only when it decides the inserted SIM is a *home* SIM. With a foreign SIM it leaves the
lock on. The lock **re-arms on every cold boot**.

You don't have to guess the code (and you shouldn't — `"PN"` unlock attempts are
limited). The password is a **constant in your own `mobile` binary**, sitting right next
to the `AT+QSIMLOCK=` format strings. `find_perso_pw.py` disassembles your binary, finds
the `AT+QSIMLOCK="PN","%s"` site and the string the code feeds as that `%s`, and prints
the exact command:

```sh
python3 find_perso_pw.py mobile
# -> perso unlock password : "123456"      (the observed SFR default; verify your own)
# -> /usr/sbin/mobile_cli send_at_cmd 'AT+QSIMLOCK="PN","123456"'
```

Run it on the device (the daemon relays the AT; raw writes to the modem node are
blocked), or use `unlock_perso.sh`:

```sh
sh unlock_perso.sh                 # uses the default, or pass your own: sh unlock_perso.sh <PW>
# AT+QSIMLOCK? now returns OK with no "PN" line, AT+CPIN? -> READY, and it registers.
```

Sending the **correct** key does not consume an unlock attempt. Once cleared, the modem
registers on your operator — and, notably, on **1.26.0 the perso unlock alone was enough
to get data**: the stock daemon's configured dial profile (APN `internet`) then connects
on its own, so the `.rodata` APN-attach patch above was **not needed** on that build.
The two locks are independent; apply whichever your box actually has.

Because the lock re-arms every cold boot and there is no on-device boot hook (see
*Persistence*), re-run the unlock after each power-on — a one-liner from the config
partition, or an external watchdog on your LAN that re-runs it when it sees `"PN"` again.

## Requirements

- Root shell on the router (see *Getting a shell*).
- On your PC: `python3` and `capstone` (`pip install --user capstone`).
- A way to move a file to/from the router. These busybox builds are stripped (no
  `wget`/`curl`/`scp`), but `tftp` (client) is present — run a small TFTP server on
  your PC.

## Getting in — valid `admin` credentials via TR-069 (the part that unlocks SSH)

On an ISP-locked unit you often **don't know the device's `admin` password**, and the web
UI won't let you set it — so SSH (Dropbear *is* listening) rejects every login and you're
stuck. The way through is **TR-069 / CWMP**: point the router at **your own ACS** and use
it to *write* the `admin` (super-admin) account password. Then that password is valid for
SSH.

This technique is **not mine** — it's the TP-Link/Aginet "jailbreak" by
**[OscarVanL](https://gist.github.com/OscarVanL)**, as refined in
**[ataniazov's gist](https://gist.github.com/ataniazov/b774f8b58deb6a02f07c7327ca67c651)**
(written for the EX230v / VX230v / EX530v). What's below is that method **adapted to the
NX511v**; credit for the approach goes to them.

1. **Run GenieACS on a box on the same LAN** (Docker: MongoDB + `genieacs-cwmp` on
   `:7547` + `genieacs-ui` on `:3000`; the UI default login is `admin:admin`).
2. **Point the router's ACS at your server.** On the NX511v this is exposed directly in
   **System Tools → CWMP Settings** (no `$.loadMain("/cwmp.htm")` console trick needed):
   enable CWMP + periodic Inform, set **ACS URL = `http://<your-LAN-ip>:7547`**, clear the
   ACS username/password, set the TR-069 interface to **LAN**, and disable connection-
   request auth. **Screenshot the original values first** so you can restore them.
3. The device shows up in GenieACS → **Devices** (online). Refresh
   `InternetGatewayDevice.User.1` / `User.2`; the user named **`admin` is the super-admin**.
   **Set its `Password`** (≥6 chars, ≥2 character classes) and commit the
   `setParameterValues`.
   > On this SFR build most `setParameterValues` are refused (`cwmp.9001 Request denied`),
   > but writing the **User password** goes through — that's the one you need.
4. You now have a known `admin` password. It works for **SSH** (below) **and** for the
   hidden **`/superadmin`** web page (band/cell lock, etc.).
5. **Clean up** when done: restore the saved CWMP settings or just disable CWMP + Inform,
   and tear down GenieACS — otherwise the ISP's ACS may reach the box again (or reset the
   password you set). Right to repair: your device, your SIM, your data plan.

## Getting a shell

With a valid `admin` password (above), the rest needs no exploit. Public research on this
family (e.g. the OpenWrt NX510v thread) reports **no working root shell** — UART is password-gated, U-Boot autoboot is blocked (`bootdelay=0`), EDL is
a dead end (SPI NAND), and on the hardened builds the patched Dropbear rejects shell
channels. But on the **NX511v up to 1.26.0** there is a simple, no-exploit path in with
nothing more than **your own admin login**:

1. **SSH in as `admin`** with the router's admin password (the one you set in the web UI):

   ```sh
   ssh admin@<router-ip>
   ```

   You don't land in a normal shell — you land in the **TP-Link CLI** (prompt
   `TP-Link(conf)#`). This is the same restricted CLI the ISP ships; most debug commands
   are gone.

2. **Escape the CLI to a root shell** — at the `TP-Link(conf)#` prompt, type:

   ```
   sh
   ```

   The CLI's `sh` command is wired to an internal `doFshell` handler that execs
   **busybox as root** (the `admin` account is UID 0 in `passwd.bak`). You drop straight to
   a prompt like `/var/tmp/dropbear #`, running as **root** — full filesystem, `mobile_cli`,
   `iptables`, `/proc/<pid>/mem`, everything. `telnetd` is also started unconditionally on
   these builds, and the UART serial console exists (both land in the same CLI).

That's the whole trick: **admin SSH → CLI → `sh` → root**. No signature bypass, no
soldering — it's your device and your admin password, and the CLI simply still has the
`doFshell` escape compiled in.

> **This escape is removed on the hardened builds.** The community reports that on
> **NX510v 1.3.0** (and, by generation, expect the same on **NX511v 1.30.0**) the CLI no
> longer escapes to `/bin/sh`, the debug/factory commands are stripped, and the patched
> Dropbear refuses shell/exec channels (port-forwarding only). So get your shell — and
> stage any persistence — while you're on a pre-hardening build, and **don't flash a newer
> one** if you want to keep this access (downgrade is version-check blocked and there is no
> documented recovery mode).

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

- **End-to-end validated on NX511v 1.10.0 Build 240419** (SFR): patched, deployed and
  confirmed with a real data session (ping 0% loss).
- **NX511v 1.26.0 Build 250807 — validated on-device.** The pattern matcher auto-finds
  the same three APN sites at *different* offsets than 1.10.0 (the point of matching by
  code-pattern, not fixed offsets). But the actual blocker on 1.26.0 turned out to be the
  **network-personalization lock** above, not the attach APN: once the modem was
  perso-unlocked (`find_perso_pw.py` + `AT+QSIMLOCK="PN",…`), it registered and the stock
  dial profile carried data (real IP, ping 0% loss, LTE + 5G NR n78) — the APN patch was
  not required on this build. So on 1.26.0 reach for `find_perso_pw.py`/`unlock_perso.sh`
  first; keep the APN patch for builds where the attach APN is the thing in your way.
- **Encrypted firmware on newer builds.** Images up to 1.26.0 are plaintext (UBI +
  squashfs, so you can unpack the `.bin` and pull `mobile` out of it). The **1.30.0**
  OTA image (Build 260320) is **fully encrypted** — uniform ~8.0 bits/byte entropy end to
  end, no UBI/squashfs/xz magic — so you can't unpack the `.bin` offline without the
  (bootloader-held) key. This does **not** block anything here: extract `mobile` from a
  **running** device instead (`tftp -p -l /usr/sbin/mobile -r mobile <PC> 69xx`) and run
  the tools on that. Only confirmed-usable on the firmware you can actually get a root
  shell on; a blind flash to an encrypted build risks losing that shell with no downgrade.
- The same functions (`GetInitialAttachApn` / `SetInitialAttachApn` /
  `SyncInitialAttachProfileToModem`) are also present in **NX510v 1.2.0**. Always run the
  dry-run on your own binary first.
- Your data IP may be **CGNAT** (100.64.0.0/10). That's your operator's doing, not this
  patch.
- **Bridge / passthrough mode** is compiled *out* of the NX511v builds
  (`# INCLUDE_LTE_BRIDGE_MODE is not set`) but *in* on the NX510v 1.2.0
  (`INCLUDE_LTE_BRIDGE_MODE=y`), same modem (Quectel RG520N). A runtime path to enable
  it on the 511v is under investigation; not included here yet.
- This needs admin access to **your own** device; it is not a remote exploit.
- **Config backup format** (`conf.bin`) is reverse-engineered in
  [`config-backup-format.md`](config-backup-format.md): XML → LZSS → **standard DES-ECB**,
  with `key = 748da50bf93e2dcf XOR ascii("%08x", devval)` and `devval` a per-device
  datamodel value. A config Restore is accepted without a root shell, so this is the most
  promising modification path on the hardened/shell-less builds — once `devval` is known.

## License

MIT — see `LICENSE`.

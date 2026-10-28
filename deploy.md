# Deploying & keeping the patch alive

The patched `mobile` runs from tmpfs, so it does not survive a reboot on its own.
Pick whichever fits you.

## A. One-off (testing)

From the router root shell, with a TFTP server running on your PC:

```sh
tftp -g -l /var/tmp/mobile.new -r mobile.patched <PC_IP> 6969
chmod 755 /var/tmp/mobile.new
kill $(pidof mobiledog) 2>/dev/null
kill $(pidof mobile)    2>/dev/null
sleep 2
cd / && /var/tmp/mobile.new >/var/tmp/mob.log 2>&1 &
```

## B. Portable (one command per power-on)

Stage the binary + `apply_runtime.sh` on the device's persistent config partition
once (see the header of `apply_runtime.sh`). Then after every power-on:

```sh
sh /var/run/misc/misc_rw/apply_runtime.sh
```

Works from a phone SSH app; no PC/TFTP needed after the one-time staging.

## C. Automatic on a home LAN (external watchdog)

Run a tiny watchdog on an always-on box on the same LAN. Every couple of minutes it
SSHes into the router and, if it sees the **stock** daemon running (i.e. `mobile.new`
is NOT running), it re-applies the patch. Sketch (pseudo-/shell):

```sh
# every 2 min, via cron:
if ! router_ssh 'pidof mobile.new' >/dev/null; then
    # push mobile.patched by tftp, then run the kill+launch sequence from A/B
    router_apply_patch
fi
```

Notes:
- The stock `mobile`/`mobiledog` are started by init (PID 1) with **no respawn**, so
  once you kill them they stay dead until the next boot — no fight with a supervisor.
- There is **no on-device boot hook** (read-only rootfs & `/etc`, no cron, no
  `rc.local`), which is why persistence is driven manually (B) or externally (C).

## Why not just reflash a patched firmware?

The flash is validated by an **RSA-1024 signature + OEM-ID** and refuses
downgrades, so only operator-signed images are accepted. A modified rootfs fails the
signature. This project therefore patches the **running** binary instead of the image.

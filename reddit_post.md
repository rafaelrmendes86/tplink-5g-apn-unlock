# Reddit draft (edit the <...> bits, add the GitHub link)

**Suggested subs:** r/homelab, r/tplink, r/4G5GInternet, r/france (for SFR users)

---

**Title:** Made an ISP-locked TP-Link NX511v (SFR) work with a different carrier's SIM — the "lock" was just a blank attach APN in the daemon

**Body:**

TL;DR: these operator-branded NX511v / NX510v 5G routers won't pass data with a
non-home SIM — you register on the network but get no Internet (signalling-only
bearer, `10.x/29`, DNS `0.0.0.0`, no default route). The web UI won't let you set an
APN and AT/TR-069 changes get reverted. Turns out it's not a SIM-signature or a modem
lock: the `mobile` daemon deliberately builds the **initial-attach APN as an empty
string**. With a home SIM the network tolerates a blank attach; with a foreign SIM it
grants only signalling. Patch the daemon so the attach APN is `internet` and you get a
real bearer. Confirmed with real traffic (ping 0% loss).

What I found / did:
- Root cause is in `/usr/sbin/mobile` — the attach-profile builder sets the APN field
  to `""` in three code paths (the displayed `apn:internet` profile is only used for
  the dial, not the attach).
- The rootfs is read-only and the flash is signature + OEM-ID gated, so you can't
  reflash a modified image. But you **can** run a patched copy of the daemon at runtime
  (root shell is available: SSH as admin → `sh` drops to busybox root).
- I wrote a small capstone-based patcher that finds those three empty-APN sites in your
  **own** extracted binary (by pattern, not fixed offsets) and rewrites them to
  `internet`, leaving user/password empty. Dry-run shows exactly what it will change.

Notes:
- Runtime-only (not persistent): the rootfs is RO and there's no boot hook, so you
  re-apply after a reboot (a one-line script from the config partition, or an external
  watchdog on your LAN).
- Your IP may be CGNAT — that's the carrier, not the patch.
- Bridge/passthrough is compiled out of the 511v builds but **in** on the NX510v 1.2.0
  (same Quectel RG520N modem) — a runtime path to enable it on the 511v is WIP.
- This needs admin access to **your own** device; it's not a remote exploit. Right to
  repair: your router, your SIM, your data plan. It voids the warranty. No vendor
  binaries are shared — the tool runs on the binary you pull from your own unit.

Repo (method + patcher, no firmware/binaries): https://github.com/rafaelrmendes86/tplink-5g-apn-unlock

Happy to answer questions — and if you have other ISP-locked variants, a dry-run of the
patcher on your `mobile` binary will show whether the same three sites are there.

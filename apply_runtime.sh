#!/bin/sh
# Runs ON the router (busybox). Launches the patched mobile daemon from the
# persistent config partition, so you only need one command after each power-on.
#
# One-time setup (from the router shell, with a TFTP server on your PC):
#   tftp -g -l /var/run/misc/misc_rw/mobile.patched -r mobile.patched <PC_IP> 6969
#   tftp -g -l /var/run/misc/misc_rw/apply_runtime.sh -r apply_runtime.sh <PC_IP> 6969
#   chmod 755 /var/run/misc/misc_rw/apply_runtime.sh
#   sync
#
# After each power-on:  ssh admin@<router> -> sh -> sh /var/run/misc/misc_rw/apply_runtime.sh

SRC=/var/run/misc/misc_rw/mobile.patched
DST=/var/tmp/mobile.new

if pidof mobile.new >/dev/null 2>&1; then
  echo "already running (pid $(pidof mobile.new))"; exit 0
fi
[ -f "$SRC" ] || { echo "ERROR: $SRC not found"; exit 1; }
# sanity: must be an ELF
head -c 4 "$SRC" | grep -q ELF || { echo "ERROR: $SRC is not an ELF binary"; exit 1; }

cp "$SRC" "$DST" && chmod 755 "$DST"
kill $(pidof mobiledog) 2>/dev/null
kill $(pidof mobile)    2>/dev/null
sleep 2
cd / && "$DST" >/var/tmp/mob.log 2>&1 &
sleep 3
NP=$(pidof mobile.new)
[ -n "$NP" ] && echo "launched pid=$NP -- Internet in ~45s" || { echo "FAILED to start"; exit 1; }

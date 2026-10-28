#!/bin/sh
# Clear the SFR network-personalization ("PN") lock on the RG520N modem at runtime.
#
# Newer modem firmware (e.g. RG520N A06, shipped in the NX511v 1.26.0 OTA) arms a
# network-personalization lock. A foreign SIM then cannot register at all:
#   AT+CPIN?      -> +CPIN: PH-NET PIN
#   AT+QSIMLOCK?  -> +QSIMLOCK: "PN",<n>     (locked)
# The daemon clears it with  AT+QSIMLOCK="PN","<password>"  -- but only for a home SIM.
# Find <password> in YOUR OWN /usr/sbin/mobile with find_perso_pw.py, then:
#
#   sh unlock_perso.sh [PASSWORD]      (default below is the observed SFR default)
#
# This is a runtime action: the perso lock re-arms on every cold boot, so re-run it
# after each power-on (e.g. from the persistent config partition, or an external
# watchdog on your LAN -- see README "Persistence"). Your device, your SIM.
PW="${1:-123456}"
CLI=/usr/sbin/mobile_cli
# wait for the modem daemon (AT goes through it)
i=0; while [ $i -lt 30 ]; do pidof mobile >/dev/null 2>&1 && break; sleep 1; i=$((i+1)); done
ST=$($CLI send_at_cmd 'AT+QSIMLOCK?' 2>/dev/null)
echo "lock before: [$ST]"
case "$ST" in
  *'"PN"'*)
    $CLI send_at_cmd "AT+QSIMLOCK=\"PN\",\"$PW\""
    sleep 3
    echo "lock after:  [$($CLI send_at_cmd 'AT+QSIMLOCK?' 2>/dev/null)]"
    echo "cpin:        [$($CLI send_at_cmd 'AT+CPIN?'     2>/dev/null)]"
    ;;
  *) echo "already unlocked" ;;
esac

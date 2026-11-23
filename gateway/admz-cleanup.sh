#!/bin/bash
# Removes the A-DMZ lab rate-limit rules (names starting ADMZ-) and switches
# the Penalty Box off. Rules with any other name are left alone.
# Run in Expert mode on the gateway (A-GW), or on EACH cluster member
# (A-GW-01 and A-GW-02). Works on R81.20 and R82. --dry-run prints only.
#
# Leave the Penalty Box on if something other than this lab relies on it:
#   KEEP_PBOX=1 bash admz-cleanup.sh

PREFIX='ADMZ-'
DRY=0; [ "$1" = "--dry-run" ] && DRY=1
R81=0; fw ver 2>/dev/null | grep -q ' R81' && R81=1

run() {
    echo "+ $*"
    [ $DRY -eq 1 ] && return 0
    "$@" || echo "  !! failed (exit $?)"
}

fwaccel dos rate get | awk -v p="$PREFIX" '
  /^fwaccel dos rate add / && index($0, "-name \"" p) { if (match($0, /-i "<[^>]*>"/)) print substr($0, RSTART + 4, RLENGTH - 5); next }
  /uid=/ && index($0, "name=" p) { if (match($0, /uid=(<[^>]*>|[^ ]+)/)) print substr($0, RSTART + 4, RLENGTH - 4); next }
  /^[ \t]*Rule UID[ \t]/ { uid = $NF; next }
  /^[ \t]*(Rule )?Name[ \t]/ && index($NF, p) == 1 && uid != "" { print uid; uid = "" }' |
while read -r uid; do run fwaccel dos rate del "$uid"; done

if [ "${KEEP_PBOX:-0}" != "1" ]; then
    if [ $R81 -eq 1 ]; then run fwaccel dos config set --disable-pbox
    else run fwaccel dos pbox --set-enabled off; fi
fi

fwaccel dos rate get
if [ $R81 -eq 1 ]; then fwaccel dos config get; else fwaccel dos pbox --show-config; fi

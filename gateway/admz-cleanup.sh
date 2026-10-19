#!/bin/bash
# Removes the A-DMZ lab rate-limit rules (names starting ADMZ-) and switches
# the Penalty Box off. Rules with any other name are left alone.
# Run in Expert mode on EACH cluster member. --dry-run prints only.
#
# Leave the Penalty Box on if something other than this lab relies on it:
#   KEEP_PBOX=1 bash admz-cleanup.sh

PREFIX='ADMZ-'
DRY=0; [ "$1" = "--dry-run" ] && DRY=1

run() {
    echo "+ $*"
    [ $DRY -eq 1 ] && return 0
    "$@" || echo "  !! failed (exit $?)"
}

fwaccel dos rate get | grep "name=$PREFIX" | sed -n 's/.*uid=\(<[^>]*>\|[^ ]*\).*/\1/p' |
while read -r uid; do run fwaccel dos rate del "$uid"; done

[ "${KEEP_PBOX:-0}" = "1" ] || run fwaccel dos pbox --set-enabled off

fwaccel dos rate get
fwaccel dos pbox --show-config

#!/bin/bash
# Read-only snapshot of the SecureXL DoS state on this gateway (A-GW) or
# cluster member. Works on R81.20 and R82. Keep the output as a baseline.

if fw ver 2>/dev/null | grep -q ' R81'; then
    cmds=("fwaccel stats -s" "fwaccel dos config get" "fwaccel dos rate get" "fwaccel dos rate counters"
          "fwaccel tab -t dos_pbox -f" "fwaccel dos deny -s" "fwaccel dos stats get")
else
    cmds=("cphaprob state" "fwaccel stats -s" "fwaccel dos config get" "fwaccel dos rate get" "fwaccel dos rate counters"
          "fwaccel dos pbox --show-config" "fwaccel dos pbox --show" "fwaccel dos deny --show" "fwaccel dos stats get")
fi

for cmd in "${cmds[@]}"; do
    echo "=================== $cmd"
    $cmd 2>&1
done

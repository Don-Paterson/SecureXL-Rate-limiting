#!/bin/bash
# Read-only snapshot of the SecureXL DoS state on this cluster member.
# Run in Expert mode on each member and keep the output as a baseline.

for cmd in "cphaprob state" "fwaccel stats -s" "fwaccel dos config get" \
           "fwaccel dos rate get" "fwaccel dos rate counters" \
           "fwaccel dos pbox --show-config" "fwaccel dos pbox --show" \
           "fwaccel dos deny --show" "fwaccel dos stats get"; do
    echo "=================== $cmd"
    $cmd 2>&1
done

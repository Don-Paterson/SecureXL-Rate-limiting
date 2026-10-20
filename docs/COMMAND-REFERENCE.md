# SecureXL Rate Limiting - Command Reference

_A-DMZ protection on A-GW-Cluster (CCSA R82 Alpha lab)_

This reference explains every command the DoS Shield portal and the gateway scripts send to the cluster members. It covers the Basic (high tolerance) profile line by line, the Penalty Box settings, and the commands used for monitoring, changes and cleanup.

All commands run in Expert mode and affect only the member they run on. Run them on both A-GW-01 and A-GW-02. The portal does this for you.

## How a rate-limit rule is built

| Piece | Meaning |
|---|---|
| `fwaccel dos rate add` | Adds a rule to the SecureXL rate-limiting policy on this member only. Run it on both members. |
| `-a d / -a n` | Action: d = drop traffic over the limit; n = notify only (log it, still pass it). |
| `-n ADMZ-BAS-...` | Rule name. The ADMZ- prefix lets the portal and scripts find and remove only lab rules. |
| `destination cidr:192.168.12.101/32` | Matches traffic to A-DMZ only. There is no source, so it matches any source. |
| `service 6/80` | Protocol/port: 6 = TCP, then the port. Leaving it out means any service. |
| `pkt-rate / new-conn-rate / concurrent-conns` | What is measured: packets per second, new connections per second, or connections open at once. |
| `track source` | Counts each source IP separately, so every client gets its own allowance. Without it, all sources share one counter. |

## The Basic profile, line by line

```bash
fwaccel dos rate add -a d -n ADMZ-BAS-pkt-src destination cidr:192.168.12.101/32 pkt-rate 20000 track source
```
Any single source sending more than 20,000 packets/s to A-DMZ has the excess dropped. Catches packet floods such as UDP floods.

```bash
fwaccel dos rate add -a d -n ADMZ-BAS-http-conn destination cidr:192.168.12.101/32 service 6/80 new-conn-rate 150 track source
```
More than 150 new HTTP connections per second from one source is dropped. Catches HTTP connection floods.

```bash
fwaccel dos rate add -a d -n ADMZ-BAS-https-conn destination cidr:192.168.12.101/32 service 6/443 new-conn-rate 150 track source
```
The same limit for HTTPS on port 443. Catches HTTPS connection floods.

```bash
fwaccel dos rate add -a d -n ADMZ-BAS-ssh-conn destination cidr:192.168.12.101/32 service 6/22 new-conn-rate 10 track source
```
More than 10 new SSH connections per second from one source is dropped. Slows down SSH password guessing.

```bash
fwaccel dos rate add -a d -n ADMZ-BAS-concurrent destination cidr:192.168.12.101/32 concurrent-conns 1000 track source
```
One source can hold at most 1,000 connections open to A-DMZ at once. Stops a client tying up the server's connection slots with slow, long-held connections.

```bash
fwaccel dos rate add -a n -n ADMZ-BAS-aggregate destination cidr:192.168.12.101/32 pkt-rate 60000
```
Notify only, with no track, so all sources are counted together. Alerts when total traffic to A-DMZ passes 60,000 packets/s. Doesn't drop, because a cap on total traffic would also hit legitimate users during a spread-out attack. Keep it notify-only until normal peak traffic has been measured.


## Penalty Box (Basic settings)

```bash
fwaccel dos pbox --set-drops-threshold 1000
```
A source is put in the Penalty Box once its traffic is being dropped at more than 1,000 packets/s. Basic value. Strict uses 300.

```bash
fwaccel dos pbox --set-timeout 60
```
A source stays in the box for 60 seconds, then is released automatically. Basic value. Strict uses 300 seconds.

```bash
fwaccel dos pbox --set-log-drops on
```
Logs the packets the Penalty Box drops, so they appear in Logs & Monitor.

```bash
fwaccel dos pbox --set-enabled on
```
Turns enforcement on. While a source is boxed, SecureXL drops all its traffic early, to any destination, not just A-DMZ. Runs last so the threshold and timeout are already set when it starts. Applies to the whole gateway, not one rule.


## Monitoring and verification

| Command | What it does |
|---|---|
| `fwaccel dos rate get` | Lists the installed rate-limit rules, with each rule's UID. |
| `fwaccel dos rate counters` | Overall counters, then per-rule matches and limits. The main way to see a rule working. |
| `fwaccel dos pbox --show-config` | Penalty Box settings: enabled, threshold, timeout, logging. |
| `fwaccel dos pbox --show` | Source IPs in the Penalty Box right now. |
| `fwaccel dos deny --show` | Addresses on the explicit deny list. |
| `fwaccel dos config get` | Global DoS settings, including whether internal interfaces are covered. Check this if A-Host (behind internal eth2) never triggers anything. |
| `fwaccel dos stats get` | Drop statistics for the whole DoS feature. |
| `fwaccel stats -s` | How much traffic SecureXL is accelerating. Rate limiting works in SecureXL. |
| `cphaprob state` | Which cluster member is Active. Watch the counters on the Active member. |

## Changing and cleaning up

| Command | What it does |
|---|---|
| `fwaccel dos rate del <UID>` | Deletes one rule by the UID shown in fwaccel dos rate get. UIDs differ between members, so the portal looks them up on each one. |
| `fwaccel dos pbox --set-enabled off` | Turns the Penalty Box off and releases boxed sources. |
| `fwaccel dos deny --add <IP>` | Blocks an address completely, in both directions. Broader than rate limiting, and lost on reboot. |
| `fwaccel dos deny --delete <IP>` | Removes an address from the deny list. |
| `fwaccel dos deny --load-default` | Loads permanent deny entries from the files in $FWDIR/conf/deny_lists/. |
| `clusterXL_admin down` | Forces this member out of the cluster so the peer takes over. Use for failover testing only. |
| `clusterXL_admin up` | Returns the member to the cluster after a failover test. |

## The three profiles compared

| Setting | Monitor | Basic | Strict |
|---|---|---|---|
| Packets/s per source | 2,000 (notify) | 20,000 drop | 2,000 drop |
| New HTTP conn/s per source (6/80) | 25 (notify) | 150 drop | 25 drop |
| New HTTPS conn/s per source (6/443) | 25 (notify) | 150 drop | 25 drop |
| New SSH conn/s per source (6/22) | 3 (notify) | 10 drop | 3 drop |
| Concurrent conns per source | - | 1,000 drop | 100 drop |
| Aggregate packets/s to A-DMZ (all sources) | 20,000 (notify) | 60,000 (notify) | 10,000 drop |
| Penalty Box | off | on | on |
| Penalty Box drops threshold | - | 1,000 drops/s | 300 drops/s |
| Penalty Box timeout | - | 60 s | 300 s |
| Penalty Box drop logging | on | on | on |

## Syntax still to confirm

Two parts couldn't be confirmed from Check Point's R82 documentation: the exact form of 'rate del <UID>' and the 'track source' option. If the gateway rejects either, the error shows in the portal's Activity tab, and the command can be changed under Settings > Command syntax.

The same reference is available as [Word](COMMAND-REFERENCE.docx) and [Excel](COMMAND-REFERENCE.xlsx) files in this folder.

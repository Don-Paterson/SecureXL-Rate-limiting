"""
Talks to the ClusterXL members over SSH and turns profile rules into
`fwaccel dos` commands.

Every command the portal can send is built here from a template in the
settings, with each substituted value validated and shell-quoted first, so
the web UI never passes free text to a gateway shell.

Simulator mode replaces SSH with a small in-memory model of the rate-limit
policy, Penalty Box and deny list. It exists so the portal can be explored
(and tested) without a lab.
"""

import ipaddress
import itertools
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import paramiko
except ImportError:          # simulator mode still works without it
    paramiko = None


# ---------------------------------------------------------------------------
# Default command templates. Editable in Settings because CLI syntax varies
# between R82 builds and Jumbo Hotfixes; the gateway's own help is the final
# word. {placeholders} are filled with validated, shell-quoted values.
# ---------------------------------------------------------------------------

DEFAULT_COMMANDS = {
    "rate_add":           "fwaccel dos rate add -a {action} -n {name} {match} {limit} {value}{track}",
    "rate_del":           "fwaccel dos rate del {uid}",
    "rate_get":           "fwaccel dos rate get",
    "rate_counters":      "fwaccel dos rate counters",
    "pbox_show_config":   "fwaccel dos pbox --show-config",
    "pbox_show":          "fwaccel dos pbox --show",
    "pbox_set_enabled":   "fwaccel dos pbox --set-enabled {onoff}",
    "pbox_set_threshold": "fwaccel dos pbox --set-drops-threshold {value}",
    "pbox_set_timeout":   "fwaccel dos pbox --set-timeout {value}",
    "pbox_set_log_drops": "fwaccel dos pbox --set-log-drops {onoff}",
    "deny_show":          "fwaccel dos deny --show",
    "deny_add":           "fwaccel dos deny --add {ip}",
    "deny_del":           "fwaccel dos deny --delete {ip}",
    "dos_config":         "fwaccel dos config get",
    "dos_stats":          "fwaccel dos stats get",
    "cluster_state":      "cphaprob state",
    "accel_stats":        "fwaccel stats -s",
}

# Read-only commands the Diagnostics panel may run. Nothing else is accepted.
DIAGNOSTICS = ["cluster_state", "accel_stats", "dos_config", "dos_stats",
               "rate_get", "rate_counters", "pbox_show_config", "pbox_show", "deny_show"]

LIMITS  = ("pkt-rate", "new-conn-rate", "concurrent-conns", "bytes")
TRACKS  = ("source", "source-service", "none")
ACTIONS = {"drop": "d", "notify": "n"}

NAME_RE    = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
SERVICE_RE = re.compile(r"^(any|\d{1,3}(/\d{1,5}(-\d{1,5})?)?)$")
UID_RE     = re.compile(r"^[A-Za-z0-9<>,{}\-_:.]{1,120}$")
USER_RE    = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")

# Gaia clish rejects anything it doesn't know with "CLINFR0329 Invalid command".
CLISH_RE   = re.compile(r"CLINFR\d+")


def is_clish(result):
    return bool(CLISH_RE.search((result.get("out") or "") + (result.get("err") or "")))


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def check_cidr(value, field):
    value = str(value).strip()
    if value == "any":
        return value
    try:
        net = ipaddress.ip_network(value if "/" in value else value + "/32", strict=False)
    except ValueError:
        raise ValidationError(f"{field}: '{value}' is not an IP address or CIDR")
    if net.version != 4:
        raise ValidationError(f"{field}: only IPv4 is handled here (use fwaccel6 for IPv6)")
    return str(net)


def check_ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        raise ValidationError(f"'{value}' is not an IPv4 address")


def check_int(value, field, lo=1, hi=10**9):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a whole number")
    if not lo <= n <= hi:
        raise ValidationError(f"{field} must be between {lo} and {hi}")
    return n


def check_rule(rule):
    """Returns a normalised copy of a rule dict, or raises ValidationError."""
    name = str(rule.get("name", "")).strip()
    if not NAME_RE.match(name):
        raise ValidationError("Rule name: 1-40 characters, letters, digits, '.', '_' or '-'")
    action = rule.get("action", "notify")
    if action not in ACTIONS:
        raise ValidationError("Action must be drop or notify")
    limit = rule.get("limit")
    if limit not in LIMITS:
        raise ValidationError(f"Limit must be one of {', '.join(LIMITS)}")
    track = rule.get("track", "none") or "none"
    if track not in TRACKS:
        raise ValidationError(f"Track must be one of {', '.join(TRACKS)}")
    service = str(rule.get("service", "any")).strip() or "any"
    if not SERVICE_RE.match(service):
        raise ValidationError("Service: 'any', a protocol number, or proto/port such as 6/80")
    return {
        "name": name,
        "action": action,
        "source": check_cidr(rule.get("source", "any") or "any", "Source"),
        "destination": check_cidr(rule.get("destination", "any") or "any", "Destination"),
        "service": service,
        "limit": limit,
        "value": check_int(rule.get("value"), "Limit value"),
        "track": track,
        "note": str(rule.get("note", ""))[:120],
    }


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------

class CommandBuilder:
    def __init__(self, templates):
        self.t = dict(DEFAULT_COMMANDS)
        self.t.update({k: v for k, v in (templates or {}).items() if k in DEFAULT_COMMANDS and v})

    def get(self, key, **values):
        quoted = {k: shlex.quote(str(v)) if k not in ("match", "track") else v
                  for k, v in values.items()}
        return self.t[key].format(**quoted)

    def rate_add(self, rule, dmz_ip):
        r = check_rule(dict(rule, destination=rule.get("destination") or dmz_ip))
        match = []
        if r["source"] != "any":
            match.append(f"source cidr:{r['source']}")
        if r["destination"] != "any":
            match.append(f"destination cidr:{r['destination']}")
        if r["service"] != "any":
            match.append(f"service {r['service']}")
        track = "" if r["track"] == "none" else f" track {r['track']}"
        return self.get("rate_add", action=ACTIONS[r["action"]], name=r["name"],
                        match=" ".join(match), limit=r["limit"], value=r["value"], track=track)

    def rate_del(self, uid):
        uid = str(uid).strip()
        if not UID_RE.match(uid):
            raise ValidationError("That does not look like a rule UID")
        return self.get("rate_del", uid=uid)

    def pbox(self, cfg):
        cmds = []
        if "threshold" in cfg:
            cmds.append(self.get("pbox_set_threshold", value=check_int(cfg["threshold"], "Drops threshold")))
        if "timeout" in cfg:
            cmds.append(self.get("pbox_set_timeout", value=check_int(cfg["timeout"], "Timeout", 1, 86400)))
        if "log_drops" in cfg:
            cmds.append(self.get("pbox_set_log_drops", onoff="on" if cfg["log_drops"] else "off"))
        if "enabled" in cfg:
            # Last, so the thresholds are in place before enforcement starts.
            cmds.append(self.get("pbox_set_enabled", onoff="on" if cfg["enabled"] else "off"))
        return cmds

    def profile(self, profile, dmz_ip):
        cmds = [self.rate_add(r, dmz_ip) for r in profile["rules"]]
        cmds += self.pbox(profile.get("pbox", {}))
        return cmds


# ---------------------------------------------------------------------------
# Output parsing. Formats differ between builds, so this is deliberately
# forgiving: anything recognisable becomes a row, and the raw text is always
# shown alongside.
# ---------------------------------------------------------------------------

KV_RE = re.compile(r"""([A-Za-z][\w\-]*)\s*[=:]\s*("[^"]*"|'[^']*'|<[^>]*>|\{[^}]*\}|[^\s,;]+)""")


def parse_rules(text):
    rules = []
    for line in (text or "").splitlines():
        if "uid" not in line.lower() and "name" not in line.lower():
            continue
        fields = {k.lower(): v.strip("\"'") for k, v in KV_RE.findall(line)}
        if "uid" in fields or "name" in fields:
            rules.append(fields)
    return rules


def lab_rule_uids(text, prefix):
    """UIDs of rules whose name starts with the lab prefix, and only those."""
    return [r["uid"] for r in parse_rules(text)
            if r.get("uid") and r.get("name", "").startswith(prefix)]


IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_ips(text):
    seen = []
    for ip in IP_RE.findall(text or ""):
        if ip not in seen:
            seen.append(ip)
    return seen


def parse_flag(text, *words):
    """Finds 'enabled'/'disabled' style state on a line mentioning one of words."""
    for line in (text or "").splitlines():
        low = line.lower()
        if any(w in low for w in words):
            if re.search(r"\b(on|enabled|yes|true)\b", low):
                return True
            if re.search(r"\b(off|disabled|no|false)\b", low):
                return False
    return None


def parse_number(text, *words):
    for line in (text or "").splitlines():
        low = line.lower()
        if any(w in low for w in words):
            m = re.search(r"(\d+)", line.split(":", 1)[-1] if ":" in line else line)
            if m:
                return int(m.group(1))
    return None


def parse_cluster_state(text):
    for line in (text or "").splitlines():
        if "(local)" in line:
            for state in ("ACTIVE", "STANDBY", "DOWN", "READY", "INIT", "BACKUP"):
                if state in line.upper():
                    return state.title()
    return None


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

class SshTransport:
    """One cached SSH connection per member. Gaia's admin shell must be bash."""

    def __init__(self, host, port, user, password, timeout=8):
        self.host, self.port, self.user, self.password = host, port, user, password
        self.timeout = timeout
        self.client = None
        self.lock = threading.Lock()

    def _connect(self):
        if paramiko is None:
            raise RuntimeError("paramiko is not installed (pip install paramiko)")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())   # lab gateways
        client.connect(self.host, port=self.port, username=self.user, password=self.password,
                       timeout=self.timeout, banner_timeout=self.timeout,
                       auth_timeout=self.timeout, look_for_keys=False, allow_agent=False)
        self.client = client

    def run(self, command, timeout=30, raw=False):
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.client is None or not self.client.get_transport() \
                            or not self.client.get_transport().is_active():
                        self._connect()
                    # A login shell picks up $FWDIR and the Check Point PATH.
                    # raw=True sends the line as-is, for clish commands.
                    wrapped = command if raw else "bash -lc " + shlex.quote(command)
                    _, out, err = self.client.exec_command(wrapped, timeout=timeout)
                    rc = out.channel.recv_exit_status()
                    return rc, out.read().decode(errors="replace"), err.read().decode(errors="replace")
                except Exception:
                    self.close()
                    if attempt == 2:
                        raise

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None


class SimTransport:
    """In-memory stand-in for a gateway, driven by the default command syntax."""

    _uids = itertools.count(0x3ce)

    def __init__(self, name, state):
        self.name = name
        self.state_label = state
        self.rules = []
        self.pbox = {"enabled": False, "threshold": 500, "timeout": 180, "log_drops": False}
        self.boxed = {}
        self.deny = []
        self.started = time.time()

    def run(self, command, timeout=30, raw=False):
        if raw:
            return 0, "", ""
        argv = shlex.split(command)
        text = " ".join(argv)
        if text.startswith("cphaprob state"):
            return 0, self._cluster(), ""
        if text.startswith("fwaccel stats -s"):
            return 0, ("Accelerated conns/Total conns : 412/437 (94%)\n"
                       "Accelerated pkts/Total pkts   : 18833921/19288412 (97%)\n"
                       "F2Fed pkts/Total pkts         : 454491/19288412 (2%)\n"), ""
        if text.startswith("fwaccel dos rate add"):
            return self._add(argv[4:])
        if text.startswith("fwaccel dos rate del"):
            uid = argv[4] if len(argv) > 4 else ""
            before = len(self.rules)
            self.rules = [r for r in self.rules if r["uid"] != uid]
            return (0, f"Rule {uid} deleted\n", "") if len(self.rules) < before \
                else (1, "", f"No rule with UID {uid}\n")
        if text.startswith("fwaccel dos rate get"):
            return 0, self._rules_text(), ""
        if text.startswith("fwaccel dos rate counters"):
            return 0, self._counters(), ""
        if text.startswith("fwaccel dos pbox"):
            return self._pbox(argv[3:])
        if text.startswith("fwaccel dos deny"):
            return self._deny(argv[3:])
        if text.startswith("fwaccel dos config get"):
            return 0, ("rate limit: enabled (without policy)\nrule cache: enabled\n"
                       "pbox: " + ("enabled" if self.pbox["enabled"] else "disabled") + "\n"
                       "deny list: enabled\ninternal: enabled\nmonitor only: disabled\n"
                       "log drops: enabled\nnotif rate: 100 notifications/second\n"), ""
        if text.startswith("fwaccel dos stats get"):
            return 0, "Rate limit drops: %d\nPenalty box drops: %d\n" % (
                int(time.time() - self.started) * 7, len(self.boxed) * 3200), ""
        return 127, "", f"simulator: unsupported command: {command}\n"

    def close(self):
        pass

    def _cluster(self):
        me, peer = ("ACTIVE", "STANDBY") if self.state_label == "Active" else ("STANDBY", "ACTIVE")
        local, remote = ("1", "2") if self.name.endswith("01") else ("2", "1")
        rows = {local: (me, "(local)"), remote: (peer, "")}
        lines = ["", "Cluster Mode:   High Availability (Active Up) with IGMP Membership", "",
                 "ID         Unique Address  Assigned Load   State          Name"]
        for i in ("1", "2"):
            st, tag = rows[i]
            addr = "192.168.10.%d" % (1 + int(i))
            load = "100%" if st == "ACTIVE" else "0%"
            lines.append(f"{i} {tag:<8} {addr:<15} {load:<15} {st:<14} A-GW-0{i}")
        return "\n".join(lines) + "\n"

    def _add(self, args):
        rule = {"action": "drop", "name": "", "source": "any", "destination": "any",
                "service": "any", "track": "none"}
        i = 0
        try:
            while i < len(args):
                a = args[i]
                if a == "-a":
                    rule["action"] = {"d": "drop", "n": "notify"}[args[i + 1]]; i += 2
                elif a == "-n":
                    rule["name"] = args[i + 1]; i += 2
                elif a in ("source", "destination", "service", "track"):
                    rule[a] = args[i + 1].replace("cidr:", ""); i += 2
                elif a in LIMITS:
                    rule["limit"], rule["value"] = a, int(args[i + 1]); i += 2
                else:
                    return 1, "", f"Unknown argument '{a}'\n"
        except (IndexError, KeyError, ValueError):
            return 1, "", "Usage: fwaccel dos rate add [-a d|n] [-n name] <match> <limit> [track]\n"
        if "limit" not in rule:
            return 1, "", "A limit (pkt-rate, new-conn-rate, concurrent-conns, bytes) is required\n"
        uid = "<%08x,00000000,6501a8c0,%08x>" % (int(time.time()), next(self._uids))
        rule["uid"] = uid
        rule["hits"] = 0
        self.rules.append(rule)
        return 0, f"Rule added, uid={uid}\n", ""

    def _rules_text(self):
        if not self.rules:
            return "Rate limiting policy: no rules installed\n"
        out = ["Rate limiting policy (%d rules):" % len(self.rules)]
        for n, r in enumerate(self.rules):
            out.append(f"  {n}: uid={r['uid']} name={r['name']} action={r['action']} "
                       f"source={r['source']} destination={r['destination']} service={r['service']} "
                       f"{r['limit']}={r['value']} track={r['track']}")
        return "\n".join(out) + "\n"

    def _counters(self):
        if not self.rules:
            return "No rate limiting rules\n"
        elapsed = time.time() - self.started
        out = ["%-4s %-24s %-8s %14s %14s" % ("idx", "name", "action", "matched pkts", "exceeded")]
        for n, r in enumerate(self.rules):
            matched = int(elapsed * (40 + 13 * n))
            exceeded = int(elapsed * 2) if r["action"] == "drop" and r["limit"] == "new-conn-rate" else 0
            out.append("%-4d %-24s %-8s %14d %14d" % (n, r["name"], r["action"], matched, exceeded))
        return "\n".join(out) + "\n"

    def _pbox(self, args):
        p = self.pbox
        if not args:
            return 1, "", "Usage: fwaccel dos pbox <option>\n"
        a = args[0]
        if a in ("--show-config", "-c"):
            return 0, ("Penalty Box configuration:\n"
                       f"  Enabled               : {'on' if p['enabled'] else 'off'}\n"
                       f"  Drops threshold       : {p['threshold']} packets/second\n"
                       f"  Timeout               : {p['timeout']} seconds\n"
                       f"  Log drops             : {'on' if p['log_drops'] else 'off'}\n"), ""
        if a == "--show":
            now = time.time()
            self.boxed = {ip: exp for ip, exp in self.boxed.items() if exp > now}
            if not self.boxed:
                return 0, "Penalty Box is empty\n", ""
            return 0, "Penalty Box entries:\n" + "".join(
                f"  {ip}  expires in {int(exp - now)}s\n" for ip, exp in self.boxed.items()), ""
        val = args[1] if len(args) > 1 else ""
        if a == "--set-enabled":
            p["enabled"] = val == "on"
            # Simulate A-Host tripping a drop rule once enforcement is on.
            if p["enabled"] and any(r["action"] == "drop" for r in self.rules):
                self.boxed["192.168.11.201"] = time.time() + p["timeout"]
            return 0, f"Penalty Box {'enabled' if p['enabled'] else 'disabled'}\n", ""
        if a == "--set-drops-threshold":
            p["threshold"] = int(val); return 0, "OK\n", ""
        if a == "--set-timeout":
            p["timeout"] = int(val); return 0, "OK\n", ""
        if a == "--set-log-drops":
            p["log_drops"] = val == "on"; return 0, "OK\n", ""
        return 1, "", f"Unknown pbox option '{a}'\n"

    def _deny(self, args):
        a = args[0] if args else ""
        ip = args[1] if len(args) > 1 else ""
        if a in ("--show", "-s"):
            return 0, ("Deny list is empty\n" if not self.deny
                       else "Deny list:\n" + "".join(f"  {x}\n" for x in self.deny)), ""
        if a == "--add":
            if ip not in self.deny:
                self.deny.append(ip)
            return 0, f"{ip} added\n", ""
        if a == "--delete":
            if ip in self.deny:
                self.deny.remove(ip)
                return 0, f"{ip} removed\n", ""
            return 1, "", f"{ip} not in deny list\n"
        return 1, "", f"Unknown deny option '{a}'\n"


# ---------------------------------------------------------------------------
# Cluster: fan a command out to every member and keep an audit trail.
# ---------------------------------------------------------------------------

class Cluster:
    def __init__(self, settings, audit):
        self.audit = audit
        self.sims = {}
        self.reload(settings)

    def reload(self, settings):
        old = getattr(self, "transports", {})
        for t in old.values():
            t.close()
        self.settings = settings
        self.builder = CommandBuilder(settings.get("commands"))
        self.transports = {}
        for i, m in enumerate(settings["members"]):
            if settings.get("simulator"):
                # Keep simulator state across settings saves.
                key = m["name"]
                if key not in self.sims:
                    self.sims[key] = SimTransport(key, "Active" if i == 0 else "Standby")
                self.transports[key] = self.sims[key]
            else:
                self.transports[m["name"]] = SshTransport(
                    m["host"], int(settings.get("ssh_port", 22)), settings.get("ssh_user", "admin"),
                    settings.get("ssh_password", ""))

    @property
    def members(self):
        return [m["name"] for m in self.settings["members"]]

    def run(self, member, command, timeout=30, record=True, raw=False):
        started = time.time()
        try:
            rc, out, err = self.transports[member].run(command, timeout=timeout, raw=raw)
            result = {"member": member, "cmd": command, "rc": rc, "out": out, "err": err,
                      "ok": rc == 0}
        except Exception as exc:
            result = {"member": member, "cmd": command, "rc": None, "out": "",
                      "err": f"{type(exc).__name__}: {exc}", "ok": False}
        if result["ok"] and is_clish(result):
            result["ok"] = False      # clish can exit 0 after rejecting the command
        result["ms"] = int((time.time() - started) * 1000)
        result["ts"] = time.strftime("%H:%M:%S")
        if record:
            self.audit(result)
        return result

    def run_sequence(self, commands_by_member, stop_on_error=False):
        """Runs each member's list in order; members run in parallel."""
        def worker(member):
            results = []
            for cmd in commands_by_member[member]:
                res = self.run(member, cmd)
                results.append(res)
                if stop_on_error and not res["ok"]:
                    break
            return member, results
        with ThreadPoolExecutor(max_workers=max(1, len(commands_by_member))) as pool:
            return dict(pool.map(worker, list(commands_by_member)))

    def run_all(self, command, record=False):
        with ThreadPoolExecutor(max_workers=max(1, len(self.members))) as pool:
            futures = {m: pool.submit(self.run, m, command, 30, record) for m in self.members}
            return {m: f.result() for m, f in futures.items()}

    def fix_shell(self, member):
        """Sets the SSH user's login shell to bash through clish, then checks it."""
        user = self.settings.get("ssh_user", "admin")
        if not USER_RE.match(user):
            raise ValidationError("SSH user name contains unexpected characters")
        results = [self.run(member, f"set user {user} shell /bin/bash", raw=True),
                   self.run(member, "save config", raw=True)]
        self.transports[member].close()          # the new shell applies to new sessions
        check = self.run(member, "echo __bash_ok__")
        check["ok"] = "__bash_ok__" in check["out"]
        results.append(check)
        return results

    def snapshot(self):
        """Everything the dashboard needs, from every member, in parallel."""
        keys = ["cluster_state", "rate_get", "pbox_show_config", "pbox_show", "deny_show"]
        cmds = {k: self.builder.get(k) for k in keys}

        def member_view(member):
            raw = {k: self.run(member, c, record=False) for k, c in cmds.items()}
            rules = parse_rules(raw["rate_get"]["out"])
            pcfg = raw["pbox_show_config"]["out"]
            boxed = [ip for ip in parse_ips(raw["pbox_show"]["out"])]
            return member, {
                "reachable": any(r["ok"] for r in raw.values()),
                "clish": any(is_clish(r) for r in raw.values()),
                "error": next((r["err"] for r in raw.values() if r["err"] and not r["ok"]), ""),
                "cluster_state": parse_cluster_state(raw["cluster_state"]["out"]),
                "rules": rules,
                "pbox": {
                    "enabled": parse_flag(pcfg, "enable", "status", "state"),
                    "threshold": parse_number(pcfg, "threshold", "drop rate"),
                    "timeout": parse_number(pcfg, "timeout"),
                    "log_drops": parse_flag(pcfg, "log"),
                    "boxed": boxed,
                },
                "deny": parse_ips(raw["deny_show"]["out"]),
                "raw": {k: (r["out"] or r["err"]) for k, r in raw.items()},
            }

        with ThreadPoolExecutor(max_workers=max(1, len(self.members))) as pool:
            return dict(pool.map(member_view, self.members))

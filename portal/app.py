"""
SecureXL Rate Limiting portal for the CCSA Alpha lab.

Runs on A-GUI, talks to A-GW-01 and A-GW-02 over SSH, and shows / changes the
SecureXL DoS rate-limiting policy, Penalty Box and deny list that protect
A-DMZ. Binds to localhost only.

    python app.py                 start the portal (http://127.0.0.1:8088)
    python app.py --simulator     start against simulated gateways
    python app.py --export strict print a profile as a gateway bash script
"""

import argparse
import collections
import json
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

import gateway as gw

HERE = Path(__file__).resolve().parent
PRESETS_FILE = HERE / "profiles.json"
DATA_DIR = Path(os.environ.get("SXL_DATA", HERE.parent / "data"))
SETTINGS_FILE = DATA_DIR / "settings.json"
CUSTOM_FILE = DATA_DIR / "custom_profiles.json"

DEFAULT_SETTINGS = {
    "members": [
        {"name": "A-GW-01", "host": "10.1.1.2"},
        {"name": "A-GW-02", "host": "10.1.1.3"},
    ],
    "ssh_user": "admin",
    "ssh_password": "",
    "ssh_port": 22,
    "dmz_ip": "192.168.12.101",
    "lab_prefix": "ADMZ-",
    "simulator": False,
    "commands": {},
}

app = Flask(__name__)
lock = threading.Lock()
audit_log = collections.deque(maxlen=400)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    s.update(load_json(SETTINGS_FILE, {}))
    return s


def presets():
    return load_json(PRESETS_FILE, {"presets": []})["presets"]


def custom_profiles():
    return load_json(CUSTOM_FILE, [])


def all_profiles():
    return [dict(p, kind="preset") for p in presets()] + \
           [dict(p, kind="custom") for p in custom_profiles()]


def find_profile(pid):
    return next((p for p in all_profiles() if p["id"] == pid), None)


def record(result):
    audit_log.appendleft(result)


settings = load_settings()
cluster = gw.Cluster(settings, record)


def public_settings():
    s = dict(settings)
    s["ssh_password"] = "********" if settings.get("ssh_password") else ""
    s["commands"] = dict(gw.DEFAULT_COMMANDS, **settings.get("commands", {}))
    s["default_commands"] = gw.DEFAULT_COMMANDS
    return s


def error(message, status=400):
    return jsonify({"error": message}), status


# ---------------------------------------------------------------------------
# Pages and read APIs
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/settings")
def get_settings():
    return jsonify(public_settings())


@app.post("/api/settings")
def set_settings():
    global settings
    body = request.get_json(force=True)
    new = dict(settings)
    try:
        members = body.get("members", new["members"])
        if not members or len(members) > 4:
            raise gw.ValidationError("Configure between one and four cluster members")
        for m in members:
            if not gw.NAME_RE.match(str(m.get("name", ""))):
                raise gw.ValidationError(f"Member name '{m.get('name')}' is not valid")
        new["members"] = [{"name": m["name"], "host": gw.check_ip(m["host"])} for m in members]
        new["ssh_user"] = str(body.get("ssh_user", new["ssh_user"])).strip() or "admin"
        if not gw.USER_RE.match(new["ssh_user"]):
            raise gw.ValidationError("SSH user: letters, digits, '.', '_' or '-'")
        new["ssh_port"] = gw.check_int(body.get("ssh_port", new["ssh_port"]), "SSH port", 1, 65535)
        new["dmz_ip"] = gw.check_ip(body.get("dmz_ip", new["dmz_ip"]))
        prefix = str(body.get("lab_prefix", new["lab_prefix"])).strip()
        if len(prefix) < 3:
            raise gw.ValidationError("Lab prefix must be at least 3 characters, so cleanup never matches unrelated rules")
        new["lab_prefix"] = prefix
        new["simulator"] = bool(body.get("simulator", new["simulator"]))
        if body.get("ssh_password") not in (None, "", "********"):
            new["ssh_password"] = body["ssh_password"]
        if "commands" in body:
            new["commands"] = {k: v.strip() for k, v in body["commands"].items()
                               if k in gw.DEFAULT_COMMANDS and v.strip() and v.strip() != gw.DEFAULT_COMMANDS[k]}
    except (gw.ValidationError, KeyError, TypeError) as exc:
        return error(str(exc))
    with lock:
        settings = new
        save_json(SETTINGS_FILE, settings)
        cluster.reload(settings)
    return jsonify(public_settings())


@app.get("/api/state")
def state():
    with lock:
        snap = cluster.snapshot()
    prefix = settings["lab_prefix"]
    names = {m: sorted(r.get("name", "") for r in v["rules"] if r.get("name", "").startswith(prefix))
             for m, v in snap.items()}
    in_sync = len({tuple(v) for v in names.values()}) <= 1
    active = None
    for p in all_profiles():
        wanted = sorted(r["name"] for r in p["rules"])
        if wanted and all(v == wanted for v in names.values()):
            active = p["id"]
    return jsonify({"members": snap, "in_sync": in_sync, "active_profile": active,
                    "lab_rules": names, "simulator": settings.get("simulator", False),
                    "dmz_ip": settings["dmz_ip"], "prefix": prefix,
                    "time": time.strftime("%H:%M:%S")})


@app.get("/api/monitor")
def monitor():
    keys = ["rate_counters", "pbox_show"]
    out = {}
    for k in keys:
        res = cluster.run_all(cluster.builder.get(k))
        out[k] = {m: (r["out"] or r["err"]) for m, r in res.items()}
    out["boxed"] = {m: gw.parse_ips(v) for m, v in out["pbox_show"].items()}
    out["time"] = time.strftime("%H:%M:%S")
    return jsonify(out)


@app.post("/api/members/<member>/fix-shell")
def fix_shell(member):
    if member not in cluster.members:
        return error("Unknown cluster member")
    with lock:
        try:
            results = cluster.fix_shell(member)
        except gw.ValidationError as exc:
            return error(str(exc))
    return jsonify({"results": {member: results}, "failed": 0 if results[-1]["ok"] else 1})


@app.post("/api/diagnostics/<key>")
def diagnostics(key):
    if key not in gw.DIAGNOSTICS:
        return error("Not an allowed diagnostic command")
    res = cluster.run_all(cluster.builder.get(key), record=True)
    return jsonify(res)


@app.get("/api/audit")
def audit():
    return jsonify(list(audit_log))


@app.delete("/api/audit")
def clear_audit():
    audit_log.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@app.get("/api/profiles")
def list_profiles():
    return jsonify(all_profiles())


def removal_commands(member):
    """Deletes only rules whose name carries the lab prefix."""
    got = cluster.run(member, cluster.builder.get("rate_get"), record=False)
    uids = gw.lab_rule_uids(got["out"], settings["lab_prefix"])
    return [cluster.builder.rate_del(u) for u in uids]


def plan(profile, replace):
    plan_by_member = {}
    for m in cluster.members:
        cmds = removal_commands(m) if replace else []
        cmds += cluster.builder.profile(profile, settings["dmz_ip"])
        plan_by_member[m] = cmds
    return plan_by_member


@app.post("/api/profiles/<pid>/preview")
def preview_profile(pid):
    p = find_profile(pid)
    if not p:
        return error("No such profile", 404)
    replace = bool((request.get_json(silent=True) or {}).get("replace", True))
    try:
        return jsonify({"plan": plan(p, replace)})
    except gw.ValidationError as exc:
        return error(str(exc))


@app.post("/api/profiles/<pid>/apply")
def apply_profile(pid):
    p = find_profile(pid)
    if not p:
        return error("No such profile", 404)
    replace = bool((request.get_json(silent=True) or {}).get("replace", True))
    with lock:
        try:
            results = cluster.run_sequence(plan(p, replace))
        except gw.ValidationError as exc:
            return error(str(exc))
    failed = sum(1 for rs in results.values() for r in rs if not r["ok"])
    return jsonify({"results": results, "failed": failed})


@app.post("/api/profiles")
def save_profile():
    body = request.get_json(force=True)
    try:
        name = str(body.get("name", "")).strip()[:40]
        if not name:
            raise gw.ValidationError("Give the profile a name")
        rules = [gw.check_rule(r) for r in body.get("rules", [])]
        if not rules:
            raise gw.ValidationError("A profile needs at least one rule")
        prefix = settings["lab_prefix"]
        for r in rules:
            if not r["name"].startswith(prefix):
                raise gw.ValidationError(f"Rule names must start with '{prefix}' so cleanup can find them")
        if len({r["name"] for r in rules}) != len(rules):
            raise gw.ValidationError("Rule names must be unique within a profile")
        pb = body.get("pbox", {})
        pbox = {"enabled": bool(pb.get("enabled")),
                "threshold": gw.check_int(pb.get("threshold", 500), "Drops threshold"),
                "timeout": gw.check_int(pb.get("timeout", 180), "Timeout", 1, 86400),
                "log_drops": bool(pb.get("log_drops", True))}
    except gw.ValidationError as exc:
        return error(str(exc))
    customs = custom_profiles()
    pid = body.get("id") or ""
    if any(p["id"] == pid for p in presets()) or not pid.startswith("custom-"):
        pid = "custom-%d" % int(time.time() * 1000)
    profile = {"id": pid, "name": name, "tagline": str(body.get("tagline", "Custom profile"))[:60],
               "tolerance": "Custom", "level": gw.check_int(body.get("level", 2), "level", 1, 3),
               "description": str(body.get("description", ""))[:400],
               "rules": rules, "pbox": pbox}
    customs = [p for p in customs if p["id"] != pid] + [profile]
    save_json(CUSTOM_FILE, customs)
    return jsonify(profile)


@app.delete("/api/profiles/<pid>")
def delete_profile(pid):
    customs = custom_profiles()
    if not any(p["id"] == pid for p in customs):
        return error("Only custom profiles can be deleted", 400)
    save_json(CUSTOM_FILE, [p for p in customs if p["id"] != pid])
    return jsonify({"ok": True})


@app.get("/api/profiles/<pid>/export.sh")
def export_profile(pid):
    p = find_profile(pid)
    if not p:
        return error("No such profile", 404)
    return Response(export_script(p), mimetype="text/x-shellscript",
                    headers={"Content-Disposition": f"attachment; filename=admz-{pid}.sh"})


def export_script(p, s=None):
    s = s or settings
    builder = gw.CommandBuilder(s.get("commands"))
    adds = "\n".join(f"run {cmd}" for cmd in builder.profile(p, s["dmz_ip"]))
    return f"""#!/bin/bash
# SecureXL rate limiting profile '{p['name']}' for A-DMZ ({s['dmz_ip']})
# Generated by the SecureXL Rate Limiting portal.
#
# Run in Expert mode on EACH cluster member:  bash admz-{p['id']}.sh
# Pass --dry-run to print the commands without running them.
# Removes existing rules named '{s['lab_prefix']}*' first, and only those.

PREFIX='{s['lab_prefix']}'
DRY=0; [ "$1" = "--dry-run" ] && DRY=1

run() {{
    echo "+ $*"
    [ $DRY -eq 1 ] && return 0
    "$@" || echo "  !! failed (exit $?) - check the syntax for this build with: fwaccel dos rate -h"
}}

echo "== Removing previous lab rules ($PREFIX*) =="
{builder.get('rate_get')} | awk -v p="$PREFIX" '
  /uid=/ && index($0, "name=" p) {{ if (match($0, /uid=(<[^>]*>|[^ ]+)/)) print substr($0, RSTART + 4, RLENGTH - 4); next }}
  /^[ \\t]*Rule UID[ \\t]/ {{ uid = $NF; next }}
  /^[ \\t]*(Rule )?Name[ \\t]/ && index($NF, p) == 1 && uid != "" {{ print uid; uid = "" }}' |
while read -r uid; do run {builder.t['rate_del'].replace('{uid}', '"$uid"')}; done

echo "== Installing profile '{p['name']}' =="
{adds}

echo "== Result =="
{builder.get('rate_get')}
{builder.get('pbox_show_config')}
"""


# ---------------------------------------------------------------------------
# Individual rules, Penalty Box, deny list
# ---------------------------------------------------------------------------

def run_everywhere(cmds):
    with lock:
        results = cluster.run_sequence({m: list(cmds) for m in cluster.members})
    failed = sum(1 for rs in results.values() for r in rs if not r["ok"])
    return jsonify({"results": results, "failed": failed})


@app.post("/api/rules")
def add_rule():
    try:
        cmd = cluster.builder.rate_add(request.get_json(force=True), settings["dmz_ip"])
    except gw.ValidationError as exc:
        return error(str(exc))
    return run_everywhere([cmd])


@app.post("/api/rules/delete")
def delete_rule():
    body = request.get_json(force=True)
    member = body.get("member")
    try:
        cmd = cluster.builder.rate_del(body.get("uid", ""))
    except gw.ValidationError as exc:
        return error(str(exc))
    if member not in cluster.members:
        return error("Unknown cluster member")
    with lock:
        res = cluster.run(member, cmd)
    return jsonify({"results": {member: [res]}, "failed": 0 if res["ok"] else 1})


@app.post("/api/rules/delete-by-name")
def delete_rule_by_name():
    """Deletes a rule by name on every member (UIDs differ per member)."""
    name = str((request.get_json(force=True) or {}).get("name", ""))
    if not name.startswith(settings["lab_prefix"]):
        return error("Only lab rules can be removed by name")
    plan_by_member = {}
    for m in cluster.members:
        got = cluster.run(m, cluster.builder.get("rate_get"), record=False)
        uids = [r["uid"] for r in gw.parse_rules(got["out"]) if r.get("name") == name and r.get("uid")]
        plan_by_member[m] = [cluster.builder.rate_del(u) for u in uids]
    with lock:
        results = cluster.run_sequence(plan_by_member)
    return jsonify({"results": results, "failed": sum(1 for rs in results.values() for r in rs if not r["ok"])})


@app.post("/api/rules/clear-lab")
def clear_lab():
    plan_by_member = {m: removal_commands(m) for m in cluster.members}
    with lock:
        results = cluster.run_sequence(plan_by_member)
    return jsonify({"results": results, "failed": sum(1 for rs in results.values() for r in rs if not r["ok"])})


@app.post("/api/pbox")
def set_pbox():
    try:
        cmds = cluster.builder.pbox(request.get_json(force=True))
    except gw.ValidationError as exc:
        return error(str(exc))
    if not cmds:
        return error("Nothing to change")
    return run_everywhere(cmds)


@app.post("/api/deny")
def deny():
    body = request.get_json(force=True)
    try:
        ip = gw.check_ip(body.get("ip", ""))
    except gw.ValidationError as exc:
        return error(str(exc))
    op = "deny_add" if body.get("op") == "add" else "deny_del"
    return run_everywhere([cluster.builder.get(op, ip=ip)])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global settings
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=int(os.environ.get("SXL_PORT", 8088)))
    ap.add_argument("--simulator", action="store_true", help="use simulated gateways")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--export", metavar="PROFILE", help="print a profile as a gateway bash script")
    args = ap.parse_args()

    if args.export:
        p = find_profile(args.export)
        if not p:
            sys.exit(f"No profile '{args.export}'. Presets: {', '.join(x['id'] for x in presets())}")
        sys.stdout.write(export_script(p, dict(DEFAULT_SETTINGS)))
        return

    if args.simulator:
        settings["simulator"] = True
        cluster.reload(settings)

    url = f"http://127.0.0.1:{args.port}/"
    mode = "SIMULATOR" if settings.get("simulator") else "LIVE (SSH)"
    print(f"\n  SecureXL Rate Limiting portal  [{mode}]\n  {url}\n  Ctrl+C to stop\n")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()

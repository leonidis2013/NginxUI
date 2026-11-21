"""fail2ban management for NginxUI. Standard library only.

NginxUI keeps its settings in one file it owns, /etc/fail2ban/jail.d/zz-nginxui.local (loaded last, so it wins),
plus one filter of its own (nginxui-probes). Every change is tested with `fail2ban-client -t` and rolled back if
the test or the reload fails.
"""
import ipaddress
import os
import re
import shutil

SRV = None

JAIL_FILE = "/etc/fail2ban/jail.d/zz-nginxui.local"
FILTER_FILE = "/etc/fail2ban/filter.d/nginxui-probes.conf"
FILTER_DIR = "/etc/fail2ban/filter.d"
LOG_FILE = "/var/log/fail2ban.log"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
TIME_RE = re.compile(r"^(-1|\d{1,7}[smhdw]?)$")

# Jails NginxUI offers. "base" = settings written only when NginxUI turns the jail on.
KNOWN = {
    "sshd": {"title": "SSH logins", "desc": "Blocks addresses that keep failing to log in over SSH.", "base": {}},
    "nginx-http-auth": {"title": "Website password prompts",
                        "desc": "Blocks addresses that keep getting the password wrong on sites with a password prompt.",
                        "base": {"backend": "auto", "logpath": "{log_dir}/*error.log"}},
    "nginxui-probes": {"title": "Scanners looking for weak spots",
                       "desc": "Blocks bots that ask for things like /.env, /.git or wp-login.php (the scans the Security page reports).",
                       "base": {"filter": "nginxui-probes", "port": "http,https", "backend": "auto",
                                "logpath": "{log_dir}/*access.log", "maxretry": "3", "findtime": "10m", "bantime": "1d"}},
    "nginx-botsearch": {"title": "Missing-page hunters",
                        "desc": "Blocks bots that hammer nginx for files that don't exist (from nginx's error logs).",
                        "base": {"backend": "auto", "logpath": "{log_dir}/*error.log"}},
    "nginx-bad-request": {"title": "Malformed requests",
                          "desc": "Blocks addresses that keep sending broken requests (HTTP 400).",
                          "base": {"backend": "auto", "logpath": "{log_dir}/*access.log"}},
    "recidive": {"title": "Repeat offenders",
                 "desc": "Blocks addresses for a week if fail2ban had to block them 5 times in a day.",
                 "base": {"backend": "auto", "logpath": "{f2b_log}", "bantime": "1w", "findtime": "1d", "maxretry": "5"}},
}

PROBE_FILTER = r"""# Managed by NginxUI: requests for files that only scanners ask for
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|OPTIONS) [^"]*(?:/\.env|/\.git/|wp-login\.php|/wp-admin|xmlrpc\.php|phpmyadmin|/cgi-bin/|/etc/passwd|\.\./|/vendor/phpunit|/boaform|/HNAP1|/\.aws/|/actuator/|/server-status)[^"]*" (?:400|401|403|404|405|444|500)
ignoreregex =
"""


def init(srv):
    global SRV
    SRV = srv


def cfg(key, default):
    return SRV.CFG.get(key, default)


def client():
    return shutil.which("fail2ban-client")


def f2b(args, timeout=30):
    return SRV.run([client() or "fail2ban-client"] + args, timeout=timeout)


def state():
    st = SRV.jload(os.path.join(SRV.DATA, "fail2ban.json"), {})
    st.setdefault("jails", {})
    st.setdefault("ignoreip", None)
    return st


def save_state(st):
    SRV.jsave(os.path.join(SRV.DATA, "fail2ban.json"), st)


def running():
    if not client():
        return False
    rc, out = f2b(["ping"], 10)
    return rc == 0 and "pong" in out


def jail_list():
    rc, out = f2b(["status"], 15)
    m = re.search(r"Jail list:\s*(.*)", out)
    return [j.strip() for j in m.group(1).split(",") if j.strip()] if (rc == 0 and m) else []


def jail_status(name):
    rc, out = f2b(["status", name], 15)
    if rc != 0:
        return None

    def num(label):
        m = re.search(label + r":\s*(\d+)", out)
        return int(m.group(1)) if m else 0
    m = re.search(r"Banned IP list:\s*(.*)", out)
    banned = m.group(1).split() if m else []
    getv = {}
    for k in ("maxretry", "findtime", "bantime"):
        rc2, v = f2b(["get", name, k], 10)
        getv[k] = v.strip() if rc2 == 0 else None
    return {"failed_now": num("Currently failed"), "failed_total": num("Total failed"),
            "banned_now": num("Currently banned"), "banned_total": num("Total banned"), "banned": banned, **getv}


def current_ignore():
    st = state()
    if st["ignoreip"] is not None:
        return st["ignoreip"]
    for j in jail_list():
        rc, out = f2b(["get", j, "ignoreip"], 10)
        if rc == 0:
            ips = [l.strip(" |`-\t") for l in out.splitlines() if re.search(r"[0-9a-fA-F:.]+/?\d*", l)]
            ips = [x for x in ips if _valid_net(x)]
            if ips:
                return sorted(set(ips) | {"127.0.0.1/8", "::1"})
    return ["127.0.0.1/8", "::1"]


def _valid_net(x):
    try:
        ipaddress.ip_network(x, strict=False)
        return True
    except ValueError:
        return False


def in_ignore(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            pass
    return False


def available(name):
    if name == "nginxui-probes":
        return True
    return os.path.isfile(os.path.join(cfg("fail2ban_filter_dir", FILTER_DIR), f"{name}.conf")) or name == "recidive"


def render(st):
    """The managed jail file, from NginxUI's saved choices."""
    fmt = {"log_dir": SRV.CFG["log_dir"].rstrip("/"), "f2b_log": cfg("fail2ban_log", LOG_FILE)}
    out = ["# Managed by NginxUI. Change these on NginxUI's Fail2ban page; edits here are overwritten.", ""]
    if st["ignoreip"] is not None:
        out += ["[DEFAULT]", "ignoreip = " + " ".join(st["ignoreip"]), ""]
    for name, j in sorted(st["jails"].items()):
        lines = []
        if "enabled" in j:
            lines.append(f"enabled = {'true' if j['enabled'] else 'false'}")
            if j["enabled"] and name in KNOWN:
                for k, v in KNOWN[name]["base"].items():
                    if k not in j:
                        lines.append(f"{k} = {v.format(**fmt)}")
        for k in ("maxretry", "findtime", "bantime"):
            if j.get(k) not in (None, ""):
                lines.append(f"{k} = {j[k]}")
        if lines:
            out += [f"[{name}]"] + lines + [""]
    return "\n".join(out)


def apply(st, user, note):
    """Write the managed files, test, reload; restore the previous files if anything fails."""
    jf = cfg("fail2ban_jail_file", JAIL_FILE)
    ff = cfg("fail2ban_filter_file", FILTER_FILE)
    old = {p: (SRV.read_text(p) if os.path.isfile(p) else None) for p in (jf, ff)}

    def restore():
        for p, t in old.items():
            if t is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                SRV.write_atomic(p, t)
    try:
        SRV.write_atomic(jf, render(st))
        if any(n == "nginxui-probes" and j.get("enabled") for n, j in st["jails"].items()):
            SRV.write_atomic(ff, PROBE_FILTER)
    except OSError as e:
        restore()
        raise SRV.ApiError(f"Could not write fail2ban settings: {e}")
    rc, out = f2b(["-t"], 60)
    if rc != 0:
        restore()
        SRV.audit(user, "fail2ban-failed", note, False, out)
        raise SRV.ApiError("fail2ban rejected the change, so nothing changed.", 422, {"test_output": out.strip()})
    if running():
        rc, out2 = f2b(["reload"], 90)
        if rc != 0:
            restore()
            f2b(["reload"], 90)
            SRV.audit(user, "fail2ban-failed", note, False, out2)
            raise SRV.ApiError("fail2ban couldn't load the change, so it was rolled back.", 422,
                               {"test_output": (out + "\n" + out2).strip()})
    save_state(st)
    SRV.audit(user, "fail2ban", note)
    return {"ok": True}


def recent_log(limit=60):
    lines = SRV.stats.tail_lines(cfg("fail2ban_log", LOG_FILE), 4000)
    ev = []
    for l in lines:
        m = re.match(r"^(\S+ \S+?),\d+ fail2ban\.(\w+)\s*\[\d+\]:\s*(\w+)\s+\[([^\]]+)\]\s+(Ban|Unban|Found|Restore Ban|Increase Ban)\s+(\S+)", l)
        if m:
            ev.append({"t": m.group(1), "jail": m.group(4), "action": m.group(5), "ip": m.group(6)})
    found = {}
    for e in ev:
        if e["action"] == "Found":
            found[e["jail"]] = found.get(e["jail"], 0) + 1
    return [e for e in ev if e["action"] != "Found"][-limit:][::-1], found


def overview(h):
    me = SRV.client_ip(h) if h else None
    info = {"installed": bool(client()), "running": False, "jails": [], "me": me}
    if not info["installed"]:
        return info
    rc, ver = f2b(["version"], 10)
    info["version"] = ver.strip().splitlines()[-1] if rc == 0 and ver.strip() else None
    rc, act = SRV.run(["systemctl", "is-active", "fail2ban"], timeout=10)
    info["service"] = act.strip()
    info["running"] = running()
    st = state()
    live = jail_list() if info["running"] else []
    ignore = current_ignore()
    info["ignoreip"] = ignore
    info["me_ignored"] = bool(me) and in_ignore(me, ignore)
    if me:
        try:
            a = ipaddress.ip_address(me)
            info["me_net"] = str(ipaddress.ip_network(f"{me}/{24 if a.version == 4 else 64}", strict=False))
        except ValueError:
            info["me_net"] = None
    names = list(dict.fromkeys(list(KNOWN) + live + list(st["jails"])))
    banned_total = 0
    for n in names:
        if n not in KNOWN and n not in live:
            continue
        if n in KNOWN and not available(n) and n not in live:
            continue
        j = {"name": n, "title": KNOWN.get(n, {}).get("title", n), "desc": KNOWN.get(n, {}).get("desc", ""),
             "on": n in live, "managed": n in st["jails"], "known": n in KNOWN,
             "settings": {k: st["jails"].get(n, {}).get(k) for k in ("maxretry", "findtime", "bantime")}}
        if n in live:
            s = jail_status(n) or {}
            j.update(s)
            banned_total += s.get("banned_now", 0)
        info["jails"].append(j)
    info["banned_now"] = banned_total
    info["me_banned_in"] = [j["name"] for j in info["jails"] if me and me in j.get("banned", [])]
    info["log"], info["found"] = recent_log()
    return info


# ---------------------------------------------------------------- API

def api_status(h, q, b, user):
    return overview(h)


def _jail(b, live_only=False):
    n = b.get("jail", "")
    if not NAME_RE.match(n or ""):
        raise SRV.ApiError("Unknown jail")
    if live_only and n not in jail_list():
        raise SRV.ApiError(f"The {n} jail isn't running")
    return n


def _ip(b, key="ip"):
    v = (b.get(key) or "").strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise SRV.ApiError(f"'{v}' is not an IP address")
    return v


def api_unban(h, q, b, user):
    if b.get("all"):
        rc, out = f2b(["unban", "--all"], 30)
        note = "all"
    else:
        ip, j = _ip(b), _jail(b, True)
        rc, out = f2b(["set", j, "unbanip", ip], 30)
        note = f"{ip} ({j})"
    SRV.audit(user, "fail2ban-unban", note, rc == 0, out)
    if rc != 0:
        raise SRV.ApiError("fail2ban couldn't unban: " + out.strip()[-200:])
    return overview(h)


def api_ban(h, q, b, user):
    ip, j = _ip(b), _jail(b, True)
    me = SRV.client_ip(h)
    if ip == me:
        raise SRV.ApiError("That's the address you're using right now. Blocking it would lock you out.")
    if in_ignore(ip, current_ignore()):
        raise SRV.ApiError("That address is on the never-block list. Remove it there first.")
    rc, out = f2b(["set", j, "banip", ip], 30)
    SRV.audit(user, "fail2ban-ban", f"{ip} ({j})", rc == 0, out)
    if rc != 0:
        raise SRV.ApiError("fail2ban couldn't block it: " + out.strip()[-200:])
    return overview(h)


def api_jail(h, q, b, user):
    n = _jail(b)
    if n not in KNOWN and n not in jail_list():
        raise SRV.ApiError("Unknown jail")
    st = state()
    if st["ignoreip"] is None:
        st["ignoreip"] = current_ignore()  # keep today's never-block list when NginxUI starts managing settings
    j = dict(st["jails"].get(n, {}))
    if "enabled" in b:
        if b["enabled"] and n in KNOWN and not available(n):
            raise SRV.ApiError(f"This fail2ban version has no {n} filter")
        j["enabled"] = bool(b["enabled"])
    for k in ("findtime", "bantime"):
        if k in b:
            v = str(b[k]).strip()
            if v and not TIME_RE.match(v):
                raise SRV.ApiError(f"{k}: use a number with s, m, h, d or w (e.g. 10m, 1h, 1d), or -1 for forever")
            j[k] = v or None
    if "maxretry" in b:
        v = str(b["maxretry"]).strip()
        if v and (not v.isdigit() or not 1 <= int(v) <= 100):
            raise SRV.ApiError("Attempts must be between 1 and 100")
        j["maxretry"] = v or None
    st["jails"][n] = {k: v for k, v in j.items() if v is not None}
    what = ("turned on" if b.get("enabled") else "turned off") if "enabled" in b else "settings changed"
    apply(st, user, f"{n} {what}")
    return overview(h)


def api_ignore(h, q, b, user):
    st = state()
    nets = list(st["ignoreip"] if st["ignoreip"] is not None else current_ignore())
    v = (b.get("net") or "").strip()
    if not _valid_net(v):
        raise SRV.ApiError(f"'{v}' is not an IP address or range like 192.168.1.0/24")
    if b.get("remove"):
        if v in ("127.0.0.1/8", "::1"):
            raise SRV.ApiError("This server's own address always stays on the list")
        me = SRV.client_ip(h)
        rest = [x for x in nets if x != v]
        if in_ignore(me, nets) and not in_ignore(me, rest) and not b.get("confirm_self"):
            raise SRV.ApiError("Removing this means your own address could be blocked.", 409, {"self": True})
        nets = rest
    elif v not in nets:
        nets.append(v)
    st["ignoreip"] = nets
    apply(st, user, f"never-block list {'-' if b.get('remove') else '+'} {v}")
    return overview(h)


def api_service(h, q, b, user):
    act = b.get("action")
    if act == "reload":
        rc, out = f2b(["reload"], 90)
    elif act in ("start", "stop", "restart"):
        rc, out = SRV.run(["systemctl", act, "fail2ban"], timeout=90)
    else:
        raise SRV.ApiError("Unknown action")
    SRV.audit(user, f"fail2ban-{act}", "", rc == 0, out)
    if rc != 0:
        raise SRV.ApiError(f"fail2ban {act} failed", 500, {"test_output": out.strip()})
    return overview(h)


ROUTES = {
    ("GET", "/api/fail2ban"): api_status,
    ("POST", "/api/fail2ban/unban"): api_unban,
    ("POST", "/api/fail2ban/ban"): api_ban,
    ("POST", "/api/fail2ban/jail"): api_jail,
    ("POST", "/api/fail2ban/ignore"): api_ignore,
    ("POST", "/api/fail2ban/service"): api_service,
}

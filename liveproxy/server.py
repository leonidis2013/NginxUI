#!/usr/bin/env python3
"""LiveProxy - web UI for an nginx reverse proxy on Ubuntu.

Runs as a systemd service (as root, because it edits /etc/nginx, reloads nginx and runs apt).
Standard library only: works with the Python 3 that ships with Ubuntu 22.04+.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nginxconf  # noqa: E402
import stats  # noqa: E402

VERSION = "1.0.0"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
CONFIG_PATH = os.environ.get("LIVEPROXY_CONFIG", "/etc/liveproxy/liveproxy.json")

DEFAULTS = {
    "bind": "0.0.0.0",
    "port": 9443,
    "tls_cert": "/etc/liveproxy/tls/liveproxy.crt",
    "tls_key": "/etc/liveproxy/tls/liveproxy.key",
    "nginx_bin": "nginx",
    "nginx_dir": "/etc/nginx",
    "sites_available": "/etc/nginx/sites-available",
    "sites_enabled": "/etc/nginx/sites-enabled",
    "conf_d": "/etc/nginx/conf.d",
    "snippets": "/etc/nginx/snippets",
    "htpasswd_dir": "/etc/nginx/liveproxy-htpasswd",
    "log_dir": "/var/log/nginx",
    "letsencrypt_dir": "/etc/letsencrypt",
    "data_dir": "/var/lib/liveproxy",
    "reload_cmd": ["systemctl", "reload", "nginx"],
    "active_cmd": ["systemctl", "is-active", "nginx"],
    "start_cmd": ["systemctl", "start", "nginx"],
    "status_port": 8099,
    "session_hours": 12,
    "auto_upgrades_file": "/etc/apt/apt.conf.d/20auto-upgrades",
    "allow_system_updates": True,
}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    return cfg


CFG = load_config()
DATA = CFG["data_dir"]
for sub in ("", "history", "backups"):
    os.makedirs(os.path.join(DATA, sub), exist_ok=True)
try:
    os.chmod(DATA, 0o700)
except OSError:
    pass

CONF_LOCK = threading.RLock()
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")


# ---------------------------------------------------------------- helpers

def run(cmd, timeout=60, env=None):
    try:
        e = dict(os.environ)
        if env:
            e.update(env)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=e)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s: {' '.join(cmd)}"


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def write_atomic(path, content, mode=0o644):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{os.path.basename(path)}.lp-tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def jload(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def jsave(path, obj):
    write_atomic(path, json.dumps(obj, indent=2), 0o600)


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def audit(user, action, target="", ok=True, detail=""):
    line = json.dumps({"t": now_iso(), "user": user, "action": action, "target": target,
                       "ok": ok, "detail": detail[:500]})
    with open(os.path.join(DATA, "audit.log"), "a") as f:
        f.write(line + "\n")


class ApiError(Exception):
    def __init__(self, msg, status=400, extra=None):
        super().__init__(msg)
        self.status = status
        self.extra = extra or {}


# ---------------------------------------------------------------- auth

USERS_PATH = os.path.join(DATA, "users.json")
SESSIONS = {}
FAILS = {}
AUTH_LOCK = threading.Lock()


def hash_pw(pw, salt=None, it=310000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), it).hex()
    return {"salt": salt, "iter": it, "hash": h}


def check_pw(rec, pw):
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), rec["salt"].encode(), rec["iter"]).hex()
    return hmac.compare_digest(h, rec["hash"])


def users():
    return jload(USERS_PATH, {})


def validate_new_password(pw):
    if not isinstance(pw, str) or len(pw) < 10:
        raise ApiError("Password must be at least 10 characters")


def new_session(user):
    tok = secrets.token_urlsafe(32)
    with AUTH_LOCK:
        SESSIONS[tok] = {"user": user, "exp": time.time() + CFG["session_hours"] * 3600}
    return tok


def session_user(handler):
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"(?:^|;\s*)lp_session=([A-Za-z0-9_-]+)", cookie)
    if not m:
        return None
    with AUTH_LOCK:
        s = SESSIONS.get(m.group(1))
        if not s or s["exp"] < time.time():
            SESSIONS.pop(m.group(1), None)
            return None
        if s["user"] not in users():
            return None
        return s["user"]


# ---------------------------------------------------------------- nginx files

GROUPS = {
    "sites": ("sites_available", "Sites"),
    "enabled": ("sites_enabled", "Sites (enabled folder only)"),
    "conf": ("conf_d", "conf.d"),
    "snippets": ("snippets", "Snippets"),
    "main": ("nginx_dir", "Main"),
}


def file_path(fid):
    if not isinstance(fid, str) or ":" not in fid:
        raise ApiError("Bad file id")
    g, name = fid.split(":", 1)
    if g not in GROUPS or not FILE_RE.match(name):
        raise ApiError("Bad file id")
    if g == "main" and name not in ("nginx.conf", "mime.types", "proxy_params", "fastcgi_params"):
        raise ApiError("Only nginx.conf and standard param files can be edited in Main")
    base = CFG[GROUPS[g][0]]
    p = os.path.join(base, name)
    if os.path.dirname(os.path.realpath(p)) != os.path.realpath(base) and not os.path.islink(p):
        raise ApiError("Path escapes its folder")
    return g, name, p


def list_files():
    out = []
    sa, se = CFG["sites_available"], CFG["sites_enabled"]
    linked = set()
    if os.path.isdir(se):
        for n in sorted(os.listdir(se)):
            p = os.path.join(se, n)
            if os.path.islink(p):
                linked.add(os.path.basename(os.path.realpath(p)))
            elif os.path.isfile(p) and FILE_RE.match(n):
                out.append(_finfo("enabled", n, p, True))
    if os.path.isdir(sa):
        for n in sorted(os.listdir(sa)):
            p = os.path.join(sa, n)
            if os.path.isfile(p) and FILE_RE.match(n):
                out.append(_finfo("sites", n, p, n in linked))
    cd = CFG["conf_d"]
    if os.path.isdir(cd):
        for n in sorted(os.listdir(cd)):
            p = os.path.join(cd, n)
            if os.path.isfile(p) and FILE_RE.match(n) and (n.endswith(".conf") or n.endswith(".conf.disabled")):
                out.append(_finfo("conf", n, p, n.endswith(".conf")))
    sn = CFG["snippets"]
    if os.path.isdir(sn):
        for n in sorted(os.listdir(sn)):
            p = os.path.join(sn, n)
            if os.path.isfile(p) and FILE_RE.match(n):
                out.append(_finfo("snippets", n, p, None))
    p = os.path.join(CFG["nginx_dir"], "nginx.conf")
    if os.path.isfile(p):
        out.append(_finfo("main", "nginx.conf", p, None))
    return out


def _finfo(g, n, p, enabled):
    st = os.stat(p)
    head = read_text(p)[:400]
    return {"id": f"{g}:{n}", "group": g, "group_label": GROUPS[g][1], "name": n, "enabled": enabled,
            "size": st.st_size, "mtime": int(st.st_mtime), "managed": "Managed by LiveProxy" in head,
            "history": len(history_list(f"{g}:{n}"))}


# ---------------------------------------------------------------- history

def _hdir(fid):
    return os.path.join(DATA, "history", fid.replace(":", "__"))


def history_list(fid):
    d = _hdir(fid)
    if not os.path.isdir(d):
        return []
    out = []
    for n in sorted(os.listdir(d), reverse=True):
        if n.endswith(".json"):
            rec = jload(os.path.join(d, n), None)
            if rec:
                out.append({"v": n[:-5], "t": rec["t"], "user": rec["user"], "note": rec["note"],
                            "action": rec["action"], "size": len(rec.get("content") or "")})
    return out


def history_add(fid, content, user, note, action):
    d = _hdir(fid)
    os.makedirs(d, exist_ok=True)
    v = f"{int(time.time() * 1000)}"
    jsave(os.path.join(d, v + ".json"),
          {"t": now_iso(), "user": user, "note": note, "action": action, "content": content})
    files = sorted(n for n in os.listdir(d) if n.endswith(".json"))
    for n in files[:-60]:
        os.remove(os.path.join(d, n))


def history_get(fid, v):
    if not re.match(r"^\d+$", v or ""):
        raise ApiError("Bad version")
    rec = jload(os.path.join(_hdir(fid), v + ".json"), None)
    if not rec:
        raise ApiError("Version not found", 404)
    return rec


# ---------------------------------------------------------------- safe apply

def nginx_test():
    rc, out = run([CFG["nginx_bin"], "-t"], timeout=30)
    return rc == 0, out.strip()


def nginx_active():
    rc, out = run(CFG["active_cmd"], timeout=10)
    return out.strip() == "active"


def nginx_reload():
    if not nginx_active():
        return True, "nginx is not running, so it was not reloaded (changes apply when it starts)."
    rc, out = run(CFG["reload_cmd"], timeout=30)
    return rc == 0, out.strip() or "reloaded"


def _snapshot(path):
    if os.path.islink(path):
        return ("link", os.readlink(path))
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return ("file", f.read(), os.stat(path).st_mode & 0o777)
    return ("none",)


def _restore(path, snap):
    if os.path.lexists(path):
        os.remove(path)
    if snap[0] == "link":
        os.symlink(snap[1], path)
    elif snap[0] == "file":
        with open(path, "wb") as f:
            f.write(snap[1])
        os.chmod(path, snap[2])


def safe_apply(ops, user, note, history=None):
    """Apply file operations, run `nginx -t`, reload. Roll everything back on any failure.

    ops: list of ("write", path, text[, mode]) | ("delete", path) | ("link", target, linkpath)
         | ("rename", src, dst)
    history: list of (fid, content, action) recorded after success.
    """
    with CONF_LOCK:
        snaps = {}

        def snap(p):
            if p not in snaps:
                snaps[p] = _snapshot(p)

        for op in ops:
            if op[0] in ("write", "delete"):
                snap(op[1])
            elif op[0] == "link":
                snap(op[2])
            elif op[0] == "rename":
                snap(op[1])
                snap(op[2])
        try:
            for op in ops:
                if op[0] == "write":
                    write_atomic(op[1], op[2], op[3] if len(op) > 3 else 0o644)
                elif op[0] == "delete":
                    if os.path.lexists(op[1]):
                        os.remove(op[1])
                elif op[0] == "link":
                    if os.path.lexists(op[2]):
                        os.remove(op[2])
                    os.symlink(op[1], op[2])
                elif op[0] == "rename":
                    os.replace(op[1], op[2])
        except OSError as e:
            for p, s in snaps.items():
                _restore(p, s)
            raise ApiError(f"Could not write files: {e}")
        ok, out = nginx_test()
        if not ok:
            for p, s in snaps.items():
                _restore(p, s)
            audit(user, "apply-failed", note, False, out)
            raise ApiError("nginx rejected the change, so nothing was applied. Your previous config is still live.",
                           422, {"test_output": out})
        rok, rout = nginx_reload()
        if not rok:
            for p, s in snaps.items():
                _restore(p, s)
            nginx_reload()
            audit(user, "reload-failed", note, False, rout)
            raise ApiError("nginx failed to reload, so the change was rolled back.", 422,
                           {"test_output": out + "\n" + rout})
        for fid, content, action in history or []:
            history_add(fid, content, user, note, action)
        audit(user, "apply", note, True)
        return {"ok": True, "test_output": out, "reload": rout}


def ensure_original(fid, path):
    """Store the pre-LiveProxy version of a file once, so it can always be restored."""
    if not history_list(fid) and os.path.isfile(path):
        history_add(fid, read_text(path), "system", "Original (before first edit in LiveProxy)", "original")


# ---------------------------------------------------------------- htpasswd

def ssha(pw):
    salt = secrets.token_bytes(8)
    d = hashlib.sha1(pw.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(d + salt).decode()


# ---------------------------------------------------------------- flow

def gather_config_files():
    rc, out = run([CFG["nginx_bin"], "-T"], timeout=30)
    files = nginxconf.split_nginx_T(out) if rc == 0 else []
    if files:
        return files, "nginx -T"
    files = []
    for f in list_files():
        if f["enabled"] is False or f["group"] == "snippets":
            continue
        _, _, p = file_path(f["id"])
        files.append((p, read_text(p)))
    return files, "files"


def tcp_check(addr):
    t0 = time.time()
    if addr.startswith("unix:"):
        return {"up": os.path.exists(addr[5:]), "ms": None}
    host, port = addr.rsplit(":", 1)
    host = host.strip("[]")
    try:
        with socket.create_connection((host, int(port)), timeout=1.5):
            return {"up": True, "ms": round((time.time() - t0) * 1000, 1)}
    except (OSError, ValueError) as e:
        return {"up": False, "ms": None, "error": str(e)[:80]}


def build_flow():
    files, source = gather_config_files()
    flow = nginxconf.extract(files)
    backends = nginxconf.resolve_targets(flow)
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda b: tcp_check(b["address"]), backends))
    for b, r in zip(backends, results):
        b.update(r)
    default_log = os.path.join(CFG["log_dir"], "access.log")
    log_users = {}
    for i, s in enumerate(flow["servers"]):
        logs = [l for l in s["access_logs"] if l != "off"] or ([] if "off" in s["access_logs"] else [default_log])
        s["logs"] = logs
        for l in logs:
            log_users.setdefault(l, []).append(i)
    counts = {}
    for l in log_users:
        if os.path.isfile(l):
            counts[l] = stats.count_recent(l, 5)
    for i, s in enumerate(flow["servers"]):
        own = [l for l in s["logs"] if len(log_users.get(l, [])) == 1]
        shared = [l for l in s["logs"] if len(log_users.get(l, [])) > 1]
        s["req_5m"] = sum(counts.get(l, 0) for l in own) if own else None
        s["shared_log"] = bool(shared and not own)
        s["id"] = i
    ports = sorted({(l["port"], l["ssl"]) for s in flow["servers"] for l in s["listen"]})
    shared_total = sum(counts.get(l, 0) for l, us in log_users.items() if len(us) > 1)
    return {"servers": flow["servers"], "upstreams": flow["upstreams"], "backends": backends,
            "ports": [{"port": p, "ssl": s} for p, s in ports], "errors": flow["errors"],
            "source": source, "shared_req_5m": shared_total, "generated": now_iso()}


# ---------------------------------------------------------------- system + updates

def os_release():
    d = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip('"')
    return d


def system_info():
    up = read_text("/proc/uptime", "0 0").split()[0]
    load = read_text("/proc/loadavg", "0 0 0").split()[:3]
    mem = {}
    for line in read_text("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        mem[k] = int(v.strip().split()[0]) * 1024 if v.strip() else 0
    du = shutil.disk_usage("/")
    rr = os.path.exists("/var/run/reboot-required")
    rr_pkgs = read_text("/var/run/reboot-required.pkgs").split()
    rc, nv = run([CFG["nginx_bin"], "-v"], timeout=10)
    return {
        "hostname": socket.gethostname(), "os": os_release().get("PRETTY_NAME", "Linux"),
        "kernel": os.uname().release, "uptime_s": int(float(up)),
        "load": [float(x) for x in load], "cpus": os.cpu_count(),
        "mem_total": mem.get("MemTotal", 0), "mem_avail": mem.get("MemAvailable", 0),
        "disk_total": du.total, "disk_used": du.used,
        "reboot_required": rr, "reboot_pkgs": sorted(set(rr_pkgs)),
        "nginx_version": nv.strip().replace("nginx version: ", "") if rc == 0 else None,
    }


def nginx_status():
    ok, out = nginx_test()
    rc, since = run(["systemctl", "show", "nginx", "-p", "ActiveEnterTimestamp", "--value"], timeout=10)
    return {"active": nginx_active(), "test_ok": ok, "test_output": out,
            "since": since.strip() if rc == 0 else None}


def nginx_package_info():
    rc, out = run(["apt-cache", "policy", "nginx"], timeout=20)
    info = {"installed": None, "candidate": None, "source": None}
    if rc != 0:
        return info
    m = re.search(r"Installed:\s*(\S+)", out)
    c = re.search(r"Candidate:\s*(\S+)", out)
    info["installed"] = m.group(1) if m else None
    info["candidate"] = c.group(1) if c else None
    # repo line under the candidate version, e.g. "500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages"
    lines = out.splitlines()
    for i, l in enumerate(lines):
        if info["candidate"] and re.match(r"^\s*(\*\*\*)?\s*" + re.escape(info["candidate"]) + r"\s", l) and i + 1 < len(lines):
            parts = lines[i + 1].split()
            if len(parts) >= 3 and parts[1].startswith("http"):
                info["source"] = f"{parts[1]} {parts[2]}"
            elif len(parts) >= 2:
                info["source"] = "installed package" if "dpkg/status" in parts[1] else parts[1]
            break
    return info


def auto_upgrades_state():
    txt = read_text(CFG["auto_upgrades_file"])
    installed = shutil.which("unattended-upgrade") is not None
    on = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', txt))
    return {"installed": installed, "enabled": on and installed}


UPD_PATH = os.path.join(DATA, "updates.json")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a", "APT_LISTCHANGES_FRONTEND": "none"}
APT_OPTS = ["-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]


def parse_upgradable(text):
    pkgs = []
    for line in text.splitlines():
        m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            pkgs.append({"name": m.group(1), "archives": m.group(2), "new": m.group(3), "arch": m.group(4),
                         "old": m.group(5), "security": "-security" in m.group(2),
                         "nginx": m.group(1).startswith(("nginx", "libnginx"))})
    return pkgs


def installed_nginx_pkgs():
    rc, out = run(["dpkg-query", "-W", "-f", "${Package} ${Status}\\n"], timeout=30)
    return [l.split()[0] for l in out.splitlines()
            if l.startswith(("nginx", "libnginx-mod")) and "install ok installed" in l]


class Job:
    def __init__(self, title):
        self.id = secrets.token_hex(6)
        self.title = title
        self.lines = []
        self.done = False
        self.ok = None
        self.started = now_iso()
        self.lock = threading.Lock()

    def log(self, s):
        with self.lock:
            for l in str(s).splitlines() or [""]:
                self.lines.append(l)
            if len(self.lines) > 20000:
                self.lines = self.lines[-15000:]

    def stream(self, cmd, env=None):
        self.log(f"$ {' '.join(cmd)}")
        e = dict(os.environ)
        e.update(env or {})
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=e)
        except FileNotFoundError:
            self.log(f"command not found: {cmd[0]}")
            return 127
        for raw in p.stdout:
            self.log(raw.decode("utf-8", "replace").rstrip())
        return p.wait()


JOBS = {}
JOB_LOCK = threading.Lock()
CURRENT_JOB = {"id": None}


def start_job(title, fn, user):
    with JOB_LOCK:
        cur = JOBS.get(CURRENT_JOB["id"])
        if cur and not cur.done:
            raise ApiError(f"Another task is running: {cur.title}", 409)
        job = Job(title)
        JOBS[job.id] = job
        CURRENT_JOB["id"] = job.id

    def wrapper():
        try:
            job.ok = bool(fn(job))
        except Exception as e:
            job.log(f"ERROR: {e}")
            job.ok = False
        job.done = True
        job.log("")
        job.log("Finished: " + ("success" if job.ok else "with problems - see above"))
        audit(user, "task", title, job.ok)

    threading.Thread(target=wrapper, daemon=True).start()
    return job


def job_check_updates(job):
    rc = job.stream(["apt-get", "update"], APT_ENV)
    if rc != 0:
        job.log("apt-get update reported a problem (see above). Showing what is known.")
    rc2, out = run(["apt", "list", "--upgradable"], timeout=120)
    pkgs = parse_upgradable(out)
    jsave(UPD_PATH, {"checked": now_iso(), "packages": pkgs})
    job.log(f"{len(pkgs)} package(s) can be updated "
            f"({sum(p['security'] for p in pkgs)} security, {sum(p['nginx'] for p in pkgs)} nginx).")
    return rc == 0


def make_apply_job(scope, user):
    def fn(job):
        was_active = nginx_active()
        job.log("Step 1: backing up nginx config")
        b = create_backup(f"before-{scope}-update", user)
        job.log(f"  saved {b['name']}")
        job.log("Step 2: refreshing package lists")
        job.stream(["apt-get", "update"], APT_ENV)
        job.log(f"Step 3: installing updates ({scope})")
        if scope == "all":
            rc = job.stream(["apt-get"] + APT_OPTS + ["--with-new-pkgs", "upgrade"], APT_ENV)
        elif scope == "security":
            rc0, out = run(["apt", "list", "--upgradable"], timeout=120)
            pk = [p["name"] for p in parse_upgradable(out) if p["security"]]
            if not pk:
                job.log("No security updates are waiting.")
                rc = 0
            else:
                rc = job.stream(["apt-get"] + APT_OPTS + ["install", "--only-upgrade"] + pk, APT_ENV)
        elif scope == "nginx":
            pk = installed_nginx_pkgs()
            if not pk:
                job.log("nginx is not installed from apt; nothing to update.")
                rc = 0
            else:
                rc = job.stream(["apt-get"] + APT_OPTS + ["install", "--only-upgrade"] + pk, APT_ENV)
        else:
            raise ApiError("Unknown scope")
        job.log("Step 4: checking nginx")
        ok, out = nginx_test()
        job.log(out)
        if was_active and not nginx_active():
            job.log("nginx stopped during the update; starting it again")
            job.stream(CFG["start_cmd"])
        active = nginx_active()
        job.log(f"nginx is {'running' if active else 'NOT running'}; config test {'passed' if ok else 'FAILED'}")
        if not ok:
            job.log(f"Tip: Backups > {b['name']} has your config from right before this update.")
        rc2, out = run(["apt", "list", "--upgradable"], timeout=120)
        jsave(UPD_PATH, {"checked": now_iso(), "packages": parse_upgradable(out)})
        if os.path.exists("/var/run/reboot-required"):
            job.log("A reboot is required to finish installing some updates (Updates page > Reboot).")
        return rc == 0 and ok and (active or not was_active)
    return fn


# ---------------------------------------------------------------- backups

BK_RE = re.compile(r"^nginx-\d{8}-\d{6}-[A-Za-z0-9_-]{1,40}\.tar\.gz$")


def create_backup(reason, user):
    reason = re.sub(r"[^A-Za-z0-9_-]", "-", reason)[:40] or "manual"
    name = f"nginx-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{reason}.tar.gz"
    path = os.path.join(DATA, "backups", name)
    with CONF_LOCK, tarfile.open(path, "w:gz") as t:
        t.add(CFG["nginx_dir"], arcname="nginx")
        if os.path.isdir(CFG["htpasswd_dir"]) and not CFG["htpasswd_dir"].startswith(CFG["nginx_dir"] + "/"):
            t.add(CFG["htpasswd_dir"], arcname="liveproxy-htpasswd")
    os.chmod(path, 0o600)
    autos = sorted(n for n in os.listdir(os.path.join(DATA, "backups")) if BK_RE.match(n) and "-manual" not in n)
    for n in autos[:-30]:
        os.remove(os.path.join(DATA, "backups", n))
    audit(user, "backup", name)
    return {"name": name}


def list_backups():
    d = os.path.join(DATA, "backups")
    out = []
    for n in sorted(os.listdir(d), reverse=True):
        if BK_RE.match(n):
            st = os.stat(os.path.join(d, n))
            out.append({"name": n, "size": st.st_size, "t": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")})
    return out


def _safe_members(t):
    for m in t.getmembers():
        if m.name.startswith("/") or ".." in m.name.split("/") or not (m.name == "nginx" or m.name.startswith("nginx/")):
            continue
        if m.isdev():
            continue
        if (m.issym() or m.islnk()) and (m.linkname.startswith("/") is False and ".." in m.linkname.split("/")):
            # relative links that climb out are skipped; absolute ones (sites-enabled) are normal
            continue
        yield m


def restore_backup(name, user):
    if not BK_RE.match(name or ""):
        raise ApiError("Bad backup name")
    src = os.path.join(DATA, "backups", name)
    if not os.path.isfile(src):
        raise ApiError("Backup not found", 404)
    nd = CFG["nginx_dir"].rstrip("/")
    parent = os.path.dirname(nd)
    with CONF_LOCK:
        create_backup("before-restore", user)
        tmp = os.path.join(parent, f".liveproxy-restore-{secrets.token_hex(4)}")
        os.makedirs(tmp)
        with tarfile.open(src, "r:gz") as t:
            members = list(_safe_members(t))
            kw = {"filter": "tar"} if hasattr(tarfile, "data_filter") else {}
            t.extractall(tmp, members=members, **kw)
        new = os.path.join(tmp, "nginx")
        if not os.path.isdir(new):
            shutil.rmtree(tmp, ignore_errors=True)
            raise ApiError("Backup does not contain an nginx folder")
        old = f"{nd}.liveproxy-prev"
        if os.path.exists(old):
            shutil.rmtree(old)
        os.rename(nd, old)
        os.rename(new, nd)
        shutil.rmtree(tmp, ignore_errors=True)
        ok, out = nginx_test()
        if ok:
            rok, rout = nginx_reload()
            ok = rok
            out += "\n" + rout
        if not ok:
            shutil.rmtree(nd)
            os.rename(old, nd)
            nginx_reload()
            audit(user, "restore-failed", name, False, out)
            raise ApiError("The restored config failed the nginx test, so your current config was kept.", 422,
                           {"test_output": out})
        shutil.rmtree(old, ignore_errors=True)
        audit(user, "restore", name)
        return {"ok": True, "test_output": out}


# ---------------------------------------------------------------- certificates

def list_certs():
    live = os.path.join(CFG["letsencrypt_dir"], "live")
    out = []
    if not os.path.isdir(live):
        return out
    for n in sorted(os.listdir(live)):
        d = os.path.join(live, n)
        fc, pk = os.path.join(d, "fullchain.pem"), os.path.join(d, "privkey.pem")
        if not os.path.exists(fc):
            continue
        rc, o = run(["openssl", "x509", "-enddate", "-noout", "-in", fc], timeout=10)
        exp = o.strip().split("=", 1)[-1] if rc == 0 else None
        days = None
        if exp:
            try:
                days = int((datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).total_seconds() // 86400)
            except ValueError:
                pass
        out.append({"name": n, "cert": fc, "key": pk, "expires": exp, "days_left": days})
    return out


# ---------------------------------------------------------------- environment checks

def environment():
    warn = []
    nb = shutil.which(CFG["nginx_bin"]) or (CFG["nginx_bin"] if os.path.exists(CFG["nginx_bin"]) else None)
    if not nb:
        warn.append("nginx was not found on this server. Install it with: sudo apt install nginx")
    if not os.path.isdir(CFG["sites_available"]):
        warn.append(f"{CFG['sites_available']} does not exist - this does not look like Ubuntu's nginx package layout.")
    if shutil.which("docker"):
        rc, out = run(["docker", "ps", "--format", "{{.Image}} {{.Names}}"], timeout=10)
        if rc == 0 and re.search(r"jc21/nginx-proxy-manager|nginx-proxy-manager", out):
            warn.append("Nginx Proxy Manager is running in Docker on this server. LiveProxy manages the "
                        "host's own nginx, not Nginx Proxy Manager's configs.")
    return {"nginx_found": bool(nb), "warnings": warn}


# ---------------------------------------------------------------- API handlers

def body_str(b, key, maxlen=200):
    v = b.get(key)
    if not isinstance(v, str) or not v or len(v) > maxlen:
        raise ApiError(f"{key} is required")
    return v


def api_session(h, q, b, user):
    return {"authenticated": bool(user), "user": user, "setup_needed": not users(), "version": VERSION,
            "hostname": socket.gethostname()}


def api_setup(h, q, b, user):
    with AUTH_LOCK:
        if users():
            raise ApiError("Setup is already done", 403)
        name = body_str(b, "username", 64)
        if not re.match(r"^[A-Za-z0-9._-]{2,64}$", name):
            raise ApiError("Username may use letters, digits, dot, dash, underscore")
        validate_new_password(b.get("password"))
        jsave(USERS_PATH, {name: hash_pw(b["password"])})
    audit(name, "setup", "first admin created")
    return {"ok": True, "_cookie": new_session(name)}


def api_login(h, q, b, user):
    ip = h.client_address[0]
    with AUTH_LOCK:
        f = FAILS.get(ip, [0, 0])
        if f[1] > time.time():
            raise ApiError(f"Too many attempts. Try again in {int(f[1] - time.time())}s.", 429)
    name, pw = b.get("username", ""), b.get("password", "")
    rec = users().get(name)
    if not rec or not isinstance(pw, str) or not check_pw(rec, pw):
        with AUTH_LOCK:
            f = FAILS.get(ip, [0, 0])
            f[0] += 1
            if f[0] >= 5:
                f = [0, time.time() + 300]
            FAILS[ip] = f
        audit(name or "?", "login-failed", ip, False)
        time.sleep(0.5)
        raise ApiError("Wrong username or password", 401)
    FAILS.pop(ip, None)
    audit(name, "login", ip)
    return {"ok": True, "_cookie": new_session(name)}


def api_logout(h, q, b, user):
    m = re.search(r"(?:^|;\s*)lp_session=([A-Za-z0-9_-]+)", h.headers.get("Cookie", ""))
    if m:
        SESSIONS.pop(m.group(1), None)
    return {"ok": True, "_cookie": ""}


def api_overview(h, q, b, user):
    upd = jload(UPD_PATH, {"checked": None, "packages": []})
    logs = [os.path.join(CFG["log_dir"], n) for n in safe_listdir(CFG["log_dir"])
            if n.endswith("access.log")]
    files = list_files()
    sites = [f for f in files if f["group"] in ("sites", "enabled", "conf")]
    audit_lines = read_text(os.path.join(DATA, "audit.log")).splitlines()[-8:]
    return {
        "nginx": nginx_status(), "system": system_info(), "env": environment(),
        "sites_total": len(sites), "sites_enabled": sum(1 for f in sites if f["enabled"]),
        "updates": {"checked": upd["checked"], "count": len(upd["packages"]),
                    "security": sum(p["security"] for p in upd["packages"]),
                    "nginx": sum(p["nginx"] for p in upd["packages"])},
        "traffic": stats.summarize(logs, 60),
        "activity": [json.loads(l) for l in reversed(audit_lines) if l.strip()],
        "live": live_stats(),
    }


def safe_listdir(d):
    try:
        return sorted(os.listdir(d))
    except OSError:
        return []


def api_files(h, q, b, user):
    return {"files": list_files()}


def api_file_get(h, q, b, user):
    fid = q.get("id", "")
    g, name, p = file_path(fid)
    if not os.path.isfile(p):
        raise ApiError("File not found", 404)
    return {"id": fid, "name": name, "group": g, "content": read_text(p), "history": history_list(fid)}


def api_file_save(h, q, b, user):
    fid = body_str(b, "id")
    content = b.get("content")
    if not isinstance(content, str) or len(content) > 1_000_000:
        raise ApiError("Content missing or too large")
    g, name, p = file_path(fid)
    if not os.path.isfile(p):
        raise ApiError("File not found", 404)
    ensure_original(fid, p)
    note = (b.get("note") or "Edited in config editor")[:200]
    return safe_apply([("write", p, content)], user, f"{note} ({name})", [(fid, content, "save")])


def api_file_create(h, q, b, user):
    g = b.get("group")
    if g not in ("sites", "conf", "snippets"):
        raise ApiError("New files can go in Sites, conf.d or Snippets")
    name = body_str(b, "name", 120)
    if g == "conf" and not name.endswith(".conf"):
        name += ".conf"
    fid = f"{g}:{name}"
    _, _, p = file_path(fid)
    if os.path.exists(p):
        raise ApiError("A file with that name already exists")
    content = b.get("content") or f"# {name}\n"
    ops = [("write", p, content)]
    if g == "sites" and b.get("enable", True):
        ops.append(("link", p, os.path.join(CFG["sites_enabled"], name)))
    res = safe_apply(ops, user, f"Created {name}", [(fid, content, "create")])
    res["id"] = fid
    return res


def api_file_enable(h, q, b, user):
    fid = body_str(b, "id")
    g, name, p = file_path(fid)
    en = bool(b.get("enabled"))
    if g == "sites":
        link = os.path.join(CFG["sites_enabled"], name)
        ops = [("link", p, link)] if en else [("delete", link)]
        res = safe_apply(ops, user, f"{'Enabled' if en else 'Disabled'} {name}")
        res["id"] = fid
        return res
    if g == "conf":
        if en and name.endswith(".conf.disabled"):
            new = name[:-len(".disabled")]
        elif not en and name.endswith(".conf"):
            new = name + ".disabled"
        else:
            return {"ok": True, "id": fid}
        np_ = os.path.join(CFG["conf_d"], new)
        if os.path.exists(np_):
            raise ApiError(f"{new} already exists")
        res = safe_apply([("rename", p, np_)], user, f"{'Enabled' if en else 'Disabled'} {name}")
        # move history with the file
        old_h, new_h = _hdir(fid), _hdir(f"conf:{new}")
        if os.path.isdir(old_h) and not os.path.exists(new_h):
            os.rename(old_h, new_h)
        res["id"] = f"conf:{new}"
        return res
    raise ApiError("This file cannot be enabled or disabled")


def api_file_delete(h, q, b, user):
    fid = body_str(b, "id")
    g, name, p = file_path(fid)
    if g == "main":
        raise ApiError("nginx.conf cannot be deleted")
    if not os.path.isfile(p):
        raise ApiError("File not found", 404)
    content = read_text(p)
    ops = [("delete", p)]
    if g == "sites":
        link = os.path.join(CFG["sites_enabled"], name)
        if os.path.islink(link):
            ops.insert(0, ("delete", link))
    ensure_original(fid, p)
    return safe_apply(ops, user, f"Deleted {name}", [(fid, content, "deleted")])


def api_history(h, q, b, user):
    fid = q.get("id", "")
    file_path(fid)
    return {"history": history_list(fid)}


def api_history_get(h, q, b, user):
    fid = q.get("id", "")
    file_path(fid)
    rec = history_get(fid, q.get("v"))
    return rec


def api_history_rollback(h, q, b, user):
    fid = body_str(b, "id")
    g, name, p = file_path(fid)
    rec = history_get(fid, body_str(b, "v"))
    content = rec["content"]
    ops = [("write", p, content)]
    if g == "sites" and not os.path.exists(p) and b.get("enable", True):
        ops.append(("link", p, os.path.join(CFG["sites_enabled"], name)))
    if os.path.isfile(p):
        ensure_original(fid, p)
    return safe_apply(ops, user, f"Rolled back {name} to version from {rec['t']}", [(fid, content, "rollback")])


def api_deleted(h, q, b, user):
    """Files that only exist in history now (deleted), so they can be restored."""
    out = []
    d = os.path.join(DATA, "history")
    for n in safe_listdir(d):
        fid = n.replace("__", ":", 1)
        try:
            _, name, p = file_path(fid)
        except ApiError:
            continue
        if not os.path.exists(p):
            hl = history_list(fid)
            if hl:
                out.append({"id": fid, "name": name, "deleted": hl[0]["t"], "v": hl[0]["v"]})
    return {"deleted": out}


def api_nginx_test(h, q, b, user):
    ok, out = nginx_test()
    return {"ok": ok, "output": out}


def api_nginx_reload(h, q, b, user):
    ok, out = nginx_test()
    if not ok:
        raise ApiError("Config test failed; not reloading", 422, {"test_output": out})
    rok, rout = nginx_reload()
    audit(user, "reload", "", rok, rout)
    if not rok:
        raise ApiError("Reload failed", 500, {"test_output": rout})
    return {"ok": True, "output": out + "\n" + rout}


def api_nginx_start(h, q, b, user):
    rc, out = run(CFG["start_cmd"], timeout=30)
    audit(user, "start-nginx", "", rc == 0, out)
    if rc != 0:
        raise ApiError("nginx failed to start", 500, {"test_output": out})
    return {"ok": True}


def nginx_version_tuple():
    rc, out = run([CFG["nginx_bin"], "-v"], timeout=10)
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else (1, 18, 0)


def wizard_params(b):
    p = dict(b.get("params") or {})
    p["_new_http2"] = nginx_version_tuple() >= (1, 25, 1)
    # skip [::] listeners on servers with IPv6 turned off, or nginx would refuse to start
    p["_ipv6"] = os.path.exists("/proc/net/if_inet6") and bool(read_text("/proc/net/if_inet6").strip())
    return p


def api_wizard_preview(h, q, b, user):
    try:
        text = nginxconf.generate(b.get("type"), wizard_params(b), b.get("name") or "")
    except nginxconf.WizardError as e:
        raise ApiError(str(e))
    return {"content": text.replace("{HTPASSWD_DIR}", CFG["htpasswd_dir"])}


def api_wizard_apply(h, q, b, user):
    name = b.get("name") or ""
    params = wizard_params(b)
    try:
        text = nginxconf.generate(b.get("type"), params, name)
        auth = nginxconf.basic_auth_users(params)
    except nginxconf.WizardError as e:
        raise ApiError(str(e))
    text = text.replace("{HTPASSWD_DIR}", CFG["htpasswd_dir"])
    fid = f"sites:{name}"
    _, _, p = file_path(fid)
    exists = os.path.exists(p)
    if exists and not b.get("overwrite"):
        raise ApiError(f"A site named {name} already exists. Pick another name or allow overwrite.", 409)
    if exists:
        ensure_original(fid, p)
    ops = [("write", p, text)]
    if auth:
        hp = "".join(f"{u}:{ssha(pw)}\n" for u, pw in auth)
        os.makedirs(CFG["htpasswd_dir"], exist_ok=True)
        ops.insert(0, ("write", os.path.join(CFG["htpasswd_dir"], name), hp, 0o640))
    if b.get("enable", True):
        ops.append(("link", p, os.path.join(CFG["sites_enabled"], name)))
    res = safe_apply(ops, user, f"Wizard '{b.get('type')}' {'updated' if exists else 'created'} {name}",
                     [(fid, text, "wizard")])
    if auth:
        try:
            shutil.chown(os.path.join(CFG["htpasswd_dir"], name), group="www-data")
        except (LookupError, PermissionError, OSError):
            pass
    res["id"] = fid
    return res


def api_certs(h, q, b, user):
    return {"certs": list_certs()}


def api_flow(h, q, b, user):
    return build_flow()


def api_stats(h, q, b, user):
    minutes = int(q.get("minutes", "15") or 15)
    minutes = max(1, min(minutes, 24 * 60))
    names = [n for n in safe_listdir(CFG["log_dir"]) if n.endswith("access.log")]
    pick = q.get("log") or ""
    if pick:
        if pick not in names:
            raise ApiError("Unknown log")
        names = [pick]
    s = stats.summarize([os.path.join(CFG["log_dir"], n) for n in names], minutes)
    s["logs"] = [n for n in safe_listdir(CFG["log_dir"]) if n.endswith("access.log")]
    s["live"] = live_stats()
    return s


def live_stats():
    url = f"http://127.0.0.1:{int(CFG['status_port'])}/nginx_status"
    try:
        with urllib.request.urlopen(url, timeout=1) as r:
            d = stats.parse_stub_status(r.read().decode())
            return {"enabled": bool(d), **(d or {})}
    except Exception:
        return {"enabled": False}


def api_live_enable(h, q, b, user):
    p = os.path.join(CFG["conf_d"], "liveproxy-status.conf")
    return safe_apply([("write", p, nginxconf.STATUS_CONF % int(CFG["status_port"]))], user,
                      "Enabled live connection stats", [("conf:liveproxy-status.conf",
                                                         nginxconf.STATUS_CONF % int(CFG["status_port"]), "create")])


def api_logs(h, q, b, user):
    out = []
    for n in safe_listdir(CFG["log_dir"]):
        p = os.path.join(CFG["log_dir"], n)
        if os.path.isfile(p) and n.endswith(".log"):
            st = os.stat(p)
            out.append({"name": n, "size": st.st_size, "mtime": int(st.st_mtime)})
    return {"logs": out}


def api_log_tail(h, q, b, user):
    n = q.get("file", "")
    if not FILE_RE.match(n) or not n.endswith(".log"):
        raise ApiError("Bad log name")
    p = os.path.join(CFG["log_dir"], n)
    if not os.path.isfile(p):
        raise ApiError("Log not found", 404)
    lines = max(10, min(int(q.get("lines", "200") or 200), 5000))
    return {"lines": stats.tail_lines(p, lines, q.get("q") or None), "size": os.path.getsize(p)}


def api_updates(h, q, b, user):
    upd = jload(UPD_PATH, {"checked": None, "packages": []})
    cur = JOBS.get(CURRENT_JOB["id"])
    return {**upd, "auto": auto_upgrades_state(), "nginx_pkg": nginx_package_info(),
            "system": system_info(), "allowed": CFG["allow_system_updates"],
            "job": {"id": cur.id, "title": cur.title, "done": cur.done} if cur else None}


def _require_updates():
    if not CFG["allow_system_updates"]:
        raise ApiError("System updates are turned off in /etc/liveproxy/liveproxy.json", 403)


def api_updates_check(h, q, b, user):
    _require_updates()
    j = start_job("Check for updates", job_check_updates, user)
    return {"job": j.id}


def api_updates_apply(h, q, b, user):
    _require_updates()
    scope = b.get("scope")
    if scope not in ("all", "security", "nginx"):
        raise ApiError("Unknown update type")
    titles = {"all": "Install all updates", "security": "Install security updates", "nginx": "Update nginx"}
    j = start_job(titles[scope], make_apply_job(scope, user), user)
    return {"job": j.id}


def api_updates_auto(h, q, b, user):
    _require_updates()
    st = auto_upgrades_state()
    if not st["installed"]:
        raise ApiError("unattended-upgrades is not installed (sudo apt install unattended-upgrades)")
    en = "1" if b.get("enabled") else "0"
    write_atomic(CFG["auto_upgrades_file"],
                 f'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "{en}";\n')
    audit(user, "auto-updates", "on" if en == "1" else "off")
    return auto_upgrades_state()


def api_job(h, q, b, user):
    j = JOBS.get(q.get("id", ""))
    if not j:
        raise ApiError("Task not found", 404)
    since = int(q.get("since", "0") or 0)
    with j.lock:
        return {"id": j.id, "title": j.title, "done": j.done, "ok": j.ok, "started": j.started,
                "lines": j.lines[since:], "next": len(j.lines)}


def api_reboot(h, q, b, user):
    _require_updates()
    if b.get("confirm") != "REBOOT":
        raise ApiError("Type REBOOT to confirm")
    audit(user, "reboot", "")
    threading.Timer(3, lambda: run(["systemctl", "reboot"])).start()
    return {"ok": True}


def api_backups(h, q, b, user):
    return {"backups": list_backups()}


def api_backup_create(h, q, b, user):
    return create_backup("manual", user)


def api_backup_restore(h, q, b, user):
    return restore_backup(body_str(b, "name"), user)


def api_backup_delete(h, q, b, user):
    n = body_str(b, "name")
    if not BK_RE.match(n):
        raise ApiError("Bad backup name")
    p = os.path.join(DATA, "backups", n)
    if os.path.isfile(p):
        os.remove(p)
    audit(user, "backup-delete", n)
    return {"ok": True}


def api_users(h, q, b, user):
    return {"users": sorted(users().keys()), "me": user}


def api_user_add(h, q, b, user):
    name = body_str(b, "username", 64)
    if not re.match(r"^[A-Za-z0-9._-]{2,64}$", name):
        raise ApiError("Username may use letters, digits, dot, dash, underscore")
    validate_new_password(b.get("password"))
    with AUTH_LOCK:
        u = users()
        if name in u:
            raise ApiError("That user already exists")
        u[name] = hash_pw(b["password"])
        jsave(USERS_PATH, u)
    audit(user, "user-add", name)
    return {"ok": True}


def api_user_delete(h, q, b, user):
    name = body_str(b, "username", 64)
    with AUTH_LOCK:
        u = users()
        if name not in u:
            raise ApiError("No such user")
        if len(u) == 1:
            raise ApiError("You cannot delete the last user")
        del u[name]
        jsave(USERS_PATH, u)
        for k in [k for k, s in SESSIONS.items() if s["user"] == name]:
            SESSIONS.pop(k, None)
    audit(user, "user-delete", name)
    return {"ok": True}


def api_password(h, q, b, user):
    rec = users().get(user)
    if not rec or not check_pw(rec, b.get("current", "")):
        raise ApiError("Current password is wrong", 403)
    validate_new_password(b.get("password"))
    with AUTH_LOCK:
        u = users()
        u[user] = hash_pw(b["password"])
        jsave(USERS_PATH, u)
    audit(user, "password-change", user)
    return {"ok": True}


def api_audit(h, q, b, user):
    lines = read_text(os.path.join(DATA, "audit.log")).splitlines()[-200:]
    return {"entries": [json.loads(l) for l in reversed(lines) if l.strip()]}


ROUTES = {
    ("GET", "/api/session"): (api_session, False),
    ("POST", "/api/setup"): (api_setup, False),
    ("POST", "/api/login"): (api_login, False),
    ("POST", "/api/logout"): (api_logout, False),
    ("GET", "/api/overview"): (api_overview, True),
    ("GET", "/api/files"): (api_files, True),
    ("GET", "/api/file"): (api_file_get, True),
    ("POST", "/api/file/save"): (api_file_save, True),
    ("POST", "/api/file/create"): (api_file_create, True),
    ("POST", "/api/file/enable"): (api_file_enable, True),
    ("POST", "/api/file/delete"): (api_file_delete, True),
    ("GET", "/api/history"): (api_history, True),
    ("GET", "/api/history/version"): (api_history_get, True),
    ("POST", "/api/history/rollback"): (api_history_rollback, True),
    ("GET", "/api/deleted"): (api_deleted, True),
    ("POST", "/api/nginx/test"): (api_nginx_test, True),
    ("POST", "/api/nginx/reload"): (api_nginx_reload, True),
    ("POST", "/api/nginx/start"): (api_nginx_start, True),
    ("POST", "/api/wizard/preview"): (api_wizard_preview, True),
    ("POST", "/api/wizard/apply"): (api_wizard_apply, True),
    ("GET", "/api/certs"): (api_certs, True),
    ("GET", "/api/flow"): (api_flow, True),
    ("GET", "/api/stats"): (api_stats, True),
    ("POST", "/api/live/enable"): (api_live_enable, True),
    ("GET", "/api/logs"): (api_logs, True),
    ("GET", "/api/logs/tail"): (api_log_tail, True),
    ("GET", "/api/updates"): (api_updates, True),
    ("POST", "/api/updates/check"): (api_updates_check, True),
    ("POST", "/api/updates/apply"): (api_updates_apply, True),
    ("POST", "/api/updates/auto"): (api_updates_auto, True),
    ("GET", "/api/job"): (api_job, True),
    ("POST", "/api/system/reboot"): (api_reboot, True),
    ("GET", "/api/backups"): (api_backups, True),
    ("POST", "/api/backups/create"): (api_backup_create, True),
    ("POST", "/api/backups/restore"): (api_backup_restore, True),
    ("POST", "/api/backups/delete"): (api_backup_delete, True),
    ("GET", "/api/users"): (api_users, True),
    ("POST", "/api/users/add"): (api_user_add, True),
    ("POST", "/api/users/delete"): (api_user_delete, True),
    ("POST", "/api/password"): (api_password, True),
    ("GET", "/api/audit"): (api_audit, True),
}

STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml")}

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "LiveProxy"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("LIVEPROXY_DEBUG"):
            sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

    def _send(self, status, body, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, extra=None):
        self._send(status, json.dumps(obj).encode(), "application/json", extra)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        u = urlparse(self.path)
        path = u.path
        if method == "GET" and path in STATIC:
            fn, ctype = STATIC[path]
            try:
                with open(os.path.join(STATIC_DIR, fn), "rb") as f:
                    return self._send(200, f.read(), ctype)
            except OSError:
                return self._send(404, b"not found", "text/plain")
        if method == "GET" and path == "/api/backups/download":
            return self._download(u)
        route = ROUTES.get((method, path))
        if not route:
            return self._json(404, {"error": "Not found"})
        fn, needs_auth = route
        user = session_user(self)
        if needs_auth and not user:
            return self._json(401, {"error": "Please log in"})
        body = {}
        if method == "POST":
            if self.headers.get("X-LiveProxy") != "1":
                return self._json(403, {"error": "Missing request header"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                return self._json(413, {"error": "Request too large"})
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(400, {"error": "Bad JSON"})
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            res = fn(self, q, body, user)
            extra = {}
            if isinstance(res, dict) and "_cookie" in res:
                tok = res.pop("_cookie")
                secure = "; Secure" if getattr(self.server, "is_tls", False) else ""
                if tok:
                    extra["Set-Cookie"] = (f"lp_session={tok}; HttpOnly; SameSite=Strict; Path=/"
                                           f"; Max-Age={CFG['session_hours'] * 3600}{secure}")
                else:
                    extra["Set-Cookie"] = f"lp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"
            self._json(200, res, extra)
        except ApiError as e:
            self._json(e.status, {"error": str(e), **e.extra})
        except Exception as e:  # pragma: no cover
            traceback.print_exc()
            self._json(500, {"error": f"Internal error: {e}"})

    def _download(self, u):
        if not session_user(self):
            return self._json(401, {"error": "Please log in"})
        n = parse_qs(u.query).get("name", [""])[0]
        if not BK_RE.match(n):
            return self._json(400, {"error": "Bad name"})
        p = os.path.join(DATA, "backups", n)
        if not os.path.isfile(p):
            return self._json(404, {"error": "Not found"})
        with open(p, "rb") as f:
            data = f.read()
        self._send(200, data, "application/gzip", {"Content-Disposition": f'attachment; filename="{n}"'})


def main():
    srv = ThreadingHTTPServer((CFG["bind"], int(CFG["port"])), Handler)
    srv.daemon_threads = True
    srv.is_tls = False
    if CFG.get("tls_cert") and CFG.get("tls_key") and os.path.exists(CFG["tls_cert"]) and os.path.exists(CFG["tls_key"]):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CFG["tls_cert"], CFG["tls_key"])
        # handshake happens in the per-connection thread, so a slow client can't block the server
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        srv.is_tls = True
    scheme = "https" if srv.is_tls else "http"
    print(f"LiveProxy {VERSION} listening on {scheme}://{CFG['bind']}:{CFG['port']}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

"""Built-in MCP server so Claude can troubleshoot and optimize this nginx.

- Endpoint: POST /mcp (MCP Streamable HTTP, JSON responses, stateless)
- Auth: Bearer tokens. Tokens come from
    * the NginxUI "Claude" page (for Claude Code), or
    * OAuth 2.1 + PKCE (for the Claude apps' custom connectors). Each connection is approved on a
      NginxUI page with username + password + authenticator code, with an access level and a time limit.
- Access levels: "read" (look only) and "change" (look + edit nginx config).
- Every change made by Claude goes live (after nginx -t) and is listed for review: keep or revert.
Standard library only.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import struct
import threading
import time
from urllib.parse import parse_qs, urlencode, urlparse

SRV = None  # the server module, set by init()
ATTEMPTS = []  # recent connection attempts (memory only) so the owner can see what reached NginxUI
LOCK = threading.RLock()
CODES = {}  # OAuth authorization codes (memory only, 10 min)
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
LEVELS = {"read": "Look only", "change": "Look and change config"}
DURATIONS = {1: "1 hour", 8: "8 hours", 24: "1 day", 168: "7 days", 720: "30 days"}


def init(server_module):
    global SRV
    SRV = server_module


def _path():
    return os.path.join(SRV.DATA, "mcp.json")


def state():
    st = SRV.jload(_path(), {})
    st.setdefault("enabled", False)
    st.setdefault("public_url", "")
    st.setdefault("totp_secret", None)
    st.setdefault("totp_confirmed", False)
    st.setdefault("totp_last", 0)
    st.setdefault("clients", {})
    st.setdefault("grants", {})
    st.setdefault("reviews", [])
    return st


def save(st):
    SRV.jsave(_path(), st)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------- TOTP (RFC 6238)

def totp_new():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_check(st, code, consume=True):
    """Accept the current code or one step either side; never accept the same step twice."""
    code = re.sub(r"\s", "", code or "")
    if not st.get("totp_secret") or not re.match(r"^\d{6}$", code):
        return False
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if hmac.compare_digest(_totp_at(st["totp_secret"], c), code) and c > st.get("totp_last", 0):
            if consume:
                st["totp_last"] = c
            return True
    return False


def totp_uri(secret, host):
    label = f"NginxUI ({host})"
    return f"otpauth://totp/{urlencode({'': label})[1:]}?" + urlencode({"secret": secret, "issuer": "NginxUI"})


# ---------------------------------------------------------------- URLs

def base_url(h):
    st = state()
    if st.get("public_url"):
        return st["public_url"].rstrip("/")
    proto = h.headers.get("X-Forwarded-Proto") or ("https" if getattr(h.server, "is_tls", False) else "http")
    host = h.headers.get("X-Forwarded-Host") or h.headers.get("Host") or f"localhost:{SRV.CFG['port']}"
    return f"{proto}://{host}"


# ---------------------------------------------------------------- grants

def new_grant(name, level, hours, via):
    tok = "nui_" + secrets.token_urlsafe(32)
    gid = secrets.token_hex(6)
    with LOCK:
        st = state()
        st["grants"][gid] = {"token_sha": sha(tok), "name": name[:60] or "Claude", "level": level,
                             "created": SRV.now_iso(), "expires": int(time.time() + hours * 3600),
                             "last_used": None, "via": via}
        save(st)
    SRV.audit("owner", "claude-connect", f"{name} ({LEVELS[level]}, {DURATIONS.get(hours, f'{hours}h')})")
    return tok, gid


def log_attempt(ip, result, detail="", who=""):
    """result: ok | tls | no_token | bad_token | expired | off | bad_request"""
    now = time.time()
    with LOCK:
        last = ATTEMPTS[0] if ATTEMPTS else None
        if last and last["ip"] == ip and last["result"] == result and last["who"] == who and now - last["ts"] < 600:
            last["count"] += 1
            last["ts"] = now
            last["t"] = SRV.now_iso()
            return
        ATTEMPTS.insert(0, {"t": SRV.now_iso(), "ts": now, "ip": ip, "result": result, "detail": detail[:200],
                            "who": who, "count": 1})
        del ATTEMPTS[40:]


def token_problem(token):
    """Why a token was refused: 'no_token', 'expired' or 'bad_token'."""
    if not token:
        return "no_token"
    s = sha(token)
    for g in state()["grants"].values():
        if hmac.compare_digest(g["token_sha"], s):
            return "expired"
    return "bad_token"


def grant_for(token):
    if not token:
        return None, None
    s = sha(token)
    with LOCK:
        st = state()
        now = time.time()
        expired = [k for k, g in st["grants"].items() if g["expires"] < now - 86400 * 7]
        for k in expired:
            del st["grants"][k]
        for gid, g in st["grants"].items():
            if hmac.compare_digest(g["token_sha"], s) and g["expires"] > now:
                if not g["last_used"] or now - g.get("_lu", 0) > 60:
                    g["last_used"] = SRV.now_iso()
                    g["_lu"] = now
                    save(st)
                return gid, g
        if expired:
            save(st)
    return None, None


# ---------------------------------------------------------------- change review

def record_review(grant, tool, fid, name, before, before_enabled, note):
    with LOCK:
        st = state()
        st["reviews"].insert(0, {"id": secrets.token_hex(6), "t": SRV.now_iso(), "who": grant["name"], "tool": tool,
                                 "fid": fid, "name": name, "before": before, "before_enabled": before_enabled,
                                 "note": note[:200], "status": "pending"})
        done = [r for r in st["reviews"] if r["status"] != "pending"]
        if len(done) > 60:
            keep_ids = {r["id"] for r in done[:60]}
            st["reviews"] = [r for r in st["reviews"] if r["status"] == "pending" or r["id"] in keep_ids]
        save(st)


def _enabled_state(fid):
    for f in SRV.list_files():
        if f["id"] == fid:
            return f["enabled"]
    return None


def revert_review(rid, user):
    with LOCK:
        st = state()
        r = next((x for x in st["reviews"] if x["id"] == rid), None)
        if not r or r["status"] != "pending":
            raise SRV.ApiError("That change is not waiting for review")
        g, name, p = SRV.file_path(r["fid"])
        ops = []
        if r["before"] is None:
            if g == "sites":
                link = os.path.join(SRV.CFG["sites_enabled"], name)
                if os.path.lexists(link):
                    ops.append(("delete", link))
            ops.append(("delete", p))
        else:
            ops.append(("write", p, r["before"]))
            if g == "sites":
                link = os.path.join(SRV.CFG["sites_enabled"], name)
                if r["before_enabled"] and not os.path.lexists(link):
                    ops.append(("link", p, link))
                elif r["before_enabled"] is False and os.path.lexists(link):
                    ops.append(("delete", link))
        hist = [(r["fid"], r["before"], "revert")] if r["before"] is not None else []
        res = SRV.safe_apply(ops, user, f"Reverted Claude's change to {name}", hist)
        r["status"] = "reverted"
        r["decided"] = SRV.now_iso()
        save(st)
        return res


def keep_review(rid, user):
    with LOCK:
        st = state()
        for r in st["reviews"]:
            if r["status"] == "pending" and (rid == "all" or r["id"] == rid):
                r["status"] = "kept"
                r["decided"] = SRV.now_iso()
        save(st)
    SRV.audit(user, "claude-keep", rid)
    return {"ok": True}


# ---------------------------------------------------------------- tools

def _s(desc, props=None, req=None):
    return {"type": "object", "properties": props or {}, "required": req or [], "additionalProperties": False}


ID = {"type": "string", "description": "Config id from list_configs, e.g. 'sites:app.example.com', 'conf:x.conf', 'main:nginx.conf'"}
WIZ_PARAMS = {"type": "object", "description": (
    "Wizard answers. Common: domains (space separated), ssl ('none'|'existing'), ssl_cert, ssl_key, force_https, "
    "http2, hsts, allow_ips (list/space separated CIDRs), basic_auth_users [{user,password}], max_body_mb. "
    "proxy: upstream 'host:port', upstream_https, websocket, timeout, buffering_off. "
    "loadbalance: upstreams (list of host:port), method round_robin|least_conn|ip_hash, max_fails, fail_timeout, websocket. "
    "static: root, spa, cache_assets. redirect: target URL, code 301|302|307|308, keep_path.")}

TOOLS = [
    ("get_overview", "read", "Start here. nginx status and version, config test result, sites, server load/memory/disk, "
     "waiting updates, traffic and errors in the last hour, and the nginx config layout.", _s("")),
    ("list_configs", "read", "List every nginx config file NginxUI manages, with id, folder and enabled state.", _s("")),
    ("read_config", "read", "Read one config file.", _s("", {"id": ID}, ["id"])),
    ("get_full_config", "read", "The complete effective config as nginx sees it (nginx -T), all includes expanded.", _s("")),
    ("test_config", "read", "Run nginx -t on the live config and return the output.", _s("")),
    ("get_traffic_flow", "read", "Parsed map of ports -> server blocks -> routes -> backends, with a live TCP health check of "
     "every backend and requests per site in the last 5 minutes.", _s("")),
    ("check_backend", "read", "Open a TCP connection to host:port from this server and report if it answers and how fast.",
     _s("", {"address": {"type": "string", "description": "host:port"}}, ["address"])),
    ("get_stats", "read", "Access-log statistics: requests over time, status codes, top IPs/paths/user agents.",
     _s("", {"minutes": {"type": "integer", "description": "Window, 1-1440 (default 60)"},
             "log": {"type": "string", "description": "One access log file name from list_logs (default: all)"}})),
    ("list_logs", "read", "List the files in the nginx log folder.", _s("")),
    ("read_log", "read", "Last lines of an nginx log, optionally filtered by a text match.",
     _s("", {"file": {"type": "string"}, "lines": {"type": "integer", "description": "10-2000, default 200"},
             "filter": {"type": "string"}}, ["file"])),
    ("run_security_scan", "read", "Run the NginxUI security scan (nginx, TLS, certificates, Ubuntu, exposed services, "
     "recent attack traffic) and return all findings.", _s("")),
    ("list_certificates", "read", "Let's Encrypt certificates on this server and their expiry.", _s("")),
    ("get_config_history", "read", "Saved versions of a config file.", _s("", {"id": ID}, ["id"])),
    ("read_config_version", "read", "Content of one saved version.",
     _s("", {"id": ID, "version": {"type": "string"}}, ["id", "version"])),
    ("preview_wizard", "read", "Generate (but do not apply) a config with a NginxUI wizard: proxy, loadbalance, static, redirect.",
     _s("", {"type": {"type": "string", "enum": ["proxy", "loadbalance", "static", "redirect"]},
             "name": {"type": "string", "description": "Site/file name"}, "params": WIZ_PARAMS}, ["type", "name", "params"])),
    ("save_config", "change", "Replace the full content of a config file. Runs nginx -t first; if it fails nothing changes. "
     "If it passes, nginx reloads and the owner is asked to keep or revert the change.",
     _s("", {"id": ID, "content": {"type": "string", "description": "Complete new file content"},
             "note": {"type": "string", "description": "Short reason, shown to the owner"}}, ["id", "content", "note"])),
    ("create_config", "change", "Create a new config file in sites (sites-available), conf (conf.d) or snippets.",
     _s("", {"group": {"type": "string", "enum": ["sites", "conf", "snippets"]}, "name": {"type": "string"},
             "content": {"type": "string"}, "enable": {"type": "boolean"},
             "note": {"type": "string"}}, ["group", "name", "content", "note"])),
    ("set_config_enabled", "change", "Enable or disable a site (sites) or conf.d file.",
     _s("", {"id": ID, "enabled": {"type": "boolean"}, "note": {"type": "string"}}, ["id", "enabled", "note"])),
    ("restore_config_version", "change", "Put a saved version of a file back (tested first).",
     _s("", {"id": ID, "version": {"type": "string"}, "note": {"type": "string"}}, ["id", "version", "note"])),
    ("apply_wizard", "change", "Create or replace a site with a NginxUI wizard (tested first, then enabled).",
     _s("", {"type": {"type": "string", "enum": ["proxy", "loadbalance", "static", "redirect"]},
             "name": {"type": "string"}, "params": WIZ_PARAMS, "overwrite": {"type": "boolean"},
             "note": {"type": "string"}}, ["type", "name", "params", "note"])),
    ("reload_nginx", "change", "Test and reload nginx without changing files.", _s("")),
]

INSTRUCTIONS = (
    "You are connected to NginxUI, the control panel for an nginx reverse proxy on Ubuntu. "
    "Start with get_overview. To troubleshoot, combine get_traffic_flow (backend health), read_log on error.log "
    "and the site's own logs, and get_stats. Read a file with read_config before changing it, and change only what "
    "is needed: save_config replaces the whole file, so send the complete content and keep the owner's comments. "
    "Every change is tested with nginx -t and rolled back automatically if it fails; changes that pass go live and "
    "the owner keeps or reverts them in NginxUI, so explain each change in the note. Never weaken security "
    "(do not remove allow/deny rules, auth_basic, or HTTPS redirects) unless the owner asked. "
    "You cannot delete files, install updates or reboot; ask the owner to do that in NginxUI.")


def _dump(obj, limit=120_000):
    t = json.dumps(obj, indent=1, default=str)
    return t if len(t) <= limit else t[:limit] + "\n… (truncated)"


def call_tool(name, args, gid, grant):
    spec = next((t for t in TOOLS if t[0] == name), None)
    if not spec:
        raise SRV.ApiError(f"Unknown tool {name}")
    if spec[1] == "change" and grant["level"] != "change":
        raise SRV.ApiError("This connection is look-only. The owner can approve a new connection with change access.")
    a = args or {}
    who = f"claude:{grant['name']}"
    q = {}
    if name == "get_overview":
        o = SRV.api_overview(None, {}, {}, who)
        o["layout"] = {k: SRV.CFG[k] for k in ("nginx_dir", "sites_available", "sites_enabled", "conf_d", "log_dir")}
        o["traffic"] = {k: o["traffic"][k] for k in ("minutes", "total", "rpm", "classes", "statuses", "top_paths")}
        o.pop("activity", None)
        return _dump(o)
    if name == "list_configs":
        return _dump(SRV.list_files())
    if name == "read_config":
        r = SRV.api_file_get(None, {"id": a.get("id", "")}, {}, who)
        return f"# {r['id']}\n{r['content']}"
    if name == "get_full_config":
        rc, out = SRV.run([SRV.CFG["nginx_bin"], "-T"], timeout=30)
        return out[:200_000]
    if name == "test_config":
        ok, out = SRV.nginx_test()
        return ("PASSED\n" if ok else "FAILED\n") + out
    if name == "get_traffic_flow":
        return _dump(SRV.build_flow())
    if name == "check_backend":
        addr = str(a.get("address", ""))
        if not re.match(r"^[A-Za-z0-9.\-\[\]:]+:\d{1,5}$", addr):
            raise SRV.ApiError("address must be host:port")
        return _dump(SRV.tcp_check(addr))
    if name == "get_stats":
        q = {"minutes": str(a.get("minutes") or 60), "log": a.get("log") or ""}
        s = SRV.api_stats(None, q, {}, who)
        s["timeline"] = [t for t in s["timeline"] if t["total"]]
        return _dump(s)
    if name == "list_logs":
        return _dump(SRV.api_logs(None, {}, {}, who))
    if name == "read_log":
        r = SRV.api_log_tail(None, {"file": a.get("file", ""), "lines": str(a.get("lines") or 200),
                                     "q": a.get("filter") or ""}, {}, who)
        return "\n".join(r["lines"]) or "(no matching lines)"
    if name == "run_security_scan":
        r = SRV.security_scan()
        return _dump({"findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in r["findings"]],
                      "passed": r["passed"]})
    if name == "list_certificates":
        return _dump(SRV.list_certs())
    if name == "get_config_history":
        return _dump(SRV.api_history(None, {"id": a.get("id", "")}, {}, who))
    if name == "read_config_version":
        r = SRV.api_history_get(None, {"id": a.get("id", ""), "v": a.get("version", "")}, {}, who)
        return r["content"]
    if name == "preview_wizard":
        return SRV.api_wizard_preview(None, {}, {"type": a.get("type"), "name": a.get("name"),
                                                 "params": a.get("params") or {}}, who)["content"]
    # ---- change tools
    note = (a.get("note") or "").strip() or "No reason given"
    if name == "reload_nginx":
        return _dump(SRV.api_nginx_reload(None, {}, {}, who))
    if name in ("save_config", "restore_config_version", "set_config_enabled"):
        fid = a.get("id", "")
        g, fname, p = SRV.file_path(fid)
        before = SRV.read_text(p) if os.path.isfile(p) else None
        before_en = _enabled_state(fid)
        if name == "save_config":
            content = a.get("content")
            if not isinstance(content, str):
                raise SRV.ApiError("content is required")
            if content == before:
                return "No change: the content is identical to the live file."
            res = SRV.api_file_save(None, {}, {"id": fid, "content": content, "note": f"Claude: {note}"}, who)
        elif name == "restore_config_version":
            res = SRV.api_history_rollback(None, {}, {"id": fid, "v": str(a.get("version", ""))}, who)
        else:
            res = SRV.api_file_enable(None, {}, {"id": fid, "enabled": bool(a.get("enabled"))}, who)
            fid = res.get("id", fid)
            if g == "conf":  # renamed file: review against the new name
                _, fname, p = SRV.file_path(fid)
        record_review(grant, name, fid, fname, before, before_en, note)
        return _dump({**res, "review": "Live now. The owner will keep or revert this change in NginxUI."})
    if name == "create_config":
        res = SRV.api_file_create(None, {}, {"group": a.get("group"), "name": a.get("name", ""),
                                             "content": a.get("content", ""), "enable": a.get("enable", True)}, who)
        _, fname, _ = SRV.file_path(res["id"])
        record_review(grant, name, res["id"], fname, None, None, note)
        return _dump({**res, "review": "Live now. The owner will keep or revert this change in NginxUI."})
    if name == "apply_wizard":
        fid = f"sites:{a.get('name', '')}"
        g, fname, p = SRV.file_path(fid)
        before = SRV.read_text(p) if os.path.isfile(p) else None
        before_en = _enabled_state(fid)
        res = SRV.api_wizard_apply(None, {}, {"type": a.get("type"), "name": a.get("name"), "params": a.get("params") or {},
                                              "overwrite": bool(a.get("overwrite")), "enable": True}, who)
        record_review(grant, name, fid, fname, before, before_en, note)
        return _dump({**res, "review": "Live now. The owner will keep or revert this change in NginxUI."})
    raise SRV.ApiError("Unhandled tool")


# ---------------------------------------------------------------- HTTP: MCP endpoint

def _unauth(h, msg="Authorization required"):
    meta = base_url(h) + "/.well-known/oauth-protected-resource"
    h._json(401, {"error": "invalid_token", "error_description": msg},
            {"WWW-Authenticate": f'Bearer realm="NginxUI", resource_metadata="{meta}"'})


def handle_mcp(h, method, u):
    st = state()
    ip = SRV.client_ip(h)
    if not st["enabled"]:
        log_attempt(ip, "off")
        return h._json(404, {"error": "Claude access (MCP) is turned off in NginxUI"})
    if method != "POST":
        return h._send(405, b"", "text/plain", {"Allow": "POST"})
    auth = h.headers.get("Authorization", "")
    tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    gid, grant = grant_for(tok)
    if not grant:
        why = token_problem(tok)
        log_attempt(ip, why, auth[:7] + "…" if auth else "no Authorization header")
        return _unauth(h, {"no_token": "No key was sent", "expired": "This key has expired",
                           "bad_token": "Unknown key (revoked, or copied wrong)"}[why])
    log_attempt(ip, "ok", "", grant["name"])
    n = int(h.headers.get("Content-Length") or 0)
    if n > 4_000_000:
        return h._json(413, {"error": "too large"})
    try:
        msg = json.loads(h.rfile.read(n) or b"null")
    except ValueError:
        return h._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
    msgs = msg if isinstance(msg, list) else [msg]
    out = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        r = _rpc(m, gid, grant)
        if r is not None:
            out.append(r)
    if not out:
        return h._send(202, b"", "text/plain")
    body = out if isinstance(msg, list) else out[0]
    h._json(200, body)


def _rpc(m, gid, grant):
    mid, meth, params = m.get("id"), m.get("method"), m.get("params") or {}
    if mid is None:  # notification
        return None

    def ok(res):
        return {"jsonrpc": "2.0", "id": mid, "result": res}

    if meth == "initialize":
        pv = params.get("protocolVersion")
        return ok({"protocolVersion": pv if pv in PROTOCOLS else PROTOCOLS[0],
                   "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "NginxUI", "title": f"NginxUI ({SRV.socket.gethostname()})", "version": SRV.VERSION},
                   "instructions": INSTRUCTIONS})
    if meth == "ping":
        return ok({})
    if meth == "tools/list":
        tools = []
        for name, lvl, desc, schema in TOOLS:
            if lvl == "change" and grant["level"] != "change":
                continue
            tools.append({"name": name, "description": desc, "inputSchema": schema,
                          "annotations": {"readOnlyHint": lvl == "read", "destructiveHint": False,
                                          "idempotentHint": lvl == "read"}})
        return ok({"tools": tools})
    if meth == "tools/call":
        name = params.get("name")
        try:
            text = call_tool(name, params.get("arguments") or {}, gid, grant)
            SRV.audit(f"claude:{grant['name']}", f"mcp:{name}", "", True)
            return ok({"content": [{"type": "text", "text": text}], "isError": False})
        except SRV.ApiError as e:
            extra = e.extra.get("test_output")
            SRV.audit(f"claude:{grant['name']}", f"mcp:{name}", "", False, str(e))
            return ok({"content": [{"type": "text", "text": str(e) + (f"\n\nnginx said:\n{extra}" if extra else "")}],
                       "isError": True})
        except Exception as e:
            return ok({"content": [{"type": "text", "text": f"Internal error: {e}"}], "isError": True})
    if meth in ("resources/list", "prompts/list"):
        return ok({meth.split("/")[0]: []})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {meth}"}}


# ---------------------------------------------------------------- HTTP: OAuth 2.1 for Claude app connectors

def handle_wellknown(h, method, u):
    if not state()["enabled"]:
        return h._json(404, {"error": "not enabled"})
    b = base_url(h)
    if u.path.startswith("/.well-known/oauth-protected-resource"):
        return h._json(200, {"resource": b + "/mcp", "authorization_servers": [b],
                             "bearer_methods_supported": ["header"], "resource_name": "NginxUI"})
    return h._json(200, {
        "issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
        "registration_endpoint": b + "/oauth/register", "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"], "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"], "scopes_supported": list(LEVELS)})


def _read_body(h):
    n = int(h.headers.get("Content-Length") or 0)
    raw = h.rfile.read(min(n, 100_000)) if n else b""
    ct = h.headers.get("Content-Type", "")
    if "json" in ct:
        try:
            d = json.loads(raw or b"{}")
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}


def _redirect_ok(uri):
    p = urlparse(uri or "")
    return p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1"))


def handle_register(h, method, u):
    st = state()
    if not st["enabled"] or method != "POST":
        return h._json(404, {"error": "not enabled"})
    b = _read_body(h)
    uris = b.get("redirect_uris") or []
    if not isinstance(uris, list) or not uris or not all(isinstance(x, str) and _redirect_ok(x) for x in uris):
        return h._json(400, {"error": "invalid_redirect_uri"})
    cid = "nuic_" + secrets.token_urlsafe(16)
    with LOCK:
        st = state()
        if len(st["clients"]) > 200:  # drop the oldest registrations
            for k in sorted(st["clients"], key=lambda k: st["clients"][k]["created"])[:50]:
                del st["clients"][k]
        st["clients"][cid] = {"name": str(b.get("client_name") or "Claude")[:60], "redirect_uris": uris[:10],
                              "created": SRV.now_iso()}
        save(st)
    return h._json(201, {"client_id": cid, "client_name": st["clients"][cid]["name"], "redirect_uris": uris[:10],
                         "grant_types": ["authorization_code"], "response_types": ["code"],
                         "token_endpoint_auth_method": "none"})


AUTH_CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'")


def _auth_page(h, q, client, error=""):
    e = html.escape
    hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k, v in q.items()
                     if k in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"))
    st = state()
    no_totp = not st.get("totp_confirmed")
    lvl = "read" if (q.get("scope") or "") == "read" else "change"
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve Claude · NginxUI</title><link rel="stylesheet" href="/app.css"></head><body>
<div class="login"><form class="card" method="post" action="/oauth/authorize" style="width:min(440px,100%)">
<div class="brand"><div class="logo">NU</div><div><b>Connect Claude</b><span>{e(SRV.socket.gethostname())}</span></div></div>
<p><b>{e(client['name'])}</b> wants to connect to NginxUI on this server.</p>
{f'<div class="banner bad">{e(error)}</div>' if error else ''}
{'<div class="banner warn">Set up the authenticator app on the Claude page in NginxUI first.</div>' if no_totp else ''}
{hidden}
<label class="f"><span>NginxUI username</span><input type="text" name="username" autocomplete="username" required></label>
<label class="f"><span>Password</span><input type="password" name="password" autocomplete="current-password" required></label>
<label class="f"><span>6-digit code from your authenticator app</span><input type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{{6,7}}" required></label>
<label class="f"><span>What Claude may do</span><select name="level">
<option value="read" {'selected' if lvl == 'read' else ''}>Look only (read configs, logs, stats, run checks)</option>
<option value="change" {'selected' if lvl == 'change' else ''}>Look and change config (you review every change)</option></select></label>
<label class="f"><span>For how long</span><select name="hours">{''.join(f'<option value="{k}" {"selected" if k == 8 else ""}>{v}</option>' for k, v in DURATIONS.items())}</select></label>
<label class="f"><span>Name this connection</span><input type="text" name="name" value="{e(client['name'])}" maxlength="60"></label>
<div class="row between"><button class="btn" name="decision" value="deny">Deny</button><button class="btn primary" name="decision" value="approve" {'disabled' if no_totp else ''}>Approve</button></div>
<p class="small muted" style="margin-top:12px">Claude can't delete files, install updates or restart the server. Every change it makes is tested first and listed in NginxUI for you to keep or revert.</p>
</form></div></body></html>"""
    h._send(200, page.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": AUTH_CSP})


def handle_authorize(h, method, u):
    st = state()
    if not st["enabled"]:
        return h._send(404, b"Claude access is turned off in NginxUI.", "text/plain")
    q = {k: v[0] for k, v in parse_qs(u.query).items()} if method == "GET" else _read_body(h)
    client = st["clients"].get(q.get("client_id", ""))
    ru = q.get("redirect_uri", "")
    if not client or ru not in client["redirect_uris"]:
        return h._send(400, b"Unknown client or redirect address.", "text/plain")
    if q.get("code_challenge_method") != "S256" or not re.match(r"^[A-Za-z0-9_-]{43,128}$", q.get("code_challenge", "")):
        return h._send(400, b"PKCE (S256) is required.", "text/plain")
    sep = "&" if "?" in ru else "?"
    if method == "GET":
        return _auth_page(h, q, client)
    if q.get("decision") != "approve":
        SRV.audit("owner", "claude-deny", client["name"])
        loc = ru + sep + urlencode({"error": "access_denied", **({"state": q["state"]} if q.get("state") else {})})
        return h._send(302, b"", "text/plain", {"Location": loc, "Content-Security-Policy": AUTH_CSP})
    ip = SRV.client_ip(h)
    with SRV.AUTH_LOCK:
        f = SRV.FAILS.get(ip, [0, 0])
        if f[1] > time.time():
            return _auth_page(h, q, client, "Too many attempts. Wait a few minutes and try again.")
    rec = SRV.users().get(q.get("username", ""))
    with LOCK:
        st = state()
        good = bool(rec) and SRV.check_pw(rec, q.get("password", "")) and st.get("totp_confirmed") \
            and totp_check(st, q.get("totp", ""))
        if good:
            save(st)
    if not good:
        with SRV.AUTH_LOCK:
            f = SRV.FAILS.get(ip, [0, 0])
            f[0] += 1
            if f[0] >= 5:
                f = [0, time.time() + 300]
            SRV.FAILS[ip] = f
        SRV.audit(q.get("username") or "?", "claude-approve-failed", ip, False)
        time.sleep(0.5)
        return _auth_page(h, q, client, "Username, password or code is wrong.")
    level = q.get("level") if q.get("level") in LEVELS else "read"
    try:
        hours = int(q.get("hours", 8))
    except ValueError:
        hours = 8
    hours = hours if hours in DURATIONS else 8
    code = secrets.token_urlsafe(32)
    CODES[code] = {"client_id": q["client_id"], "redirect_uri": ru, "challenge": q["code_challenge"],
                   "level": level, "hours": hours, "name": (q.get("name") or client["name"])[:60],
                   "exp": time.time() + 600}
    loc = ru + sep + urlencode({"code": code, **({"state": q["state"]} if q.get("state") else {})})
    h._send(302, b"", "text/plain", {"Location": loc, "Content-Security-Policy": AUTH_CSP})


def handle_token(h, method, u):
    if not state()["enabled"] or method != "POST":
        return h._json(404, {"error": "not enabled"})
    b = _read_body(h)
    if b.get("grant_type") != "authorization_code":
        return h._json(400, {"error": "unsupported_grant_type"})
    c = CODES.pop(b.get("code", ""), None)
    for k in [k for k, v in CODES.items() if v["exp"] < time.time()]:
        CODES.pop(k, None)
    if not c or c["exp"] < time.time() or c["client_id"] != b.get("client_id") or c["redirect_uri"] != b.get("redirect_uri"):
        return h._json(400, {"error": "invalid_grant"})
    ver = b.get("code_verifier", "")
    chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).decode().rstrip("=")
    if not hmac.compare_digest(chal, c["challenge"]):
        return h._json(400, {"error": "invalid_grant", "error_description": "PKCE check failed"})
    tok, gid = new_grant(c["name"], c["level"], c["hours"], "Claude app")
    return h._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": c["hours"] * 3600,
                         "scope": c["level"]})


RAW = {
    "/mcp": handle_mcp,
    "/.well-known/oauth-protected-resource": handle_wellknown,
    "/.well-known/oauth-protected-resource/mcp": handle_wellknown,
    "/.well-known/oauth-authorization-server": handle_wellknown,
    "/oauth/register": handle_register,
    "/oauth/authorize": handle_authorize,
    "/oauth/token": handle_token,
}


# ---------------------------------------------------------------- UI API (logged-in NginxUI users)

def ui_state(h, user):
    st = state()
    now = time.time()
    grants = [{"id": k, "name": g["name"], "level": LEVELS[g["level"]], "via": g["via"], "created": g["created"],
               "last_used": g["last_used"], "expires_in_h": round((g["expires"] - now) / 3600, 1)}
              for k, g in st["grants"].items() if g["expires"] > now]
    reviews = [{k: v for k, v in r.items() if k != "before"} for r in st["reviews"][:40]]
    return {"enabled": st["enabled"], "public_url": st["public_url"], "url": base_url(h) + "/mcp",
            "totp": {"set": bool(st["totp_secret"]), "confirmed": st["totp_confirmed"]},
            "grants": sorted(grants, key=lambda g: g["created"], reverse=True), "reviews": reviews,
            "pending": sum(1 for r in st["reviews"] if r["status"] == "pending"),
            "durations": DURATIONS, "levels": LEVELS, "port": SRV.CFG["port"]}

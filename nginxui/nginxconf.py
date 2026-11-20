"""nginx config parsing (for the traffic-flow map) and config generation (for wizards).

Standard library only.
"""
import re

# ---------------------------------------------------------------- parsing


class ParseError(Exception):
    pass


def tokenize(text):
    """Yield tokens: words/strings, '{', '}', ';'. Comments are dropped."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c
            i += 1
        elif c in "\"'":
            q = c
            i += 1
            buf = []
            while i < n and text[i] != q:
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                buf.append(text[i])
                i += 1
            i += 1
            yield "".join(buf)
        else:
            buf = []
            while i < n and not text[i].isspace() and text[i] not in "{};":
                # allow ${var} inside words
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    j = text.find("}", i)
                    if j == -1:
                        j = n - 1
                    buf.append(text[i:j + 1])
                    i = j + 1
                    continue
                buf.append(text[i])
                i += 1
            yield "".join(buf)


def parse(text):
    """Parse nginx config text into a list of {'name', 'args', 'block'} dicts."""
    tokens = list(tokenize(text))
    pos = 0

    def parse_block():
        nonlocal pos
        out = []
        words = []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == ";":
                if words:
                    out.append({"name": words[0], "args": words[1:], "block": None})
                words = []
            elif t == "{":
                name = words[0] if words else ""
                child = parse_block()
                out.append({"name": name, "args": words[1:], "block": child})
                words = []
            elif t == "}":
                return out
            else:
                words.append(t)
        return out

    return parse_block()


def split_nginx_T(output):
    """Split `nginx -T` output into [(filename, text)]."""
    parts = []
    cur_name, cur = None, []
    for line in output.splitlines():
        m = re.match(r"^# configuration file (.+):\s*$", line)
        if m:
            if cur_name:
                parts.append((cur_name, "\n".join(cur)))
            cur_name, cur = m.group(1), []
        elif cur_name:
            cur.append(line)
    if cur_name:
        parts.append((cur_name, "\n".join(cur)))
    return parts


def _first(block, name):
    for d in block or []:
        if d["name"] == name:
            return d
    return None


def _all(block, name):
    return [d for d in (block or []) if d["name"] == name]


def _walk(nodes, names, ctx=None):
    """Find directives named in `names` anywhere, yielding (node, context-name)."""
    for d in nodes or []:
        if d["name"] in names:
            yield d, ctx
        if d["block"] is not None:
            yield from _walk(d["block"], names, d["name"])


def _parse_target(url):
    """proxy_pass URL -> (scheme, host, port, path) ; host may be an upstream name."""
    m = re.match(r"^(https?|grpcs?|uwsgi|fastcgi)?(?:://)?([^/:]+|\[[^\]]+\])(?::(\d+))?(/.*)?$", url or "")
    if not m:
        return None
    scheme = m.group(1) or "http"
    host = m.group(2)
    port = int(m.group(3)) if m.group(3) else None
    return scheme, host, port, m.group(4) or ""


def extract(files):
    """files: [(filename, text)] -> {'servers': [...], 'upstreams': {...}, 'errors': [...]}"""
    servers, upstreams, errors = [], {}, []
    for fname, text in files:
        try:
            tree = parse(text)
        except Exception as e:  # pragma: no cover - parser is forgiving
            errors.append(f"{fname}: {e}")
            continue
        for up, _ctx in _walk(tree, {"upstream"}):
            if not up["args"] or up["block"] is None:
                continue
            members = []
            for s in _all(up["block"], "server"):
                if s["args"]:
                    flags = s["args"][1:]
                    members.append({"address": s["args"][0], "flags": flags})
            method = "round_robin"
            for m in ("least_conn", "ip_hash", "hash", "random", "least_time"):
                if _first(up["block"], m):
                    method = m
            upstreams[up["args"][0]] = {"servers": members, "method": method, "file": fname}
        for srv, ctx in _walk(tree, {"server"}):
            if srv["block"] is None or ctx in ("upstream",):
                continue
            if ctx == "stream":
                kind = "stream"
            else:
                kind = "http"
            b = srv["block"]
            listens = []
            for l in _all(b, "listen"):
                if not l["args"]:
                    continue
                addr = l["args"][0]
                port = addr.rsplit(":", 1)[-1] if ":" in addr and not addr.endswith("]") else addr
                if not port.isdigit():
                    port = "80"
                listens.append({"raw": " ".join(l["args"]), "port": int(port),
                                "ssl": "ssl" in l["args"] or "quic" in l["args"],
                                "default": "default_server" in l["args"]})
            if not listens and kind == "http":
                listens.append({"raw": "80 (implicit)", "port": 80, "ssl": False, "default": False})
            names = []
            for sn in _all(b, "server_name"):
                names += sn["args"]
            access_logs = [a["args"][0] for a in _all(b, "access_log") if a["args"]]
            routes = []

            def add_route(path, blk):
                r = {"path": path, "type": None, "target": None,
                     "auth": bool(_first(blk, "auth_basic") and _first(blk, "auth_basic")["args"]
                                  and _first(blk, "auth_basic")["args"][0] != "off"),
                     "ip_rules": bool(_first(blk, "allow") or _first(blk, "deny"))}
                pp = _first(blk, "proxy_pass") or _first(blk, "grpc_pass") or _first(blk, "uwsgi_pass") \
                    or _first(blk, "fastcgi_pass")
                ret = _first(blk, "return")
                root = _first(blk, "root") or _first(blk, "alias")
                if pp and pp["args"]:
                    r["type"] = "proxy"
                    r["target"] = pp["args"][0]
                elif ret and ret["args"]:
                    r["type"] = "return"
                    r["target"] = " ".join(ret["args"])
                elif root and root["args"]:
                    r["type"] = "static"
                    r["target"] = root["args"][0]
                elif _first(blk, "stub_status"):
                    r["type"] = "status"
                    r["target"] = "stub_status"
                routes.append(r)
                return r

            base = add_route("(server)", b)
            locs = _all(b, "location")
            for loc in locs:
                path = " ".join(loc["args"])
                r = add_route(path, loc["block"] or [])
                if r["type"] is None:
                    # inherit server-level root
                    if base["type"] == "static":
                        r["type"], r["target"] = "static", base["target"]
                for inner in _all(loc["block"], "location"):
                    add_route(path + " > " + " ".join(inner["args"]), inner["block"] or [])
            if base["type"] is None:
                routes.remove(base)
            if kind == "stream":
                pp = _first(b, "proxy_pass")
                routes = [{"path": "(stream)", "type": "proxy", "target": pp["args"][0] if pp and pp["args"] else None,
                           "auth": False, "ip_rules": False}]
            servers.append({
                "file": fname, "kind": kind, "listen": listens, "names": names or ["_"],
                "access_logs": access_logs, "routes": [r for r in routes if r["type"]],
            })
    return {"servers": servers, "upstreams": upstreams, "errors": errors}


def resolve_targets(flow):
    """Return a list of host:port backends with their referencing servers."""
    ups = flow["upstreams"]
    backends = {}
    for i, s in enumerate(flow["servers"]):
        for r in s["routes"]:
            r["backends"] = []
            if r["type"] != "proxy" or not r["target"]:
                continue
            t = _parse_target(r["target"])
            if not t:
                continue
            scheme, host, port, _path = t
            if "$" in r["target"]:
                r["dynamic"] = True
                continue
            if host in ups:
                r["upstream"] = host
                addrs = [m["address"] for m in ups[host]["servers"]]
            else:
                default = 443 if scheme in ("https", "grpcs") else 80
                if s["kind"] == "stream":
                    addrs = [r["target"]]
                else:
                    addrs = [f"{host}:{port or default}"]
            for a in addrs:
                if a.startswith("unix:"):
                    key = a
                else:
                    if ":" not in a.rsplit("]", 1)[-1]:
                        a = a + ":80"
                    key = a
                r["backends"].append(key)
                backends.setdefault(key, {"address": key, "servers": set()})["servers"].add(i)
    for b in backends.values():
        b["servers"] = sorted(b["servers"])
    return list(backends.values())


# ---------------------------------------------------------------- generation

DOMAIN_RE = re.compile(r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$|^_$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$|^\[[0-9A-Fa-f:]+\]$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
CIDR_RE = re.compile(r"^(all|[0-9A-Fa-f:.]+(/\d{1,3})?)$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]*$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class WizardError(ValueError):
    pass


def _req(p, key, label=None):
    v = p.get(key)
    if v in (None, "", []):
        raise WizardError(f"{label or key} is required")
    return v


def _domains(p):
    raw = p.get("domains") or ""
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    doms = [d.strip().lower() for d in raw if d.strip()]
    if not doms:
        raise WizardError("At least one domain name is required (use _ to match any name)")
    for d in doms:
        if not DOMAIN_RE.match(d):
            raise WizardError(f"'{d}' is not a valid domain name")
    return doms


def _hostport(s, label):
    s = (s or "").strip()
    s = re.sub(r"^https?://", "", s).rstrip("/")
    if ":" in s.rsplit("]", 1)[-1]:
        host, port = s.rsplit(":", 1)
    else:
        host, port = s, ""
    if not HOST_RE.match(host or ""):
        raise WizardError(f"{label}: '{host}' is not a valid host or IP")
    if not port.isdigit() or not (0 < int(port) < 65536):
        raise WizardError(f"{label}: a port number (1-65535) is required, e.g. 192.168.1.20:8080")
    return host, int(port)


def _path(s, label):
    s = (s or "").strip()
    if not SAFE_PATH_RE.match(s) or ".." in s:
        raise WizardError(f"{label}: '{s}' is not an allowed path")
    return s


def _cidrs(p):
    raw = p.get("allow_ips") or ""
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    out = []
    for c in raw:
        c = c.strip()
        if not c:
            continue
        if not CIDR_RE.match(c):
            raise WizardError(f"'{c}' is not a valid IP or CIDR range")
        out.append(c)
    return out


def _int(p, key, default, lo, hi, label):
    v = p.get(key, default)
    if v in (None, ""):
        v = default
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise WizardError(f"{label} must be a number")
    if not lo <= v <= hi:
        raise WizardError(f"{label} must be between {lo} and {hi}")
    return v


def _ssl(p):
    mode = p.get("ssl", "none")
    if mode == "none":
        return None
    if mode != "existing":
        raise WizardError("Unknown SSL mode")
    cert = _path(_req(p, "ssl_cert", "Certificate file"), "Certificate file")
    key = _path(_req(p, "ssl_key", "Key file"), "Key file")
    return {"cert": cert, "key": key, "force": bool(p.get("force_https", True)),
            "hsts": bool(p.get("hsts", False)), "http2": bool(p.get("http2", True))}


def _access_block(p, name, indent="        "):
    lines = []
    cidrs = _cidrs(p)
    if cidrs:
        lines.append(f"{indent}# Only these addresses may connect")
        for c in cidrs:
            lines.append(f"{indent}allow {c};")
        lines.append(f"{indent}deny all;")
    if p.get("basic_auth_users"):
        lines.append(f"{indent}# Password prompt")
        lines.append(f'{indent}auth_basic "Restricted";')
        lines.append(f"{indent}auth_basic_user_file {{HTPASSWD_DIR}}/{name};")
    return lines


def basic_auth_users(p):
    out = []
    for u in p.get("basic_auth_users") or []:
        user = (u.get("user") or "").strip()
        pw = u.get("password") or ""
        if not USER_RE.match(user):
            raise WizardError(f"Basic auth username '{user}' is invalid (letters, digits, . _ - only)")
        if len(pw) < 8:
            raise WizardError(f"Password for '{user}' must be at least 8 characters")
        out.append((user, pw))
    return out


def _server_wrap(name, doms, ssl, body_lines, p):
    """Wrap location/body lines into one or two server blocks with optional SSL."""
    sn = " ".join(doms)
    log = [f"    access_log /var/log/nginx/{name}.access.log;",
           f"    error_log  /var/log/nginx/{name}.error.log;"]
    out = [f"# Managed by NginxUI wizard: {p.get('_wizard', '')}",
           f"# Site: {name}", ""]
    if ssl and ssl["force"]:
        out += ["server {",
                "    listen 80;"] + (["    listen [::]:80;"] if p.get("_ipv6", True) else []) + [
                f"    server_name {sn};",
                "",
                "    # Send all plain-HTTP visitors to HTTPS",
                "    return 301 https://$host$request_uri;",
                "}", ""]
    out.append("server {")
    if ssl:
        # nginx 1.25.1+ uses "http2 on;" instead of the old "listen ... http2" flag
        new_h2 = bool(p.get("_new_http2"))
        h2 = " http2" if ssl["http2"] and not new_h2 else ""
        out += [f"    listen 443 ssl{h2};"] + ([f"    listen [::]:443 ssl{h2};"] if p.get("_ipv6", True) else [])
        if ssl["http2"] and new_h2:
            out.append("    http2 on;")
        if not ssl["force"]:
            out += ["    listen 80;"] + (["    listen [::]:80;"] if p.get("_ipv6", True) else [])
    else:
        out += ["    listen 80;"] + (["    listen [::]:80;"] if p.get("_ipv6", True) else [])
    out.append(f"    server_name {sn};")
    out.append("")
    if ssl:
        out += [f"    ssl_certificate     {ssl['cert']};",
                f"    ssl_certificate_key {ssl['key']};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    ssl_session_cache shared:SSL:10m;"]
        if ssl["hsts"]:
            out.append('    add_header Strict-Transport-Security "max-age=31536000" always;')
        out.append("")
    out += log
    mb = _int(p, "max_body_mb", 10, 0, 100000, "Max upload size")
    out.append(f"    client_max_body_size {mb}m;")
    out.append("")
    out += body_lines
    out.append("}")
    return "\n".join(out) + "\n"


def gen_proxy(p, name):
    doms = _domains(p)
    host, port = _hostport(_req(p, "upstream", "Backend address"), "Backend address")
    scheme = "https" if p.get("upstream_https") else "http"
    ssl = _ssl(p)
    timeout = _int(p, "timeout", 60, 1, 86400, "Timeout")
    body = ["    location / {"]
    body += _access_block(p, name)
    body += [f"        proxy_pass {scheme}://{host}:{port};",
             "        proxy_http_version 1.1;",
             "        proxy_set_header Host $host;",
             "        proxy_set_header X-Real-IP $remote_addr;",
             "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
             "        proxy_set_header X-Forwarded-Proto $scheme;"]
    if p.get("websocket"):
        body += ["        # WebSocket support",
                 "        proxy_set_header Upgrade $http_upgrade;",
                 '        proxy_set_header Connection "upgrade";']
    body += [f"        proxy_read_timeout {timeout}s;", f"        proxy_send_timeout {timeout}s;"]
    if p.get("buffering_off"):
        body.append("        proxy_buffering off;")
    if scheme == "https" and not p.get("verify_upstream_tls"):
        body.append("        proxy_ssl_server_name on;")
    body.append("    }")
    return _server_wrap(name, doms, ssl, body, p)


def gen_loadbalance(p, name):
    doms = _domains(p)
    raw = p.get("upstreams") or ""
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    members = [_hostport(u, "Backend") for u in raw if u.strip()]
    if len(members) < 2:
        raise WizardError("Add at least two backends for load balancing")
    method = p.get("method", "round_robin")
    if method not in ("round_robin", "least_conn", "ip_hash"):
        raise WizardError("Unknown balancing method")
    max_fails = _int(p, "max_fails", 3, 0, 100, "Max fails")
    fail_timeout = _int(p, "fail_timeout", 30, 1, 3600, "Fail timeout")
    ssl = _ssl(p)
    up = f"{re.sub(r'[^A-Za-z0-9_]', '_', name)}_pool"
    head = [f"upstream {up} {{"]
    if method != "round_robin":
        head.append(f"    {method};")
    for h, pt in members:
        head.append(f"    server {h}:{pt} max_fails={max_fails} fail_timeout={fail_timeout}s;")
    head += ["    keepalive 16;", "}", ""]
    body = ["    location / {"]
    body += _access_block(p, name)
    body += [f"        proxy_pass http://{up};",
             "        proxy_http_version 1.1;",
             "        proxy_set_header Host $host;",
             "        proxy_set_header X-Real-IP $remote_addr;",
             "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
             "        proxy_set_header X-Forwarded-Proto $scheme;"]
    if p.get("websocket"):
        body += ["        proxy_set_header Upgrade $http_upgrade;",
                 '        proxy_set_header Connection "upgrade";']
    else:
        body.append('        proxy_set_header Connection "";')
    body += ["        proxy_next_upstream error timeout http_502 http_503 http_504;", "    }"]
    text = _server_wrap(name, doms, ssl, body, p)
    lines = text.split("\n")
    # insert upstream block after header comments
    return "\n".join(lines[:3] + head + lines[3:])


def gen_static(p, name):
    doms = _domains(p)
    root = _path(_req(p, "root", "Web folder"), "Web folder")
    ssl = _ssl(p)
    body = [f"    root {root};", "    index index.html index.htm;", "", "    location / {"]
    body += _access_block(p, name)
    if p.get("spa"):
        body.append("        # Single-page app: unknown paths load index.html")
        body.append("        try_files $uri $uri/ /index.html;")
    else:
        body.append("        try_files $uri $uri/ =404;")
    body.append("    }")
    if p.get("cache_assets"):
        body += ["", "    location ~* \\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?)$ {",
                 "        expires 7d;", '        add_header Cache-Control "public";', "    }"]
    return _server_wrap(name, doms, ssl, body, p)


def gen_redirect(p, name):
    doms = _domains(p)
    target = (p.get("target") or "").strip().rstrip("/")
    if not re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/%-]*)?$", target):
        raise WizardError("Target must be a full URL like https://example.com")
    code = _int(p, "code", 301, 301, 308, "Redirect code")
    if code not in (301, 302, 307, 308):
        raise WizardError("Redirect code must be 301, 302, 307 or 308")
    ssl = _ssl(p)
    keep = "$request_uri" if p.get("keep_path", True) else ""
    body = [f"    return {code} {target}{keep};"]
    p = dict(p, max_body_mb=1)
    return _server_wrap(name, doms, ssl, body, p)


WIZARDS = {
    "proxy": gen_proxy,
    "loadbalance": gen_loadbalance,
    "static": gen_static,
    "redirect": gen_redirect,
}


def generate(kind, params, name):
    if kind not in WIZARDS:
        raise WizardError("Unknown wizard")
    if not NAME_RE.match(name or ""):
        raise WizardError("Site name may only use letters, digits, dot, dash and underscore")
    params = dict(params or {}, _wizard=kind)
    return WIZARDS[kind](params, name)


STATUS_CONF = """# Managed by NginxUI: local-only live connection stats
server {
    listen 127.0.0.1:%d;
    server_name localhost;
    access_log off;

    location = /nginx_status {
        stub_status;
        allow 127.0.0.1;
        deny all;
    }
}
"""

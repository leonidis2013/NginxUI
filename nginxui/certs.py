"""Certificates for NginxUI: find every certificate on the server, add your own (e.g. a Cloudflare Origin
certificate pasted from the Cloudflare dashboard), and restore real visitor addresses behind Cloudflare.
Standard library only (uses the openssl command).
"""
import glob
import json
import os
import re
import secrets
import shutil
import tempfile
import time
import urllib.request

SRV = None
CF_FILE = "nginxui-cloudflare-realip.conf"
# Cloudflare's published ranges (https://www.cloudflare.com/ips/), used if the live list can't be downloaded
CF_V4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
         "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
         "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CF_V6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
         "2a06:98c0::/29", "2c0f:f248::/32"]
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}$")
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----")


def init(srv):
    global SRV
    SRV = srv


def store():
    return SRV.CFG.get("cert_store") or os.path.join(SRV.CFG["nginx_dir"], "nginxui-certs")


# ---------------------------------------------------------------- reading certificates

_cache = {}


def inspect(path):
    """Facts about one certificate file (cached by path + mtime)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_mtime)
    if key in _cache:
        return _cache[key]
    rc, out = SRV.run(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-enddate",
                       "-ext", "subjectAltName", "-nameopt", "RFC2253"], 10)
    if rc != 0:
        _cache[key] = None
        return None
    subj = re.search(r"subject=(.*)", out)
    iss = re.search(r"issuer=(.*)", out)
    end = re.search(r"notAfter=(.*)", out)
    names = re.findall(r"DNS:([^,\s]+)", out)
    cn = re.search(r"CN=([^,]+)", subj.group(1)) if subj else None
    if not names and cn:
        names = [cn.group(1)]
    issuer = iss.group(1).strip() if iss else ""
    icn = re.search(r"CN=([^,]+)", issuer)
    days = None
    expires = None
    if end:
        try:
            from datetime import datetime
            exp = datetime.strptime(end.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            expires = exp.strftime("%Y-%m-%d")
            days = int((exp - datetime.utcnow()).total_seconds() // 86400)
        except ValueError:
            pass
    low = issuer.lower()
    kind = ("cloudflare" if "cloudflare origin" in low else "letsencrypt" if "let's encrypt" in low or "o=let" in low
            else "self-signed" if subj and issuer and subj.group(1).strip() == issuer else "other")
    info = {"names": names, "issuer": icn.group(1) if icn else issuer[:80], "kind": kind,
            "expires": expires, "days_left": days}
    _cache[key] = info
    return info


def _pubkey(path, is_key):
    cmd = ["openssl", "pkey", "-in", path, "-pubout"] if is_key else ["openssl", "x509", "-in", path, "-noout", "-pubkey"]
    rc, out = SRV.run(cmd, 10)
    return out.strip() if rc == 0 else None


def key_matches(cert, key):
    a, b = _pubkey(cert, False), _pubkey(key, True)
    return bool(a) and a == b


def covers(names, domain):
    d = domain.lower().rstrip(".")
    for n in names:
        n = n.lower()
        if n == d:
            return True
        if n.startswith("*.") and d.count(".") == n.count(".") and d.endswith(n[1:]):
            return True
    return False


# ---------------------------------------------------------------- finding certificates

def _guess_key(cert):
    d, base = os.path.dirname(cert), os.path.basename(cert)
    stem = re.sub(r"\.(pem|crt|cer)$", "", base)
    stem2 = re.sub(r"(fullchain|cert|chain)$", "", stem).rstrip("._-")
    for cand in (f"{stem}.key", f"{stem}-key.pem", f"{stem}.key.pem", "privkey.pem", "key.pem", "private.pem",
                 f"{stem2}.key" if stem2 else "", f"{stem2}-key.pem" if stem2 else "", f"{stem2}.pem.key" if stem2 else ""):
        if cand:
            p = os.path.join(d, cand)
            if os.path.isfile(p) and p != cert:
                return p
    for p in glob.glob(os.path.join(d, "*.key")):
        return p
    return None


def _looks_like_cert(p):
    try:
        with open(p, "rb") as f:
            return b"-----BEGIN CERTIFICATE-----" in f.read(4096)
    except OSError:
        return False


def discover():
    """Every certificate NginxUI can offer: added in NginxUI, Let's Encrypt, used in nginx configs, and
    certificate files under /etc/ssl and the nginx folder (not the system's list of trusted authorities)."""
    found = {}

    real = set()

    def add(cert, key, source, name=None):
        r = os.path.realpath(cert)
        if r in real or not os.path.isfile(cert):
            return
        real.add(r)
        info = inspect(cert)
        if not info:
            return
        found[cert] = {"cert": cert, "key": key if key and os.path.isfile(key) else None, "source": source,
                       "name": name or os.path.basename(os.path.dirname(cert)) or os.path.basename(cert), **info}

    st = store()
    if os.path.isdir(st):
        for n in sorted(os.listdir(st)):
            d = os.path.join(st, n)
            meta = SRV.jload(os.path.join(d, "meta.json"), {})
            add(os.path.join(d, "fullchain.pem"), os.path.join(d, "privkey.pem"), "nginxui", meta.get("name") or n)
    live = os.path.join(SRV.CFG["letsencrypt_dir"], "live")
    if os.path.isdir(live):
        for n in sorted(os.listdir(live)):
            add(os.path.join(live, n, "fullchain.pem"), os.path.join(live, n, "privkey.pem"), "letsencrypt", n)
    try:
        files, _ = SRV.gather_config_files()
        import nginxconf
        for fname, text in files:
            for d, _p in _walk(nginxconf.parse(text)):
                if d["name"] == "server" and d["block"]:
                    c = next((x["args"][0] for x in d["block"] if x["name"] == "ssl_certificate" and x["args"]), None)
                    k = next((x["args"][0] for x in d["block"] if x["name"] == "ssl_certificate_key" and x["args"]), None)
                    if c and "$" not in c:
                        c = c if os.path.isabs(c) else os.path.join(SRV.CFG["nginx_dir"], c)
                        k = (k if os.path.isabs(k) else os.path.join(SRV.CFG["nginx_dir"], k)) if k else None
                        add(c, k, "in use")
    except Exception:
        pass
    roots = SRV.CFG.get("cert_search_dirs") or ["/etc/ssl", SRV.CFG["nginx_dir"], "/etc/cloudflare"]
    skip = {"/etc/ssl/certs", os.path.join(SRV.CFG["letsencrypt_dir"], "archive")}
    seen = 0
    for root in roots:
        for dirpath, dirs, fnames in os.walk(root):
            dirs[:] = [x for x in dirs if os.path.join(dirpath, x) not in skip and dirpath.count(os.sep) - root.count(os.sep) < 3]
            for fn in fnames:
                if not re.search(r"\.(pem|crt|cer)$", fn) or re.search(r"(key|privkey|chain\.pem$)", fn) and "fullchain" not in fn:
                    continue
                p = os.path.join(dirpath, fn)
                seen += 1
                if seen > 300:
                    break
                if p not in found and _looks_like_cert(p):
                    add(p, _guess_key(p), "found", f"{os.path.basename(dirpath)}/{fn}")
    out = sorted(found.values(), key=lambda c: ({"nginxui": 0, "letsencrypt": 1, "in use": 2, "found": 3}[c["source"]], c["name"]))
    used = set()
    try:
        files, _ = SRV.gather_config_files()
        alltext = "\n".join(t for _, t in files)
        used = set(re.findall(r"ssl_certificate\s+([^;\s]+);", alltext))
    except Exception:
        pass
    for c in out:
        c["in_use"] = c["cert"] in used
        c["removable"] = c["source"] == "nginxui" and not c["in_use"]
        c["key_ok"] = bool(c["key"]) and key_matches(c["cert"], c["key"])
        c["id"] = c["cert"]
    return out


def _walk(nodes):
    for d in nodes or []:
        yield d, None
        if d["block"] is not None:
            yield from _walk(d["block"])


# ---------------------------------------------------------------- adding / removing

def api_list(h, q, b, user):
    return {"certs": discover(), "store": store(), "cloudflare": cf_state()}


def api_add(h, q, b, user):
    name = (b.get("name") or "").strip()
    cert_txt = b.get("cert") or ""
    key_txt = b.get("key") or ""
    if not name:
        raise SRV.ApiError("Give the certificate a name, like 'Cloudflare ulickifamily.com'")
    if len(cert_txt) > 64000 or len(key_txt) > 16000:
        raise SRV.ApiError("That's too long to be a certificate")
    certs = CERT_RE.findall(cert_txt)
    keys = KEY_RE.findall(key_txt)
    if not certs:
        if KEY_RE.search(cert_txt):
            raise SRV.ApiError("The first box has the private key in it. The certificate goes in the first box, the key in the second.")
        raise SRV.ApiError("No certificate found in the first box. It should start with -----BEGIN CERTIFICATE-----")
    if not keys:
        if CERT_RE.search(key_txt):
            raise SRV.ApiError("The second box has a certificate in it, not the private key.")
        raise SRV.ApiError("No private key found in the second box. It should start with -----BEGIN PRIVATE KEY-----")
    if "ENCRYPTED" in keys[0]:
        raise SRV.ApiError("That private key is password-protected. nginx needs the key without a password.")
    slug = re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-")[:50] or "cert"
    d = os.path.join(store(), slug)
    if os.path.exists(d):
        slug = f"{slug}-{secrets.token_hex(2)}"
        d = os.path.join(store(), slug)
    tmp = tempfile.mkdtemp(prefix="nginxui-cert-")
    try:
        cp, kp = os.path.join(tmp, "fullchain.pem"), os.path.join(tmp, "privkey.pem")
        with open(cp, "w") as f:
            f.write("\n".join(c.strip() for c in certs) + "\n")
        with open(kp, "w") as f:
            f.write(keys[0].strip() + "\n")
        os.chmod(kp, 0o600)
        info = inspect(cp)
        if not info:
            raise SRV.ApiError("openssl couldn't read that certificate. Copy it again, including the BEGIN and END lines.")
        rc, out = SRV.run(["openssl", "pkey", "-in", kp, "-noout"], 10)
        if rc != 0:
            raise SRV.ApiError("openssl couldn't read that private key. Copy it again, including the BEGIN and END lines.")
        if not key_matches(cp, kp):
            raise SRV.ApiError("The private key doesn't belong to this certificate. Make sure both came from the same "
                               "Cloudflare 'Create Certificate' step.")
        os.makedirs(store(), mode=0o700, exist_ok=True)
        os.chmod(store(), 0o700)
        shutil.copytree(tmp, d)
        os.chmod(d, 0o700)
        os.chmod(os.path.join(d, "privkey.pem"), 0o600)
        os.chmod(os.path.join(d, "fullchain.pem"), 0o644)
        SRV.jsave(os.path.join(d, "meta.json"), {"name": name[:80], "added": SRV.now_iso(), "by": user})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    SRV.audit(user, "cert-add", f"{name} ({', '.join(info['names'][:3])})")
    return {"ok": True, "cert": os.path.join(d, "fullchain.pem"), "key": os.path.join(d, "privkey.pem"), **info,
            "certs": discover(), "cloudflare": cf_state()}


def api_delete(h, q, b, user):
    p = b.get("cert") or ""
    d = os.path.dirname(p)
    if os.path.dirname(d) != store() or not SLUG_RE.match(os.path.basename(d) or ""):
        raise SRV.ApiError("Only certificates added in NginxUI can be removed here")
    c = next((x for x in discover() if x["cert"] == p), None)
    if c and c["in_use"]:
        raise SRV.ApiError("A site still uses this certificate. Switch that site to another certificate first.")
    shutil.rmtree(d, ignore_errors=True)
    SRV.audit(user, "cert-delete", p)
    return {"certs": discover(), "cloudflare": cf_state()}


# ---------------------------------------------------------------- Cloudflare: real visitor addresses

def cf_path():
    return os.path.join(SRV.CFG["conf_d"], CF_FILE)


def cf_state():
    p = cf_path()
    on = os.path.isfile(p)
    txt = SRV.read_text(p) if on else ""
    m = re.search(r"# updated (\S+ \S+)", txt)
    return {"realip": on, "updated": m.group(1) if m else None, "ranges": len(re.findall(r"set_real_ip_from", txt))}


def cf_ranges():
    out, src = [], "built-in list"
    try:
        for u in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
            with urllib.request.urlopen(u, timeout=6) as r:
                part = [l.strip() for l in r.read().decode().splitlines() if l.strip()]
            if not part or not all(re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", x) for x in part):
                raise ValueError("unexpected list")
            out += part
        src = "cloudflare.com"
    except Exception:
        out = CF_V4 + CF_V6
    return out, src


def cf_conf(ranges, src):
    lines = ["# Managed by NginxUI: show real visitor addresses for traffic that comes through Cloudflare",
             f"# updated {SRV.now_iso()} from {src}",
             "# Logs, stats, IP allow lists and fail2ban then see the visitor, not Cloudflare.", ""]
    lines += [f"set_real_ip_from {r};" for r in ranges]
    lines += ["", "real_ip_header CF-Connecting-IP;", ""]
    return "\n".join(lines)


def api_cf_realip(h, q, b, user):
    p = cf_path()
    fid = f"conf:{CF_FILE}"
    if b.get("enabled"):
        ranges, src = cf_ranges()
        txt = cf_conf(ranges, src)
        res = SRV.safe_apply([("write", p, txt)], user, f"Cloudflare real visitor addresses on ({len(ranges)} ranges from {src})",
                             [(fid, txt, "create")])
    else:
        if not os.path.isfile(p):
            return {"cloudflare": cf_state()}
        SRV.ensure_original(fid, p)
        res = SRV.safe_apply([("delete", p)], user, "Cloudflare real visitor addresses off", [(fid, SRV.read_text(p), "deleted")])
    return {**res, "cloudflare": cf_state()}


ROUTES = {
    ("GET", "/api/certs"): api_list,
    ("POST", "/api/certs/add"): api_add,
    ("POST", "/api/certs/delete"): api_delete,
    ("POST", "/api/cloudflare/realip"): api_cf_realip,
}

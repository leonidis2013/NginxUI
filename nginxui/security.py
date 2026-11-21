"""Security scan: nginx config, certificates, Ubuntu, NginxUI itself, and recent traffic.

Each finding: id, sev (high|medium|low|info), area, title, detail, why, fix, and optionally
fix_action (a server-side one-tap fix key), link ({page, id}) and commands (to copy).
Standard library only.
"""
import os
import re
import shutil
import time
from collections import Counter, defaultdict
from datetime import datetime

import nginxconf
import stats

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
PROBE_RE = re.compile(r"(/\.env|/\.git|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|/cgi-bin|/etc/passwd|\.\./|"
                      r"/vendor/phpunit|/actuator|/boaform|/HNAP1|/solr|/\.aws|/config\.json|/server-status)", re.I)
RISKY_PORTS = {
    2375: ("Docker API (no encryption)", "high"), 2376: ("Docker API", "high"),
    3306: ("MySQL / MariaDB", "medium"), 5432: ("PostgreSQL", "medium"), 6379: ("Redis", "high"),
    27017: ("MongoDB", "high"), 11211: ("Memcached", "high"), 9200: ("Elasticsearch", "high"),
    5984: ("CouchDB", "medium"), 8086: ("InfluxDB", "medium"), 1883: ("MQTT (unencrypted)", "medium"),
    5900: ("VNC remote desktop", "high"), 3389: ("Remote Desktop", "high"), 23: ("Telnet", "high"),
    21: ("FTP (unencrypted)", "medium"), 445: ("Windows file sharing (SMB)", "medium"),
}


def _walk(nodes, path=()):
    for d in nodes or []:
        yield d, path
        if d["block"] is not None:
            yield from _walk(d["block"], path + (d,))


def _args(d):
    return " ".join(d["args"])


class Scan:
    def __init__(self, ctx):
        self.c = ctx
        self.findings = []
        self.passed = []

    def add(self, fid, sev, area, title, detail, why, fix, **kw):
        f = {"id": fid, "sev": sev, "area": area, "title": title, "detail": detail, "why": why, "fix": fix}
        f.update({k: v for k, v in kw.items() if v is not None})
        self.findings.append(f)

    def ok(self, area, title):
        self.passed.append({"area": area, "title": title})

    # ------------------------------------------------------------ nginx config
    def nginx(self):
        files = self.c["files"]
        trees = []
        for fname, text in files:
            try:
                trees.append((fname, nginxconf.parse(text)))
            except Exception:
                pass
        fid = self.c["path_to_fid"]

        # server_tokens
        st = [(f, d) for f, t in trees for d, _ in _walk(t) if d["name"] == "server_tokens"]
        on = [(f, d) for f, d in st if d["args"] and d["args"][0] != "off"]
        if not st or on:
            self.add("server_tokens", "low", "nginx", "nginx shows its version number to visitors",
                     "Error pages and the Server header include the exact nginx version.",
                     "Attackers scan for version numbers to find servers with known bugs. Hiding it costs nothing.",
                     "Add server_tokens off; to the http block.",
                     fix_action="server_tokens" if not on else None,
                     link={"page": "configs", "id": fid(on[0][0])} if on and fid(on[0][0]) else None)
        else:
            self.ok("nginx", "nginx version is hidden")

        # ssl_protocols
        sp = [(f, d) for f, t in trees for d, _ in _walk(t) if d["name"] == "ssl_protocols"]
        old = [(f, d) for f, d in sp if set(d["args"]) & {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}]
        uses_tls = any(d["name"] == "listen" and ("ssl" in d["args"] or "quic" in d["args"])
                       for _, t in trees for d, _ in _walk(t))
        if old:
            files_old = sorted({f for f, _ in old})
            self.add("ssl_protocols", "high" if uses_tls else "medium", "tls", "Old, broken TLS versions are allowed",
                     f"ssl_protocols allows {', '.join(sorted(set(a for _, d in old for a in d['args']) & {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}))} "
                     f"in {', '.join(files_old)}.",
                     "TLS 1.0 and 1.1 have known weaknesses and every current browser has dropped them. "
                     "Leaving them on only helps attackers force a weaker connection.",
                     "Change the line to: ssl_protocols TLSv1.2 TLSv1.3;",
                     fix_action="ssl_protocols", link={"page": "configs", "id": fid(files_old[0])} if fid(files_old[0]) else None)
        elif not sp and uses_tls and self.c["nginx_version"] < (1, 23, 4):
            self.add("ssl_protocols", "medium", "tls", "Old TLS versions are allowed by default",
                     "No ssl_protocols line is set, and this nginx version still allows TLS 1.0 and 1.1 by default.",
                     "TLS 1.0 and 1.1 have known weaknesses and browsers no longer use them.",
                     "Add ssl_protocols TLSv1.2 TLSv1.3; to the http block.", fix_action="ssl_protocols_add")
        elif uses_tls:
            self.ok("tls", "Only modern TLS versions are allowed")

        # per-server checks
        https_names, http_servers = defaultdict(list), []
        servers = []
        hsts_global = any(d["name"] == "add_header" and d["args"] and d["args"][0].lower() == "strict-transport-security"
                          and not any(p["name"] == "server" for p in path)
                          for _, t in trees for d, path in _walk(t))
        for fname, t in trees:
            for d, path in _walk(t):
                if d["name"] != "server" or d["block"] is None or any(p["name"] in ("stream", "upstream") for p in path):
                    continue
                b = d["block"]
                listens = [x["args"] for x in b if x["name"] == "listen" and x["args"]] or [["80"]]
                names = [a for x in b if x["name"] == "server_name" for a in x["args"]] or ["_"]
                ssl = any("ssl" in l or "quic" in l for l in listens)
                local_only = all(re.match(r"^(127\.|\[::1\]|localhost|unix:)", l[0]) for l in listens)
                inner = [x for x, _ in _walk(b)]
                srv = {"file": fname, "names": names, "ssl": ssl, "local": local_only, "nodes": inner, "block": b,
                       "label": " ".join(names) if names != ["_"] else f"default site ({os.path.basename(fname)})"}
                servers.append(srv)
                if ssl:
                    for n in names:
                        https_names[n].append(srv)
                else:
                    http_servers.append(srv)

        redirect_missing, plain_auth, plain_sites, no_hsts = [], [], [], []
        for s in servers:
            if s["local"]:
                continue
            nodes = s["nodes"]
            has_auth = any(x["name"] == "auth_basic" and x["args"] and x["args"][0] != "off" for x in nodes)
            if s["ssl"]:
                hsts = hsts_global or any(x["name"] == "add_header" and x["args"] and
                                          x["args"][0].lower() == "strict-transport-security" for x in nodes)
                if not hsts and s["names"] != ["_"]:
                    no_hsts.append(s)
                continue
            redirects = any(x["name"] == "return" and x["args"] and "https://" in _args(x) for x in s["block"])
            if any(n in https_names for n in s["names"]):
                if not redirects:
                    redirect_missing.append(s)
            elif not redirects and s["names"] != ["_"]:
                if has_auth:
                    plain_auth.append(s)
                else:
                    plain_sites.append(s)

        for s in redirect_missing:
            self.add(f"redirect:{s['label']}", "medium", "tls", f"{s['label']} still works over plain HTTP",
                     "This site has HTTPS, but the HTTP version serves the site too instead of sending visitors to HTTPS.",
                     "Anyone who types the address without https:// gets an unencrypted connection, "
                     "including any logins or cookies.",
                     "Make the port-80 server for this name return 301 https://$host$request_uri; "
                     "(the reverse proxy wizard does this when 'Send HTTP visitors to HTTPS' is on).",
                     link={"page": "configs", "id": fid(s["file"])} if fid(s["file"]) else None)
        for s in plain_auth:
            self.add(f"plainauth:{s['label']}", "high", "tls", f"Passwords for {s['label']} are sent unencrypted",
                     "This site asks for a password but only runs over plain HTTP.",
                     "Basic-auth passwords travel in the clear. Anyone on the same network, or between you and "
                     "the server, can read them.",
                     "Add HTTPS to this site (run the wizard again with the same name and pick a certificate).",
                     link={"page": "configs", "id": fid(s["file"])} if fid(s["file"]) else None)
        if plain_sites:
            labels = [s["label"] for s in plain_sites]
            self.add("plainhttp", "info", "tls", f"{len(labels)} site(s) have no HTTPS",
                     ", ".join(labels[:8]) + (" …" if len(labels) > 8 else ""),
                     "Fine for sites only used inside your network. Anything reachable from the internet should use HTTPS.",
                     "If a site is public, get a certificate and re-run its wizard with HTTPS turned on. "
                     "If it is LAN-only, mark this as OK.")
        if no_hsts:
            labels = [s["label"] for s in no_hsts]
            self.add("hsts", "low", "tls", f"{len(labels)} HTTPS site(s) don't turn on HSTS",
                     ", ".join(labels[:8]),
                     "HSTS tells browsers to always use HTTPS for the site, which stops downgrade tricks on public Wi-Fi.",
                     'Once HTTPS works well, add: add_header Strict-Transport-Security "max-age=31536000" always;')
        if servers and not (redirect_missing or plain_auth):
            self.ok("tls", "HTTPS sites redirect plain-HTTP visitors")

        # autoindex
        ai = [(f, d) for f, t in trees for d, _ in _walk(t) if d["name"] == "autoindex" and d["args"][:1] == ["on"]]
        if ai:
            self.add("autoindex", "medium", "nginx", "Folder listings are turned on",
                     f"autoindex on in {', '.join(sorted({f for f, _ in ai}))}.",
                     "Visitors can browse every file in that folder, including backups or files you didn't mean to publish.",
                     "Remove autoindex on; unless you really want a public file listing.",
                     link={"page": "configs", "id": fid(ai[0][0])} if fid(ai[0][0]) else None)
        else:
            self.ok("nginx", "No public folder listings")

        # stub_status exposed
        exposed = []
        for s in servers:
            for d, path in _walk(s["block"]):
                if d["name"] == "location" and d["block"] and any(x["name"] == "stub_status" for x in d["block"]):
                    if not s["local"] and not any(x["name"] in ("allow", "deny") for x in d["block"]):
                        exposed.append(s)
        if exposed:
            self.add("stub_status", "medium", "nginx", "The nginx status page is public",
                     ", ".join(s["label"] for s in exposed),
                     "It reveals traffic numbers to anyone and helps attackers time their attempts.",
                     "Add allow 127.0.0.1; deny all; inside that location, or listen on 127.0.0.1 only.",
                     link={"page": "configs", "id": fid(exposed[0]["file"])} if fid(exposed[0]["file"]) else None)

        # certificates + private keys + htpasswd files
        certs, keys, pwfiles = set(), set(), set()
        for _, t in trees:
            for d, _ in _walk(t):
                if d["args"] and "$" not in d["args"][0]:
                    if d["name"] == "ssl_certificate":
                        certs.add(d["args"][0])
                    elif d["name"] == "ssl_certificate_key":
                        keys.add(d["args"][0])
                    elif d["name"] == "auth_basic_user_file":
                        pwfiles.add(d["args"][0])
        expired, soon, later = [], [], []
        for cp in sorted(certs):
            p = cp if os.path.isabs(cp) else os.path.join(self.c["cfg"]["nginx_dir"], cp)
            rc, out = self.c["run"](["openssl", "x509", "-enddate", "-noout", "-in", p], 10)
            if rc != 0:
                continue
            try:
                exp = datetime.strptime(out.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
            except (ValueError, IndexError):
                continue
            days = int((exp - datetime.utcnow()).total_seconds() // 86400)
            (expired if days < 0 else soon if days < 14 else later if days < 30 else []).append((cp, days))
        for cp, days in expired:
            self.add(f"cert_expired:{cp}", "high", "tls", "A certificate has expired",
                     f"{cp} expired {-days} day(s) ago.",
                     "Browsers show a full-page warning and most visitors (and apps) will refuse to connect.",
                     "Renew it (for Let's Encrypt: sudo certbot renew), then reload nginx.",
                     commands="sudo certbot renew && sudo systemctl reload nginx")
        for cp, days in soon:
            self.add(f"cert_soon:{cp}", "high", "tls", f"A certificate expires in {days} day(s)",
                     cp, "Once it expires, browsers block the site with a warning.",
                     "Renew it now. If it's Let's Encrypt, check that automatic renewal works: sudo certbot renew --dry-run",
                     commands="sudo certbot renew --dry-run")
        for cp, days in later:
            self.add(f"cert_30:{cp}", "low", "tls", f"A certificate expires in {days} days", cp,
                     "Let's Encrypt normally renews at 30 days left. If this one doesn't renew soon, renewal may be broken.",
                     "Keep an eye on it, or test renewal: sudo certbot renew --dry-run",
                     commands="sudo certbot renew --dry-run")
        if certs and not (expired or soon):
            self.ok("tls", f"{len(certs)} certificate(s) valid for 2+ weeks")
        bad_keys = []
        for k in sorted(keys):
            p = k if os.path.isabs(k) else os.path.join(self.c["cfg"]["nginx_dir"], k)
            try:
                if os.stat(p).st_mode & 0o004:
                    bad_keys.append(k)
            except OSError:
                pass
        if bad_keys:
            self.add("keyperms", "high", "tls", "A private key can be read by every user on the server",
                     ", ".join(bad_keys),
                     "Anyone who can log in to this server (or any compromised service on it) can copy the key "
                     "and pretend to be your site.",
                     "Restrict it to root.", fix_action="keyperms",
                     commands="\n".join(f"sudo chmod 600 {k}" for k in bad_keys))
        elif keys:
            self.ok("tls", "Private keys are not world-readable")
        bad_pw = []
        for pf in sorted(pwfiles):
            try:
                if os.stat(pf).st_mode & 0o004:
                    bad_pw.append(pf)
            except OSError:
                pass
        if bad_pw:
            self.add("htpasswdperms", "medium", "nginx", "A password file can be read by every user",
                     ", ".join(bad_pw), "The hashed passwords inside can be copied and cracked offline.",
                     "Make it readable only by root and nginx (www-data).", fix_action="htpasswdperms",
                     commands="\n".join(f"sudo chown root:www-data {p} && sudo chmod 640 {p}" for p in bad_pw))

    # ------------------------------------------------------------ Ubuntu
    def system(self):
        run = self.c["run"]
        upd, sysinfo, auto = self.c["updates"], self.c["system"], self.c["auto"]
        pk = upd.get("packages") or []
        sec = [p for p in pk if p.get("security")]
        checked = upd.get("checked")
        if sec:
            self.add("sec_updates", "high", "system", f"{len(sec)} security update(s) are waiting",
                     ", ".join(p["name"] for p in sec[:10]) + (" …" if len(sec) > 10 else ""),
                     "These fix known, published problems. Unpatched servers are the most common way in.",
                     "Install the security fixes from the Updates page.", link={"page": "updates"})
        elif checked:
            age_days = (datetime.now() - datetime.strptime(checked, "%Y-%m-%d %H:%M:%S")).days
            if age_days > 7:
                self.add("upd_stale", "low", "system", f"Updates were last checked {age_days} days ago",
                         f"Last check: {checked}", "New security fixes come out every week.",
                         "Check for updates on the Updates page.", link={"page": "updates"})
            else:
                self.ok("system", "No security updates waiting")
        else:
            self.add("upd_never", "medium", "system", "Updates have never been checked here",
                     "NginxUI doesn't know yet whether security fixes are waiting.",
                     "Unpatched servers are the most common way in.", "Check for updates on the Updates page.",
                     link={"page": "updates"})
        if sysinfo.get("reboot_required"):
            self.add("reboot", "medium", "system", "A restart is needed to finish security updates",
                     ", ".join(sysinfo.get("reboot_pkgs") or []) or "Ubuntu has flagged that a restart is required.",
                     "Kernel and core library fixes don't take effect until the server restarts.",
                     "Restart from the Updates page at a quiet time.", link={"page": "updates"})
        if not auto.get("installed"):
            self.add("auto_updates", "medium", "system", "Automatic security updates are not installed",
                     "unattended-upgrades is missing.",
                     "Without it, security fixes wait until someone logs in and installs them.",
                     "Install it, then turn it on from the Updates page.",
                     commands="sudo apt install unattended-upgrades")
        elif not auto.get("enabled"):
            self.add("auto_updates", "medium", "system", "Automatic security updates are off",
                     "Ubuntu won't install security fixes on its own.",
                     "Fixes wait until someone installs them by hand, sometimes for weeks.",
                     "Turn them on.", fix_action="auto_updates")
        else:
            self.ok("system", "Automatic security updates are on")

        # firewall
        ports_open = self.c["listening"]
        ui_port = int(self.c["cfg"]["port"])
        ssh_port = self.c["ssh"].get("port", "22") if self.c["ssh"] else "22"
        if shutil.which("ufw"):
            rc, out = run(["ufw", "status"], 10)
            if "Status: active" in out:
                self.ok("system", "Firewall (ufw) is on")
            else:
                self.add("firewall", "medium", "system", "The firewall is off",
                         "ufw is installed but not active.",
                         "Every service listening on this server can be reached by anything that can reach the server.",
                         f"Allow only what you need, then turn it on. Make sure your SSH port ({ssh_port}) is allowed first "
                         "or you can lock yourself out.",
                         commands=f"sudo ufw allow {ssh_port}/tcp\nsudo ufw allow 80/tcp\nsudo ufw allow 443/tcp\n"
                                  f"sudo ufw allow from 192.168.0.0/16 to any port {ui_port} proto tcp\nsudo ufw enable")
        else:
            self.add("firewall", "low", "system", "No ufw firewall found",
                     "NginxUI couldn't tell whether a firewall is protecting this server.",
                     "Without a firewall, every service listening here can be reached by anything that can reach the server. "
                     "That's fine if your router or another firewall already blocks it.",
                     "Use your router/UniFi firewall, or install ufw.",
                     commands=f"sudo apt install ufw\nsudo ufw allow {ssh_port}/tcp\nsudo ufw allow 80/tcp\n"
                              f"sudo ufw allow 443/tcp\nsudo ufw enable")

        # SSH
        ssh = self.c["ssh"]
        if ssh:
            if ssh.get("permitrootlogin") == "yes":
                self.add("ssh_root", "high", "system", "root can log in over SSH with a password",
                         "PermitRootLogin is yes.",
                         "root is the first account attackers try, and it has full control.",
                         "Log in as your own user and use sudo. Set PermitRootLogin no in /etc/ssh/sshd_config, "
                         "then restart SSH.",
                         commands="sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                                  "sudo systemctl restart ssh")
            else:
                self.ok("system", "root can't log in over SSH with a password")
            if ssh.get("passwordauthentication") == "yes":
                self.add("ssh_pw", "medium", "system", "SSH accepts passwords",
                         "PasswordAuthentication is yes.",
                         "Bots try password guesses against SSH all day. SSH keys can't be guessed.",
                         "Set up an SSH key for your account first, test it, then turn passwords off.",
                         commands="ssh-copy-id you@this-server   # from your computer, then test it\n"
                                  "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
                                  "sudo systemctl restart ssh")
            else:
                self.ok("system", "SSH only accepts keys")
        fb = self.c.get("f2b") or {}
        if not fb.get("installed"):
            self.add("fail2ban", "low", "system", "Nothing blocks repeated login guesses",
                     "fail2ban is not installed.",
                     "fail2ban watches logs and temporarily blocks addresses that keep failing SSH or website password prompts.",
                     "Install it, then manage it on NginxUI's Fail2ban page.",
                     commands="sudo apt install fail2ban")
        elif not fb.get("running"):
            self.add("fail2ban", "medium", "system", "fail2ban is installed but not running",
                     "It isn't blocking anything right now.",
                     "Password guessing and scanners go unchecked until it's running again.",
                     "Start it on the Fail2ban page.", link={"page": "fail2ban"})
        else:
            web = [j for j in fb.get("jails", []) if j.startswith("nginx")]
            if not web:
                self.add("fail2ban_web", "low", "system", "fail2ban only watches SSH, not your websites",
                         "Running jails: " + (", ".join(fb.get("jails", [])) or "none"),
                         "Turning on the website jails blocks password guessing on your sites and the scanners "
                         "that show up in your logs.",
                         "Turn on 'Website password prompts' and 'Scanners looking for weak spots' on the Fail2ban page.",
                         link={"page": "fail2ban"})
            else:
                self.ok("system", f"fail2ban is running ({len(fb.get('jails', []))} jails)")

        # listening services
        risky, others = [], []
        known_ok = {22, 80, 443, int(ssh_port) if str(ssh_port).isdigit() else 22, ui_port, 53}
        for addr, port, proc in ports_open:
            if re.match(r"^(127\.|\[?::1\]?|localhost)", addr):
                continue
            if port in RISKY_PORTS:
                risky.append((port, proc, addr))
            elif port not in known_ok:
                others.append((port, proc))
        for port, proc, addr in risky:
            label, sev = RISKY_PORTS[port]
            self.add(f"port:{port}", sev, "system", f"{label} is reachable from the network",
                     f"Port {port} ({proc or 'unknown program'}) listens on {addr}.",
                     "Services like this are meant to be private and are a favorite target for automated attacks.",
                     f"Make it listen on 127.0.0.1 only, or block port {port} in the firewall.",
                     commands=f"sudo ufw deny {port}")
        if others:
            self.add("ports", "info", "system", f"{len(others)} other service(s) are listening on the network",
                     ", ".join(f"{p} ({n or '?'})" for p, n in sorted(set(others))[:12]),
                     "Each listening service is another door. Make sure you know what each one is.",
                     "Close or firewall anything you don't recognise or don't need from other machines.")
        if not risky:
            self.ok("system", "No databases or remote-desktop services exposed")

    # ------------------------------------------------------------ NginxUI itself
    def self_check(self):
        cfg = self.c["cfg"]
        tls = bool(cfg.get("tls_cert") and os.path.exists(cfg.get("tls_cert") or ""))
        local = cfg.get("bind") in ("127.0.0.1", "::1", "localhost")
        if not tls and not local:
            self.add("ui_tls", "high", "nginxui", "NginxUI is reachable without HTTPS",
                     f"It listens on {cfg.get('bind')}:{cfg.get('port')} over plain HTTP.",
                     "Your NginxUI password and session travel unencrypted, and NginxUI can change the proxy "
                     "and install software.",
                     "Re-run the installer without --no-tls, or set bind to 127.0.0.1.")
        else:
            self.ok("nginxui", "NginxUI uses HTTPS or is local-only")
        mcp = self.c.get("mcp") or {}
        if mcp.get("enabled") and not mcp.get("totp"):
            self.add("mcp_totp", "medium", "nginxui", "Claude access is on without an authenticator code",
                     "The MCP server is enabled but no authenticator app is set up for approving connections.",
                     "Anyone who learns your NginxUI password could approve a Claude connection.",
                     "Set up the authenticator on the Claude page.", link={"page": "claude"})

    # ------------------------------------------------------------ traffic (last 24h)
    def traffic(self):
        logdir = self.c["cfg"]["log_dir"]
        paths = [os.path.join(logdir, n) for n in self.c["listdir"](logdir) if n.endswith("access.log")]
        since = time.time() - 86400
        probes, probe_ips = Counter(), Counter()
        fails = Counter()
        for p in paths:
            for e in stats.read_window(p, since, max_bytes=24 * 1024 * 1024):
                m = PROBE_RE.search(e["path"])
                if m:
                    probes[m.group(1).lower()] += 1
                    probe_ips[e["ip"]] += 1
                if e["status"] in (401, 403):
                    fails[e["ip"]] += 1
        if probes:
            total = sum(probes.values())
            top = ", ".join(f"{k} ×{v}" for k, v in probes.most_common(5))
            self.add("probes", "info" if total < 200 else "low", "traffic",
                     f"{total} scans for common weak spots in the last 24 hours",
                     f"From {len(probe_ips)} address(es). Most asked for: {top}. Busiest: "
                     + ", ".join(f"{ip} ({n})" for ip, n in probe_ips.most_common(3)),
                     "This is normal background noise for any server on the internet - bots try every address. "
                     "It only matters if one of those paths actually exists on your sites.",
                     "Make sure none of those paths return real files. fail2ban can block the noisiest scanners.")
        guessers = [(ip, n) for ip, n in fails.items() if n >= 20]
        if guessers:
            self.add("bruteforce", "medium", "traffic", f"{len(guessers)} address(es) hit password prompts repeatedly",
                     ", ".join(f"{ip} ({n} refused)" for ip, n in sorted(guessers, key=lambda x: -x[1])[:6]),
                     "Many 401/403 replies from one address usually means someone is guessing passwords.",
                     "Block the address on the Fail2ban page, add an IP allow list to the site, or turn on the fail2ban "
                     "'Website password prompts' jail so this is handled automatically.", link={"page": "fail2ban"},
                     commands="\n".join(f"sudo ufw deny from {ip}" for ip, _ in sorted(guessers, key=lambda x: -x[1])[:6]))
        if paths and not guessers:
            self.ok("traffic", "No password guessing seen in the last 24 hours")

    def run(self):
        for step in (self.nginx, self.system, self.self_check, self.traffic):
            try:
                step()
            except Exception as e:  # one broken check shouldn't hide the rest
                self.add(f"error:{step.__name__}", "info", "nginxui", f"The {step.__name__} checks could not finish",
                         str(e)[:200], "", "")
        self.findings.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["area"], f["title"]))
        return self.findings, self.passed


def parse_ss(out):
    """`ss -Htlnp` -> [(addr, port, process)]"""
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        addr = addr.strip("[]").split("%")[0]
        res.append((addr, int(port), m.group(1) if m else ""))
    return res


def parse_sshd(out):
    d = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        if k in ("permitrootlogin", "passwordauthentication", "port") and k not in d:
            d[k] = v.strip()
    return d

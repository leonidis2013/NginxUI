# LiveProxy

A web UI for an nginx reverse proxy on Ubuntu. Manage configs safely, set up new sites with guided wizards, see where traffic goes, read logs and stats, and keep Ubuntu and nginx up to date — all from a browser.

Version 1.0.0 · runs as a native systemd service · no dependencies beyond the Python 3 that ships with Ubuntu.

## What it does

| Page | What you get |
|---|---|
| **Dashboard** | nginx running / config OK, sites, requests and errors in the last hour, live connections, server load, memory, disk, pending updates, recent activity |
| **Configs** | Edit every file in `sites-available`, `conf.d`, `snippets` and `nginx.conf` with syntax colors. Turn sites on/off with a switch. **Every save is tested with `nginx -t` first; if the test or reload fails, the old file is put back automatically** and the error line is highlighted. |
| **History** | Every save is kept (60 versions per file), plus the original file from before LiveProxy touched it. Compare any version with a diff and restore it with one tap. Deleted files can be restored too. |
| **Wizards** | Reverse proxy, load balancer, static website, redirect. Asks plain questions (domain, where the app is, HTTPS certificate, IP allow list, password prompt, WebSockets, upload size…), shows the finished config, then applies it safely. |
| **Traffic Flow** | A live map: visitors → ports → sites → backends. Line thickness shows requests in the last 5 minutes; every backend is checked and shown green (answering) or red (down). Tap anything for details. |
| **Stats** | Requests over time, 4xx/5xx errors, status codes, top visitors, top pages, top clients — from the access logs. Optional live connection counter (nginx `stub_status`, local-only). |
| **Logs** | Tail any nginx log with a filter and follow mode; errors and 4xx/5xx lines are colored. |
| **Updates** | Check for Ubuntu updates, then install **security only**, **nginx only**, or **everything**. Before installing it backs up `/etc/nginx`; apt is told to keep your config files; afterwards nginx is tested and restarted if needed. Shows when a reboot is required (with a guarded reboot button) and toggles Ubuntu's automatic security updates. |
| **Backups** | Snapshot the whole `/etc/nginx` folder, download it, or restore it (restores are tested too, and roll back on failure). Automatic backup before every update and restore. |
| **Settings** | Users, password change, full activity log. |

## Install

On the Ubuntu server that runs nginx:

```bash
git clone https://github.com/leonidis2013/NginxUI.git
cd NginxUI
sudo ./install.sh
```

Then open `https://<server-ip>:9443` and create the admin login. The UI uses a self-signed certificate, so the browser warns the first time.

Options:

```bash
sudo ./install.sh --port 9500     # different port
sudo ./install.sh --no-tls        # plain HTTP on 127.0.0.1 only (put it behind nginx yourself)
sudo ./install.sh uninstall       # remove the app; keeps settings, history and backups
```

**Upgrade:** `git pull` then `sudo ./install.sh` again. Settings, users, history and backups are kept.

### Not sure which nginx you have?

The installer checks. LiveProxy is for nginx installed with `apt` (configs in `/etc/nginx/sites-available`). If Nginx Proxy Manager is running in Docker on the server, the installer stops and tells you — NPM keeps its own configs and has its own UI.

### Reaching it from the LAN only

If `ufw` is on, allow just your LAN:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 9443 proto tcp
```

Avoid exposing the LiveProxy port to the internet; it can change your proxy and install system updates.

## Settings file

`/etc/liveproxy/liveproxy.json` — restart with `sudo systemctl restart liveproxy` after editing.

| Key | Default | Meaning |
|---|---|---|
| `bind` / `port` | `0.0.0.0` / `9443` | Where the UI listens |
| `tls_cert` / `tls_key` | self-signed files in `/etc/liveproxy/tls` | Set both to `""` for plain HTTP |
| `allow_system_updates` | `true` | Set `false` to hide apt updates and reboot |
| `status_port` | `8099` | Local port for the live-connections status page |
| `session_hours` | `12` | How long a login lasts |
| `nginx_dir`, `sites_available`, `sites_enabled`, `conf_d`, `log_dir`, `letsencrypt_dir` | Ubuntu defaults | Change only for a custom layout |

Data lives in `/var/lib/liveproxy` (users, history, backups, activity log).

## How "safe save" works

1. The current file (and any symlink) is snapshotted.
2. The new content is written.
3. `nginx -t` runs. If it fails → everything is put back, nothing reloads, you see nginx's error.
4. `systemctl reload nginx`. If that fails → everything is put back and nginx is reloaded with the old config.
5. Only then is the version saved to history.

## Good to know

- Stats read nginx's standard `combined` log format. Sites made with a wizard get their own access log, so the Traffic Flow map can count requests per site; sites sharing one log show "shared log".
- Wizards write `http2 on;` on nginx 1.25.1+ and the older `listen … http2` form on earlier versions, and skip IPv6 listeners if IPv6 is turned off.
- Password prompts made by wizards are stored in `/etc/nginx/liveproxy-htpasswd/<site>`.
- HTTPS for sites uses certificates already on the server (Let's Encrypt certificates in `/etc/letsencrypt/live` are listed automatically). Getting certificates with certbot is not built in yet.
- LiveProxy runs as root because it edits `/etc/nginx`, reloads nginx and runs apt.

## Files

```
install.sh                 installer / upgrader / uninstaller
systemd/liveproxy.service  service unit
liveproxy/server.py        web server + API
liveproxy/nginxconf.py     nginx config parser (flow map) and wizard generator
liveproxy/stats.py         access-log stats and log tailing
liveproxy/static/          web UI (HTML, CSS, JS — no external files)
```

## License

© Jerod Ulicki. All rights reserved.

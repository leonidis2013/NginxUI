# Changelog

## 1.3.1 — 2026-11-21
- Fix: Claude Code failed with "HTTP 400 … Bad request syntax". When NginxUI answered a request early (for example 401 for a wrong key) it didn't read the request body, so the next request on the same connection was garbled. NginxUI now always reads the whole request first.
- Claude Code guide: the step 3 command only appears once you have a key (no more copying the placeholder), and the new key survives a page reload in that browser tab.

## 1.3.0 — 2026-11-21
- **Step-by-step Claude Code setup** on the Claude page (macOS / Windows / Linux): create a key, trust NginxUI's certificate, add the server, check it. Every command is ready to copy with your key and address already filled in.
- **Live connection check**: the guide shows what actually reached NginxUI from your computer (connected, certificate not trusted, no key, unknown or expired key) and what to do about each.
- NginxUI's certificate can be downloaded from /nginxui.pem, and a button makes a new certificate that covers the address you're using (then restarts NginxUI).
- New installs get a certificate clients can trust: marked as its own authority, for web servers, covering every server address and hostname.local, 825 days.
- Claude Code keys are added with --scope user, so NginxUI works in every folder.

## 1.2.1 — 2026-11-20
- NginxUI updates are part of the main update flow: one Check looks for Ubuntu, nginx and NginxUI updates, and "Choose what to install" has an "Also update NginxUI" option (on by default) that runs last, after the system updates.
- The task output window folds away: it's open while a task runs, folds up when it finishes, and the last task's output stays one tap away.

## 1.2.0 — 2026-11-20
- NginxUI updates itself from the browser: **Check** on the Updates page fetches the GitHub clone you installed from, lists the new changes and version, and **Update NginxUI** pulls them, reinstalls and restarts (settings, users, history and backups kept). The regular update check now includes NginxUI too.
- git runs as the clone's owner, so your GitHub sign-in is used and file ownership in the clone stays yours.

## 1.1.0 — 2026-11-20
- **Security page**: scans nginx (version shown, old TLS, missing HTTPS redirects, passwords over plain HTTP, HSTS, folder listings, public status page), certificates (expiry, private-key and password-file permissions), Ubuntu (security updates, restart needed, automatic updates, firewall, SSH root/password login, fail2ban, exposed databases/remote desktop) and the last 24 hours of traffic (scanners, password guessing). Each finding explains why it matters and how to fix it; safe ones have a one-tap fix. Findings can be marked as OK.
- **Claude (MCP) access**: built-in MCP server at /mcp with 21 tools for troubleshooting and tuning. Connect the Claude app (custom connector, approved with password + authenticator code, access level and time limit) or Claude Code (key). Every change Claude makes is tested, goes live, and waits on the Claude page for you to keep or revert.
- **Traffic Flow** groups server blocks by config file (switch to turn it off); tap a group to open that file.

## 1.0.2 — 2026-11-20
- Updates page redesigned as one top-to-bottom flow: status with one check button, a single "choose what to install" list (security fixes picked by default) with one Install button, progress shown in place, package list folded away, server info and automatic updates at the bottom

## 1.0.1 — 2026-11-20
- Renamed the app from LiveProxy to NginxUI (service `nginxui`, files in /opt/nginxui, /etc/nginxui, /var/lib/nginxui)

## 1.0.0 — 2026-11-20
First release.
- Config editor with syntax colors, enable/disable, safe save (nginx -t + automatic rollback), error-line highlight
- Version history with diff and one-tap restore; restore deleted files
- Wizards: reverse proxy, load balancer, static site, redirect (HTTPS, IP allow list, password prompt, WebSockets)
- Traffic Flow map with per-site request counts and backend health checks
- Stats from access logs, optional live connection counts (stub_status)
- Log viewer with filter and follow
- Ubuntu + nginx updates: check, install security / nginx / all, pre-update backup, reboot detection, automatic security updates toggle
- Backups of /etc/nginx with download and tested restore
- Login with multiple users, lockout after failed attempts, activity log
- Installer with systemd service and self-signed HTTPS

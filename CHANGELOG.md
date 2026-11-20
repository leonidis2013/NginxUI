# Changelog

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

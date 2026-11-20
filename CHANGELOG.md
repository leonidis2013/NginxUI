# Changelog

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

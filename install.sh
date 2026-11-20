#!/usr/bin/env bash
# NginxUI installer for Ubuntu (22.04 / 24.04 and newer)
#   sudo ./install.sh              install or upgrade
#   sudo ./install.sh --port 9443  pick a different port
#   sudo ./install.sh --no-tls     serve plain HTTP (only behind another HTTPS proxy)
#   sudo ./install.sh uninstall    remove the app (keeps /etc/nginxui and /var/lib/nginxui)
set -euo pipefail

APP=/opt/nginxui
ETC=/etc/nginxui
DATA=/var/lib/nginxui
UNIT=/etc/systemd/system/nginxui.service
PORT=9443
TLS=1
FORCE=0
UPDATE=0
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
w() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mxx\033[0m %s\n' "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo ./install.sh"

if [[ "${1:-}" == "uninstall" ]]; then
  c "Removing NginxUI"
  systemctl disable --now nginxui 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  rm -rf "$APP"
  c "Removed. Settings ($ETC) and history/backups ($DATA) were kept. Delete them by hand if you want."
  c "Your nginx config was not touched."
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --no-tls) TLS=0; shift ;;
    --force) FORCE=1; shift ;;
    --update) UPDATE=1; FORCE=1; shift ;;
    *) die "Unknown option $1" ;;
  esac
done

. /etc/os-release 2>/dev/null || true
[[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* || "${ID:-}" == "debian" ]] || w "This is not Ubuntu/Debian (${PRETTY_NAME:-unknown}); continuing anyway."

command -v python3 >/dev/null || { c "Installing python3"; apt-get update -qq; apt-get install -y python3; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python 3.8 or newer is needed"

# --- what kind of nginx is this? ---
if command -v docker >/dev/null && docker ps --format '{{.Image}}' 2>/dev/null | grep -q 'nginx-proxy-manager'; then
  w "Nginx Proxy Manager is running in Docker here."
  w "NginxUI manages the server's own nginx (apt package), not Nginx Proxy Manager's configs."
  [[ $FORCE -eq 1 ]] || die "Re-run with --force if you also have plain nginx installed and want NginxUI for it."
fi
if ! command -v nginx >/dev/null; then
  w "nginx is not installed."
  [[ $UPDATE -eq 1 ]] && die "nginx is missing; run the installer by hand."
  read -r -p "Install nginx from Ubuntu now? [Y/n] " a
  [[ "${a:-Y}" =~ ^[Yy]$ ]] || die "NginxUI needs nginx."
  apt-get update -qq && apt-get install -y nginx
fi
[[ -d /etc/nginx/sites-available ]] || w "/etc/nginx/sites-available is missing - NginxUI expects Ubuntu's nginx layout. conf.d files will still work."
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d

# --- copy the app ---
c "Installing app to $APP"
mkdir -p "$APP"
rm -rf "$APP/static"
cp -r "$SRC/nginxui/." "$APP/"
cp "$SRC/VERSION" "$APP/VERSION" 2>/dev/null || true
find "$APP" -name '__pycache__' -prune -exec rm -rf {} +
chown -R root:root "$APP"; chmod -R go-w "$APP"

mkdir -p "$ETC" "$DATA"; chmod 700 "$DATA"
if [[ -d "$SRC/.git" ]]; then
  echo "$SRC" > "$ETC/source"
  c "Browser updates will pull from the git clone in $SRC"
else
  rm -f "$ETC/source"
fi

# --- settings (kept on upgrade) ---
if [[ ! -f "$ETC/nginxui.json" ]]; then
  c "Writing settings to $ETC/nginxui.json"
  if [[ $TLS -eq 1 ]]; then
    cat > "$ETC/nginxui.json" <<EOF
{
  "bind": "0.0.0.0",
  "port": $PORT,
  "tls_cert": "$ETC/tls/nginxui.crt",
  "tls_key": "$ETC/tls/nginxui.key",
  "allow_system_updates": true
}
EOF
  else
    cat > "$ETC/nginxui.json" <<EOF
{
  "bind": "127.0.0.1",
  "port": $PORT,
  "tls_cert": "",
  "tls_key": "",
  "allow_system_updates": true
}
EOF
  fi
  chmod 600 "$ETC/nginxui.json"
else
  c "Keeping existing settings in $ETC/nginxui.json"
fi

# --- self-signed certificate for the web UI ---
if [[ $TLS -eq 1 && ! -f "$ETC/tls/nginxui.crt" ]]; then
  c "Creating a self-signed HTTPS certificate for the web UI"
  mkdir -p "$ETC/tls"
  IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$ETC/tls/nginxui.key" -out "$ETC/tls/nginxui.crt" \
    -subj "/CN=$(hostname)" \
    -addext "subjectAltName=DNS:$(hostname),DNS:localhost${IP:+,IP:$IP},IP:127.0.0.1" >/dev/null 2>&1
  chmod 600 "$ETC/tls/nginxui.key"
fi

# --- systemd service ---
c "Setting up the nginxui service"
cp "$SRC/systemd/nginxui.service" "$UNIT"
systemctl daemon-reload
systemctl enable nginxui >/dev/null 2>&1
systemctl restart nginxui
sleep 1
systemctl is-active --quiet nginxui || { journalctl -u nginxui -n 30 --no-pager; die "The service did not start (see above)."; }

PORT_NOW=$(python3 -c "import json;print(json.load(open('$ETC/nginxui.json')).get('port',9443))")
SCHEME=https; grep -q '"tls_cert": ""' "$ETC/nginxui.json" && SCHEME=http
IP=$(hostname -I 2>/dev/null | awk '{print $1}')

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  w "The ufw firewall is on. To reach NginxUI from your LAN only, run e.g.:"
  echo "    sudo ufw allow from 192.168.1.0/24 to any port $PORT_NOW proto tcp"
fi

echo
c "NginxUI $(cat "$APP/VERSION" 2>/dev/null || echo) is running"
echo "    Open:  $SCHEME://${IP:-this-server}:$PORT_NOW"
[[ $SCHEME == https ]] && echo "    Your browser will warn about the self-signed certificate the first time - that's expected."
echo "    First visit asks you to create the admin login."
echo "    Logs:  journalctl -u nginxui -f"

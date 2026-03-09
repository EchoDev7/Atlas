#!/usr/bin/env bash
set -euo pipefail

# Atlas VPN Panel - Safe Update Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

step() {
  echo -e "\n${BLUE}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

ok() {
  echo -e "${GREEN}✓${NC} $1"
}

warn() {
  echo -e "${YELLOW}!${NC} $1"
}

fail() {
  echo -e "${RED}✗ $1${NC}"
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  fail "Please run as root: sudo bash update.sh"
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${PROJECT_ROOT}/.venv"
SERVICE_FILE="/etc/systemd/system/atlas-backend.service"

step "Ensuring critical system dependencies are installed"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  openvpn easy-rsa wireguard wireguard-tools certbot \
  "linux-headers-$(uname -r)" openvpn-dco-dkms \
  iptables-persistent netfilter-persistent
ok "Critical system dependencies verified"

step "Updating source code from GitHub"
if [[ ! -d "${PROJECT_ROOT}/.git" ]]; then
  fail "This directory is not a git repository: ${PROJECT_ROOT}"
fi

git -C "${PROJECT_ROOT}" fetch --all --prune
git -C "${PROJECT_ROOT}" pull --ff-only origin main
ok "Source code updated"

step "Updating Python environment"
if [[ ! -d "${VENV_PATH}" ]]; then
  python3 -m venv "${VENV_PATH}"
  ok "Virtual environment created"
fi

"${VENV_PATH}/bin/pip" install --upgrade pip setuptools wheel
"${VENV_PATH}/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"
ok "Python packages updated"

step "Applying database migrations safely"
PYTHONPATH="${PROJECT_ROOT}" "${VENV_PATH}/bin/python" - <<'PY'
import backend.models  # noqa: F401
from backend.database import init_db

init_db()
print("Database schema is up to date")
PY
ok "Database migration completed without data wipe"

step "Ensuring atlas-backend.service uses dynamic HTTP/HTTPS runner"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Atlas FastAPI Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}
Environment=PYTHONPATH=${PROJECT_ROOT}
ExecStart=${VENV_PATH}/bin/python3 ${PROJECT_ROOT}/backend/run.py
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
ok "atlas-backend.service updated"

step "Restarting services"
if systemctl cat atlas-backend.service >/dev/null 2>&1; then
  systemctl restart atlas-backend.service
  if systemctl is-active --quiet atlas-backend.service; then
    ok "atlas-backend.service restarted"
  else
    fail "atlas-backend.service failed health check after restart"
  fi
else
  warn "atlas-backend.service not found. Skipping backend restart."
fi

if systemctl cat openvpn-server@server >/dev/null 2>&1; then
  systemctl restart openvpn-server@server
  if systemctl is-active --quiet openvpn-server@server; then
    ok "openvpn-server@server restarted"
  else
    warn "openvpn-server@server restart finished but service is not active"
  fi
elif systemctl cat openvpn@server >/dev/null 2>&1; then
  systemctl restart openvpn@server
  if systemctl is-active --quiet openvpn@server; then
    ok "openvpn@server restarted"
  else
    warn "openvpn@server restart finished but service is not active"
  fi
else
  warn "OpenVPN service unit not found. Skipping OpenVPN restart."
fi

step "Update completed"
echo -e "${GREEN}${BOLD}Atlas VPN Panel is now updated to the latest main branch.${NC}"

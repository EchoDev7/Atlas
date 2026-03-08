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

step "Restarting services"
systemctl daemon-reload
if systemctl cat atlas-backend.service >/dev/null 2>&1; then
  systemctl restart atlas-backend.service
  ok "atlas-backend.service restarted"
else
  warn "atlas-backend.service not found. Skipping backend restart."
fi

if systemctl cat openvpn-server@server >/dev/null 2>&1; then
  systemctl restart openvpn-server@server
  ok "openvpn-server@server restarted"
elif systemctl cat openvpn@server >/dev/null 2>&1; then
  systemctl restart openvpn@server
  ok "openvpn@server restarted"
else
  warn "OpenVPN service unit not found. Skipping OpenVPN restart."
fi

step "Update completed"
echo -e "${GREEN}${BOLD}Atlas VPN Panel is now updated to the latest main branch.${NC}"

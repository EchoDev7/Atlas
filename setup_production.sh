#!/usr/bin/env bash
set -euo pipefail

# Atlas Production Bootstrap (Ubuntu/Debian)
# Usage: sudo bash setup_production.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run as root: sudo bash setup_production.sh"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python3"
OPENVPN_DIR="/etc/openvpn"
OPENVPN_SERVER_DIR="${OPENVPN_DIR}/server"
EASYRSA_SRC="/usr/share/easy-rsa"


echo "[1/7] Installing OS dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  openvpn \
  easy-rsa \
  python3 \
  python3-venv \
  python3-pip \
  sqlite3 \
  curl \
  ca-certificates


echo "[2/7] Preparing OpenVPN server directories..."
mkdir -p "${OPENVPN_SERVER_DIR}"
mkdir -p "${OPENVPN_SERVER_DIR}/ccd"
mkdir -p "${OPENVPN_SERVER_DIR}/client-configs"


echo "[3/7] Preparing Easy-RSA working directory..."
if [[ -d "${EASYRSA_SRC}" ]]; then
  cp -a "${EASYRSA_SRC}/." "${OPENVPN_SERVER_DIR}/"
  chmod +x "${OPENVPN_SERVER_DIR}/easyrsa" || true
else
  echo "[WARN] Easy-RSA source directory not found at ${EASYRSA_SRC}."
  echo "[WARN] Ensure easy-rsa package is correctly installed."
fi


echo "[4/7] Creating Python virtual environment..."
if [[ ! -d "${PROJECT_ROOT}/.venv" ]]; then
  "${PYTHON_BIN}" -m venv "${PROJECT_ROOT}/.venv"
fi
"${PROJECT_ROOT}/.venv/bin/pip" install --upgrade pip
if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
  "${PROJECT_ROOT}/.venv/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"
else
  echo "[WARN] requirements.txt not found; skipping pip dependency install."
fi


echo "[5/7] Initializing Atlas database schema..."
PYTHONPATH="${PROJECT_ROOT}" "${PROJECT_ROOT}/.venv/bin/python" - <<'PY'
from backend.database import init_db
init_db()
print('Database initialized successfully')
PY


echo "[6/7] Applying baseline filesystem permissions..."
# OpenVPN private materials are generated later by PKI manager and additionally hardened there.
chown -R root:root "${OPENVPN_SERVER_DIR}"
chmod 700 "${OPENVPN_SERVER_DIR}"


echo "[7/7] Bootstrap complete."
echo "Next steps:"
echo "  1) Configure /etc/openvpn/server/server.conf via Atlas settings API"
echo "  2) Start service: systemctl enable --now openvpn-server@server"
echo "  3) Verify status: systemctl status openvpn-server@server"

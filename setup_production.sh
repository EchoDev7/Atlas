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
EASYRSA_BIN="${OPENVPN_SERVER_DIR}/easyrsa"
OPENVPN_SUBNET="10.8.0.0/24"
SYSCTL_FILE="/etc/sysctl.d/99-atlas.conf"
ATLAS_SERVICE_FILE="/etc/systemd/system/atlas-backend.service"


echo "[1/11] Installing OS dependencies..."
export DEBIAN_FRONTEND=noninteractive
if command -v debconf-set-selections >/dev/null 2>&1; then
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
fi
apt-get update -y
apt-get install -y \
  openvpn \
  easy-rsa \
  iproute2 \
  iptables \
  iptables-persistent \
  python3 \
  python3-venv \
  python3-pip \
  sqlite3 \
  curl \
  ca-certificates


echo "[2/11] Preparing OpenVPN server directories..."
mkdir -p "${OPENVPN_SERVER_DIR}"
mkdir -p "${OPENVPN_SERVER_DIR}/ccd"
mkdir -p "${OPENVPN_SERVER_DIR}/client-configs"


echo "[3/11] Preparing Easy-RSA working directory..."
if [[ -d "${EASYRSA_SRC}" ]]; then
  cp -a "${EASYRSA_SRC}/." "${OPENVPN_SERVER_DIR}/"
  chmod +x "${OPENVPN_SERVER_DIR}/easyrsa" || true
else
  echo "[WARN] Easy-RSA source directory not found at ${EASYRSA_SRC}."
  echo "[WARN] Ensure easy-rsa package is correctly installed."
fi


echo "[4/11] Enabling IPv4 forwarding (runtime + persistent)..."
sysctl -w net.ipv4.ip_forward=1
cat > "${SYSCTL_FILE}" <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null


echo "[5/11] Configuring NAT MASQUERADE for OpenVPN subnet..."
WAN_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
if [[ -z "${WAN_IFACE}" ]]; then
  echo "[ERROR] Failed to detect WAN interface from default route."
  exit 1
fi

if ! iptables -t nat -C POSTROUTING -s "${OPENVPN_SUBNET}" -o "${WAN_IFACE}" -j MASQUERADE 2>/dev/null; then
  iptables -t nat -A POSTROUTING -s "${OPENVPN_SUBNET}" -o "${WAN_IFACE}" -j MASQUERADE
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
else
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
fi


echo "[6/11] Creating Python virtual environment..."
if [[ ! -d "${PROJECT_ROOT}/.venv" ]]; then
  "${PYTHON_BIN}" -m venv "${PROJECT_ROOT}/.venv"
fi
"${PROJECT_ROOT}/.venv/bin/pip" install --upgrade pip
if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
  "${PROJECT_ROOT}/.venv/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"
else
  echo "[WARN] requirements.txt not found; skipping pip dependency install."
fi


echo "[7/11] Initializing Atlas database + PKI + server config..."
PYTHONPATH="${PROJECT_ROOT}" "${PROJECT_ROOT}/.venv/bin/python" - <<'PY'
import backend.models  # noqa: F401 - ensure SQLAlchemy metadata is registered
from backend.database import init_db
from backend.core.openvpn import OpenVPNManager

init_db()
print('Database initialized successfully')

openvpn_manager = OpenVPNManager()

pki_result = openvpn_manager.initialize_pki()
if not pki_result.get("success"):
    raise SystemExit(f"PKI initialization failed: {pki_result.get('message', 'unknown error')}")
print("PKI initialized successfully")

config_result = openvpn_manager.generate_server_config()
if not config_result.get("success"):
    raise SystemExit(f"Server config generation failed: {config_result.get('message', 'unknown error')}")
print(f"Server config generated: {config_result.get('config_path')}")
PY


echo "[8/11] Ensuring OpenVPN server certificate and DH params..."
if [[ ! -x "${EASYRSA_BIN}" ]]; then
  echo "[ERROR] Easy-RSA executable not found at ${EASYRSA_BIN}"
  exit 1
fi

if [[ ! -f "${OPENVPN_SERVER_DIR}/pki/issued/server.crt" ]] || [[ ! -f "${OPENVPN_SERVER_DIR}/pki/private/server.key" ]]; then
  "${EASYRSA_BIN}" --batch build-server-full server nopass
fi

if [[ ! -f "${OPENVPN_SERVER_DIR}/pki/dh.pem" ]]; then
  "${EASYRSA_BIN}" --batch gen-dh
fi


echo "[9/11] Applying baseline filesystem permissions..."
# OpenVPN private materials are generated later by PKI manager and additionally hardened there.
chown -R root:root "${OPENVPN_SERVER_DIR}"
chmod 700 "${OPENVPN_SERVER_DIR}"
find "${OPENVPN_SERVER_DIR}" -type f -name "*.key" -exec chmod 600 {} \;


echo "[10/11] Creating and enabling atlas-backend systemd service..."
cat > "${ATLAS_SERVICE_FILE}" <<EOF
[Unit]
Description=Atlas FastAPI Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}
Environment=PYTHONPATH=${PROJECT_ROOT}
ExecStart=${PROJECT_ROOT}/.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now atlas-backend.service


echo "[11/11] Enabling and starting OpenVPN service..."
systemctl enable --now openvpn-server@server


echo "Bootstrap complete."
echo "Next steps:"
echo "  1) Verify OpenVPN: systemctl status openvpn-server@server"
echo "  2) Verify Atlas backend: systemctl status atlas-backend.service"
echo "  3) Run full health check: sudo bash verify_production.sh"

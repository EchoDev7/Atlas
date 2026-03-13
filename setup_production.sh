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

resolve_openvpn_unit() {
  local candidate
  for candidate in openvpn-server@server openvpn@server openvpn.service; do
    if systemctl is-active --quiet "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  for candidate in openvpn-server@server openvpn@server openvpn.service; do
    if systemctl cat "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

detect_virtualization_type() {
  local virt_type=""

  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt_type="$(systemd-detect-virt 2>/dev/null || true)"
  fi

  if [[ -z "${virt_type}" || "${virt_type}" == "none" ]]; then
    if command -v hostnamectl >/dev/null 2>&1; then
      virt_type="$(hostnamectl 2>/dev/null | awk -F': ' '/Virtualization/ {print tolower($2); exit}' | xargs || true)"
    fi
  fi

  if [[ -z "${virt_type}" ]]; then
    virt_type="unknown"
  fi

  echo "${virt_type}"
}

install_openvpn_dco_if_supported() {
  local virt_type="$1"

  case "${virt_type}" in
    lxc|openvz)
      echo "[WARN] Warning: DCO not supported on this container, falling back to standard OpenVPN"
      return 0
      ;;
  esac

  if [[ "${virt_type}" != "kvm" && "${virt_type}" != "vmware" && "${virt_type}" != "none" && "${virt_type}" != "unknown" ]]; then
    echo "[INFO] Virtualization '${virt_type}' is not a known DCO-capable target. Continuing without DCO kernel module."
    return 0
  fi

  echo "[INFO] Attempting OpenVPN DCO install for virtualization: ${virt_type}"

  set +e
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "linux-headers-$(uname -r)" openvpn-dco-dkms >/dev/null 2>&1
  local install_rc=$?
  if [[ ${install_rc} -eq 0 ]]; then
    modprobe ovpn-dco-v2 >/dev/null 2>&1
    local modprobe_rc=$?
    if [[ ${modprobe_rc} -ne 0 ]]; then
      echo "[WARN] Warning: DCO installation completed but ovpn-dco-v2 could not be loaded, falling back to standard OpenVPN"
    else
      echo "[INFO] OpenVPN DCO kernel module installed and loaded successfully"
    fi
  else
    echo "[WARN] Warning: DCO not supported on this container, falling back to standard OpenVPN"
  fi
  set -e
}


echo "[1/12] Installing OS dependencies..."
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


echo "[2/12] Checking virtualization and installing OpenVPN DCO with graceful fallback..."
VIRT_TYPE="$(detect_virtualization_type)"
echo "[INFO] Detected virtualization: ${VIRT_TYPE}"
install_openvpn_dco_if_supported "${VIRT_TYPE}"


echo "[3/12] Preparing OpenVPN server directories..."
mkdir -p "${OPENVPN_SERVER_DIR}"
mkdir -p "${OPENVPN_SERVER_DIR}/ccd"
mkdir -p "${OPENVPN_SERVER_DIR}/client-configs"


echo "[4/12] Preparing Easy-RSA working directory..."
if [[ -d "${EASYRSA_SRC}" ]]; then
  cp -a "${EASYRSA_SRC}/." "${OPENVPN_SERVER_DIR}/"
  chmod +x "${OPENVPN_SERVER_DIR}/easyrsa" || true
else
  echo "[WARN] Easy-RSA source directory not found at ${EASYRSA_SRC}."
  echo "[WARN] Ensure easy-rsa package is correctly installed."
fi


echo "[5/12] Enabling IPv4/IPv6 forwarding and IPv6 kernel support (runtime + persistent)..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.disable_ipv6=0
sysctl -w net.ipv6.conf.default.disable_ipv6=0
sysctl -w net.ipv6.conf.all.forwarding=1
cat > "${SYSCTL_FILE}" <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system >/dev/null
if command -v netplan >/dev/null 2>&1; then
  netplan apply || true
fi


echo "[6/12] Configuring NAT MASQUERADE for OpenVPN subnet..."
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


echo "[7/12] Creating Python virtual environment..."
if [[ ! -d "${PROJECT_ROOT}/.venv" ]]; then
  "${PYTHON_BIN}" -m venv "${PROJECT_ROOT}/.venv"
fi
"${PROJECT_ROOT}/.venv/bin/pip" install --upgrade pip
if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
  "${PROJECT_ROOT}/.venv/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"
else
  echo "[WARN] requirements.txt not found; skipping pip dependency install."
fi


echo "[8/12] Initializing Atlas database + PKI + server config..."
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


echo "[9/12] Ensuring OpenVPN server certificate and DH params..."
if [[ ! -x "${EASYRSA_BIN}" ]]; then
  echo "[ERROR] Easy-RSA executable not found at ${EASYRSA_BIN}"
  exit 1
fi

if [[ ! -f "${OPENVPN_SERVER_DIR}/pki/issued/server.crt" ]] || [[ ! -f "${OPENVPN_SERVER_DIR}/pki/private/server.key" ]]; then
  (
    cd "${OPENVPN_SERVER_DIR}"
    EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
  )
fi

if [[ ! -f "${OPENVPN_SERVER_DIR}/pki/dh.pem" ]]; then
  (
    cd "${OPENVPN_SERVER_DIR}"
    EASYRSA_BATCH=1 ./easyrsa gen-dh
  )
fi


echo "[10/12] Applying baseline filesystem permissions..."
# OpenVPN private materials are generated later by PKI manager and additionally hardened there.
chown -R root:root "${OPENVPN_SERVER_DIR}"
chmod 700 "${OPENVPN_SERVER_DIR}"
find "${OPENVPN_SERVER_DIR}" -type f -name "*.key" -exec chmod 600 {} \;


echo "[11/12] Creating and enabling atlas-backend systemd service..."
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


echo "[12/12] Enabling and starting OpenVPN service..."
if OPENVPN_UNIT="$(resolve_openvpn_unit)"; then
  systemctl enable --now "${OPENVPN_UNIT}"
else
  echo "[ERROR] OpenVPN systemd unit not found (checked: openvpn-server@server, openvpn@server, openvpn.service)"
  exit 1
fi


echo "Bootstrap complete."
echo "Next steps:"
echo "  1) Verify OpenVPN: systemctl status ${OPENVPN_UNIT:-<detected_openvpn_unit>}"
echo "  2) Verify Atlas backend: systemctl status atlas-backend.service"
echo "  3) Run full health check: sudo bash verify_production.sh"

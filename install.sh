#!/usr/bin/env bash
set -eo pipefail

# Atlas VPN Panel - One-Line Installer (Ubuntu/Debian)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
  fail "Please run as root: sudo bash install.sh"
fi

if ! command -v apt-get >/dev/null 2>&1; then
  fail "This installer supports Ubuntu/Debian only (apt-get is required)."
fi

INSTALL_DIR="/opt/Atlas"
REPO_URL="${ATLAS_REPO_URL:-https://github.com/EchoDev7/Atlas.git}"
PROJECT_ROOT="${INSTALL_DIR}"
VENV_PATH="${PROJECT_ROOT}/.venv"
SERVICE_FILE="/etc/systemd/system/atlas-backend.service"
OPENVPN_SERVER_DIR="/etc/openvpn/server"
EASYRSA_SRC="/usr/share/easy-rsa"

step "Installing bootstrap dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl ca-certificates
ok "Bootstrap dependencies installed"

step "Preparing Atlas repository in ${INSTALL_DIR}"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  git -C "${INSTALL_DIR}" fetch --all --prune
  git -C "${INSTALL_DIR}" checkout main
  git -C "${INSTALL_DIR}" pull --ff-only origin main
  ok "Repository updated in ${INSTALL_DIR}"
elif [[ -d "${INSTALL_DIR}" && -n "$(ls -A "${INSTALL_DIR}" 2>/dev/null)" ]]; then
  fail "${INSTALL_DIR} exists and is not a git repository. Clean it and run installer again."
else
  mkdir -p "/opt"
  rm -rf "${INSTALL_DIR}"
  git clone "${REPO_URL}" "${INSTALL_DIR}"
  ok "Repository cloned to ${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}" || fail "Failed to enter ${INSTALL_DIR}"
PROJECT_ROOT="$(pwd)"
VENV_PATH="${PROJECT_ROOT}/.venv"

step "Installing system dependencies"
apt-get install -y \
  python3 python3-venv python3-pip \
  openvpn easy-rsa sqlite3 \
  "linux-headers-$(uname -r)" openvpn-dco-dkms \
  iproute2 iptables iptables-persistent \
  openssl
ok "OS dependencies installed"

step "Preparing environment file"
if [[ ! -f "${PROJECT_ROOT}/.env" ]]; then
  if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
    cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
  else
    cat > "${PROJECT_ROOT}/.env" <<'EOF'
SECRET_KEY=CHANGE_THIS_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
EOF
  fi
  ok "Created .env file"
else
  ok ".env already exists"
fi

if grep -q '^SECRET_KEY=CHANGE_THIS_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32' "${PROJECT_ROOT}/.env"; then
  NEW_SECRET="$(openssl rand -hex 32)"
  sed -i "s/^SECRET_KEY=.*/SECRET_KEY=${NEW_SECRET}/" "${PROJECT_ROOT}/.env"
  ok "Generated secure SECRET_KEY"
fi

step "Creating Python virtual environment"
if [[ ! -d "${VENV_PATH}" ]]; then
  python3 -m venv "${VENV_PATH}"
  ok "Virtual environment created"
else
  ok "Virtual environment already exists"
fi

"${VENV_PATH}/bin/pip" install --upgrade pip setuptools wheel
"${VENV_PATH}/bin/pip" install -r "${PROJECT_ROOT}/requirements.txt"
ok "Python dependencies installed"

step "Preparing OpenVPN directories"
mkdir -p "${OPENVPN_SERVER_DIR}" "${OPENVPN_SERVER_DIR}/ccd" "${OPENVPN_SERVER_DIR}/client-configs"
if [[ -d "${EASYRSA_SRC}" ]]; then
  cp -a "${EASYRSA_SRC}/." "${OPENVPN_SERVER_DIR}/"
  chmod +x "${OPENVPN_SERVER_DIR}/easyrsa" || true
  ok "Easy-RSA files prepared"
else
  warn "Easy-RSA source directory not found at ${EASYRSA_SRC}"
fi

step "Ensuring OpenVPN server PKI materials"
if [[ ! -x "${OPENVPN_SERVER_DIR}/easyrsa" ]]; then
  fail "Easy-RSA executable not found at ${OPENVPN_SERVER_DIR}/easyrsa"
fi

mkdir -p "${OPENVPN_SERVER_DIR}/pki"
unset EASYRSA_REQ_CN
export EASYRSA_BATCH=1

(
  cd "${OPENVPN_SERVER_DIR}" || exit 1

  if [[ ! -f "pki/index.txt" ]]; then
    ./easyrsa init-pki
  fi

  if [[ ! -f "pki/ca.crt" ]]; then
    EASYRSA_REQ_CN="Atlas_VPN_CA" ./easyrsa build-ca nopass
  fi

  unset EASYRSA_REQ_CN

  if [[ ! -f "pki/issued/server.crt" || ! -f "pki/private/server.key" ]]; then
    ./easyrsa build-server-full server nopass
  fi

  if [[ ! -f "pki/dh.pem" ]]; then
    ./easyrsa gen-dh
  fi

  if [[ ! -f "pki/tls-crypt.key" ]]; then
    openvpn --genkey secret pki/tls-crypt.key \
      || openvpn --genkey --secret pki/tls-crypt.key \
      || exit 1
  fi
)

if [[ ! -f "${OPENVPN_SERVER_DIR}/pki/tls-crypt.key" ]]; then
  fail "Failed to generate tls-crypt key at ${OPENVPN_SERVER_DIR}/pki/tls-crypt.key"
fi

cp -f "${OPENVPN_SERVER_DIR}/pki/tls-crypt.key" "${OPENVPN_SERVER_DIR}/ta.key"
chmod 600 "${OPENVPN_SERVER_DIR}/pki/tls-crypt.key" "${OPENVPN_SERVER_DIR}/ta.key" "${OPENVPN_SERVER_DIR}/pki/private/server.key" "${OPENVPN_SERVER_DIR}/pki/dh.pem" 2>/dev/null || true
ok "OpenVPN server PKI materials are ready"

step "Initializing Atlas database and OpenVPN assets"
PYTHONPATH="${PROJECT_ROOT}" "${VENV_PATH}/bin/python" - <<'PY'
import backend.models  # noqa: F401
from backend.database import init_db
from backend.core.openvpn import OpenVPNManager

init_db()
manager = OpenVPNManager()

pki_result = manager.initialize_pki()
if not pki_result.get("success"):
    raise SystemExit(f"PKI initialization failed: {pki_result.get('message', 'unknown error')}")

config_result = manager.generate_server_config()
if not config_result.get("success"):
    raise SystemExit(f"Server config generation failed: {config_result.get('message', 'unknown error')}")

print("Atlas DB + PKI + OpenVPN server config ready")
PY
ok "Database and OpenVPN configuration initialized"

step "Creating systemd service: atlas-backend.service"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Atlas FastAPI Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}
Environment=PYTHONPATH=${PROJECT_ROOT}
ExecStart=${VENV_PATH}/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now atlas-backend.service
ok "atlas-backend.service enabled and started"

step "Starting OpenVPN service"
OPENVPN_UNIT=""
if systemctl cat openvpn-server@server >/dev/null 2>&1; then
  OPENVPN_UNIT="openvpn-server@server"
elif systemctl cat openvpn@server >/dev/null 2>&1; then
  OPENVPN_UNIT="openvpn@server"
fi

if [[ -n "${OPENVPN_UNIT}" ]]; then
  systemctl enable --now "${OPENVPN_UNIT}"
  ok "${OPENVPN_UNIT} enabled and started"
else
  warn "OpenVPN systemd unit not detected automatically. Configure manually if needed."
fi

PUBLIC_IP="$(curl -4 -s --max-time 5 ifconfig.me || true)"
if [[ -z "${PUBLIC_IP}" ]]; then
  PUBLIC_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print; exit}')"
fi
if [[ -z "${PUBLIC_IP}" ]]; then
  PUBLIC_IP="<PUBLIC_IP>"
fi

echo
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                 ✅ Atlas VPN Panel installed successfully!          ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}${BOLD}║ Access URL:${NC}            http://${PUBLIC_IP}:8000"
echo -e "${BLUE}${BOLD}║ Default Credentials:${NC}   Username: admin | Password: admin123"
echo -e "${YELLOW}${BOLD}║ Security Warning:${NC}      Change the default password immediately after first login."
echo -e "${BLUE}${BOLD}║ Useful Commands:${NC}"
echo -e "${BLUE}║   - Service status:${NC} systemctl status atlas-backend"
echo -e "${BLUE}║   - Live logs:${NC} journalctl -u atlas-backend -f"
echo -e "${BLUE}║   - Update panel:${NC} cd /opt/Atlas && sudo bash update.sh"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"

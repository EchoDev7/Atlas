#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

OK_COUNT=0
ERR_COUNT=0

ok() {
  echo -e "${GREEN}[OK]${NC} $1"
  OK_COUNT=$((OK_COUNT + 1))
}

err() {
  echo -e "${RED}[ERROR]${NC} $1"
  ERR_COUNT=$((ERR_COUNT + 1))
}

check_exists() {
  local path="$1"
  local label="$2"
  if [[ -e "$path" ]]; then
    ok "$label exists: $path"
  else
    err "$label missing: $path"
  fi
}

check_listening_port() {
  local port="$1"
  local label="$2"
  if command -v ss >/dev/null 2>&1; then
    if ss -tuln | grep -Eq "[:.]${port}[[:space:]]"; then
      ok "$label is listening on port ${port}"
    else
      err "$label is not listening on port ${port}. Fix: ensure service is running and bound to ${port}."
    fi
  else
    err "ss command not found. Fix: sudo apt install -y iproute2"
  fi
}

echo "=== Atlas Production Verification ==="

# 0) Dependencies
if command -v openvpn >/dev/null 2>&1; then
  ok "openvpn is installed"
else
  err "openvpn is not installed. Fix: sudo apt update && sudo apt install -y openvpn"
fi

if command -v easyrsa >/dev/null 2>&1 || [[ -x "/usr/share/easy-rsa/easyrsa" ]] || [[ -x "/etc/openvpn/server/easyrsa" ]]; then
  ok "easy-rsa is installed"
else
  err "easy-rsa is not installed. Fix: sudo apt update && sudo apt install -y easy-rsa"
fi

OPENVPN_SERVER_DIR="/etc/openvpn/server"
PKI_DIR="${OPENVPN_SERVER_DIR}/pki"
CA_CERT="${PKI_DIR}/ca.crt"
TA_KEY="${OPENVPN_SERVER_DIR}/ta.key"
ATLAS_BACKEND_SERVICE_FILE="/etc/systemd/system/atlas-backend.service"

# 1) PKI paths and required files
check_exists "$OPENVPN_SERVER_DIR" "OpenVPN server directory"
check_exists "$PKI_DIR" "PKI directory"
check_exists "$CA_CERT" "CA certificate"
check_exists "$TA_KEY" "TLS static key (ta.key)"

# 2) Strict permissions on private key files (.key => 600)
if [[ -d "$OPENVPN_SERVER_DIR" ]]; then
  mapfile -t key_files < <(find "$OPENVPN_SERVER_DIR" -type f -name "*.key" 2>/dev/null || true)
  if [[ ${#key_files[@]} -eq 0 ]]; then
    err "No .key files found under $OPENVPN_SERVER_DIR"
  else
    for key_file in "${key_files[@]}"; do
      perm=$(stat -c "%a" "$key_file")
      if [[ "$perm" == "600" ]]; then
        ok "Key permission is 600: $key_file"
      else
        err "Key permission is $perm (expected 600): $key_file"
      fi
    done
  fi
else
  err "Cannot validate .key permissions because $OPENVPN_SERVER_DIR is missing"
fi

# 3) SQLite initialization check
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="${PROJECT_ROOT}/data/atlas.db"

if [[ -f "$DB_PATH" ]]; then
  ok "SQLite database file exists: $DB_PATH"

  if command -v sqlite3 >/dev/null 2>&1; then
    tables=$(sqlite3 "$DB_PATH" ".tables" || true)
    if [[ "$tables" == *"admins"* ]] || [[ "$tables" == *"vpn_users"* ]]; then
      ok "SQLite schema initialized (critical tables detected)"
    else
      err "SQLite file exists but expected tables were not detected"
    fi
  else
    err "sqlite3 binary not found; cannot validate schema tables"
  fi
else
  err "SQLite database file not found: $DB_PATH"
fi

# 4) Network & routing check
if command -v sysctl >/dev/null 2>&1; then
  ip_forward_value="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "")"
  if [[ "$ip_forward_value" == "1" ]]; then
    ok "net.ipv4.ip_forward is enabled"
  else
    err "net.ipv4.ip_forward is not enabled. Fix: sudo sysctl -w net.ipv4.ip_forward=1 && echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-atlas.conf"
  fi
else
  err "sysctl command not found. Fix: install procps package."
fi

# 5) Firewall/NAT check for OpenVPN subnet
OPENVPN_SUBNET="10.8.0.0/24"
if command -v iptables >/dev/null 2>&1; then
  if iptables -t nat -S 2>/dev/null | grep -Eq "(${OPENVPN_SUBNET}.*(MASQUERADE|SNAT)|(MASQUERADE|SNAT).*(-s ${OPENVPN_SUBNET}|--source ${OPENVPN_SUBNET}))"; then
    ok "NAT rule exists for OpenVPN subnet ${OPENVPN_SUBNET}"
  else
    err "No MASQUERADE/SNAT rule found for ${OPENVPN_SUBNET}. Fix: sudo iptables -t nat -A POSTROUTING -s ${OPENVPN_SUBNET} -o <WAN_IFACE> -j MASQUERADE"
  fi
else
  err "iptables command not found. Fix: sudo apt install -y iptables"
fi

# 6) Ports & services checks
if command -v ss >/dev/null 2>&1; then
  if ss -tuln | grep -Eq "(:443|:1194)[[:space:]]"; then
    ok "OpenVPN listening port detected (443 or 1194)"
  else
    err "OpenVPN port is not listening on 443/1194. Fix: verify server.conf port/proto and restart OpenVPN: sudo systemctl restart openvpn-server@server"
  fi
else
  err "ss command not found. Fix: sudo apt install -y iproute2"
fi

check_listening_port "8000" "Atlas FastAPI panel"

if command -v systemctl >/dev/null 2>&1; then
  check_exists "$ATLAS_BACKEND_SERVICE_FILE" "Atlas backend systemd unit file"

  atlas_backend_state="$(systemctl is-active atlas-backend.service 2>/dev/null || true)"
  if [[ "$atlas_backend_state" == "active" ]]; then
    ok "systemd service atlas-backend.service is active"
  else
    err "systemd service atlas-backend.service is '${atlas_backend_state:-inactive}'. Fix: sudo systemctl daemon-reload && sudo systemctl enable --now atlas-backend.service"
  fi

  openvpn_service_state="$(systemctl is-active openvpn-server@server 2>/dev/null || true)"
  if [[ "$openvpn_service_state" == "active" ]]; then
    ok "systemd service openvpn-server@server is active"
  else
    err "systemd service openvpn-server@server is '${openvpn_service_state:-inactive}'. Fix: sudo systemctl enable --now openvpn-server@server"
  fi
else
  err "systemctl command not found. Fix: run this script on a systemd-based Ubuntu VPS."
fi

echo ""
echo "=== Verification Summary ==="
echo -e "${GREEN}OK:${NC} ${OK_COUNT}"
echo -e "${RED}ERROR:${NC} ${ERR_COUNT}"

if [[ "$ERR_COUNT" -gt 0 ]]; then
  exit 1
fi

exit 0

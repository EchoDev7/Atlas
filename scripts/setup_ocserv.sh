#!/usr/bin/env bash
set -euo pipefail

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
  fail "Please run as root"
fi

if ! command -v apt-get >/dev/null 2>&1; then
  fail "setup_ocserv.sh supports Ubuntu/Debian only"
fi

OCSERV_CONF="/etc/ocserv/ocserv.conf"
OCSERV_SSL_DIR="/etc/ocserv/ssl"
OCSERV_CERT="${OCSERV_SSL_DIR}/server-cert.pem"
OCSERV_KEY="${OCSERV_SSL_DIR}/server-key.pem"
LE_LIVE_DIR="/etc/letsencrypt/live"

step "Installing OpenConnect packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ocserv gnutls-bin
ok "ocserv and gnutls-bin installed"

step "Preparing OpenConnect SSL assets"
mkdir -p "${OCSERV_SSL_DIR}"
chmod 700 "${OCSERV_SSL_DIR}" || true

pick_letsencrypt_domain() {
  local domain_dir
  for domain_dir in "${LE_LIVE_DIR}"/*; do
    [[ -d "${domain_dir}" ]] || continue
    [[ -f "${domain_dir}/fullchain.pem" ]] || continue
    [[ -f "${domain_dir}/privkey.pem" ]] || continue
    echo "${domain_dir}"
    return 0
  done
  return 1
}

if domain_path="$(pick_letsencrypt_domain)"; then
  ln -sf "${domain_path}/fullchain.pem" "${OCSERV_CERT}"
  ln -sf "${domain_path}/privkey.pem" "${OCSERV_KEY}"
  ok "Using Let's Encrypt certificate from ${domain_path}"
else
  warn "No Let's Encrypt certificate found. Generating self-signed fallback certificate."
  certtool --generate-privkey --outfile "${OCSERV_KEY}"
  cat > /tmp/ocserv-cert.tmpl <<'EOF'
cn = "Atlas OpenConnect"
organization = "Atlas"
serial = 1
expiration_days = 3650
tls_www_server
encryption_key
signing_key
EOF
  certtool --generate-self-signed \
    --load-privkey "${OCSERV_KEY}" \
    --template /tmp/ocserv-cert.tmpl \
    --outfile "${OCSERV_CERT}"
  rm -f /tmp/ocserv-cert.tmpl
  ok "Self-signed certificate generated for ocserv"
fi

chmod 600 "${OCSERV_KEY}" || true
chmod 644 "${OCSERV_CERT}" || true

step "Writing baseline ocserv configuration"
cat > "${OCSERV_CONF}" <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = 4433
udp-port = 4433
device = vpns
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv-socket
isolate-workers = true
max-clients = 1024
max-same-clients = 4
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
server-cert = ${OCSERV_CERT}
server-key = ${OCSERV_KEY}
ipv4-network = 10.10.12.0
ipv4-netmask = 255.255.255.0
route = default
no-route = 127.0.0.0/8
no-route = 10.0.0.0/8
no-route = 172.16.0.0/12
no-route = 192.168.0.0/16
dns = 1.1.1.1
dns = 8.8.8.8
EOF
ok "ocserv baseline configuration written"

step "Enabling and restarting ocserv"
systemctl daemon-reload || true
systemctl enable ocserv || true
if systemctl restart ocserv; then
  if systemctl is-active --quiet ocserv; then
    ok "ocserv is active"
  else
    warn "ocserv restart completed but service is not active"
  fi
else
  warn "Failed to restart ocserv. Verify /etc/ocserv/ocserv.conf and certificates"
fi

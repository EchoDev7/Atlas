#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

IPSEC_PSK="${ATLAS_IPSEC_PSK:-atlas-change-me-strong-psk}"
L2TP_LOCAL_IP="10.10.11.1"
L2TP_REMOTE_POOL="10.10.11.100-200"
L2TP_SUBNET="10.10.11.0/24"

echo "[1/7] Installing required native PPP/IPsec packages..."
apt-get update
apt-get install -y xl2tpd strongswan iptables-persistent

echo "[2/7] Preparing L2TP/IPsec baseline..."

echo "[3/7] Writing L2TP/IPsec baseline configuration..."
cat > /etc/ipsec.conf <<'EOF'
config setup
  charondebug="ike 1, knl 1, cfg 0"
  uniqueids=no

conn atlas-l2tp-psk
  auto=add
  keyexchange=ikev1
  authby=secret
  type=transport
  left=%any
  leftprotoport=17/1701
  right=%any
  rightprotoport=17/%any
  ike=aes256-sha1-modp1024,aes128-sha1-modp1024!
  esp=aes256-sha1,aes128-sha1!
  rekey=no
EOF

cat > /etc/ipsec.secrets <<EOF
%any %any : PSK "${IPSEC_PSK}"
EOF

mkdir -p /etc/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
ipsec saref = yes

[lns default]
ip range = ${L2TP_REMOTE_POOL}
local ip = ${L2TP_LOCAL_IP}
require chap = yes
refuse pap = yes
require authentication = yes
name = xl2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<'EOF'
name xl2tpd
ipcp-accept-local
ipcp-accept-remote
ms-dns 1.1.1.1
ms-dns 8.8.8.8
noccp
auth
crtscts
idle 1800
mtu 1460
mru 1460
lock
connect-delay 5000
EOF

echo "[4/7] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if grep -q '^net.ipv4.ip_forward=' /etc/sysctl.conf; then
  sed -i 's/^net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
else
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi

echo "[5/7] Applying firewall allow rules (L2TP/IPsec)..."
ensure_rule() {
  if ! iptables -C "$@" 2>/dev/null; then
    iptables -A "$@"
  fi
}

ensure_rule INPUT -p udp --dport 1701 -j ACCEPT
ensure_rule INPUT -p udp --dport 500 -j ACCEPT
ensure_rule INPUT -p udp --dport 4500 -j ACCEPT
ensure_rule INPUT -p 50 -j ACCEPT

echo "[6/7] Applying NAT/MASQUERADE rules for PPP client subnets..."
ensure_rule FORWARD -s "${L2TP_SUBNET}" -j ACCEPT
ensure_rule FORWARD -d "${L2TP_SUBNET}" -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.11.0/24 -j MASQUERADE

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
fi

echo "[7/7] Restarting and enabling VPN daemons..."
systemctl enable --now xl2tpd
systemctl restart xl2tpd

resolve_strongswan_unit() {
  local candidate
  for candidate in strongswan strongswan-swanctl strongswan-starter; do
    if systemctl cat "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

if STRONGSWAN_UNIT="$(resolve_strongswan_unit)"; then
  systemctl enable --now "${STRONGSWAN_UNIT}" || true
  systemctl restart "${STRONGSWAN_UNIT}" || true
  echo "StrongSwan service active unit: ${STRONGSWAN_UNIT}"
elif command -v ipsec >/dev/null 2>&1; then
  ipsec restart || true
  echo "StrongSwan controlled through ipsec command fallback."
else
  echo "StrongSwan service unit/command not found (tried strongswan,strongswan-swanctl,strongswan-starter,ipsec)" >&2
fi

echo

echo "Native PPP/IPsec provisioning completed."
echo "L2TP local/remote: ${L2TP_LOCAL_IP}, ${L2TP_REMOTE_POOL}"
echo "IPsec PSK source: ATLAS_IPSEC_PSK env var (fallback default if unset)."

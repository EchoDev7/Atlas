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
  fail "setup_singbox.sh supports Ubuntu/Debian only"
fi

SINGBOX_BIN_PATH="/usr/local/bin/sing-box"
SINGBOX_CONFIG_DIR="/usr/local/etc/sing-box"
SINGBOX_CONFIG_PATH="${SINGBOX_CONFIG_DIR}/config.json"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
GITHUB_LATEST_API="https://api.github.com/repos/SagerNet/sing-box/releases/latest"

step "Installing sing-box provisioning dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl tar jq
ok "Dependencies installed"

step "Resolving latest sing-box linux-amd64 release dynamically"
release_json="$(curl -fsSL "${GITHUB_LATEST_API}")" || fail "Failed to query GitHub releases API"

download_url="$(
  printf '%s' "${release_json}" \
  | jq -r '.assets[]? | select(.name | test("linux-amd64\\.tar\\.gz$")) | .browser_download_url' \
  | head -n 1
)"

if [[ -z "${download_url}" || "${download_url}" == "null" ]]; then
  download_url="$(
    printf '%s' "${release_json}" \
    | grep -Eo 'https://[^"[:space:]]*linux-amd64\.tar\.gz' \
    | head -n 1
  )"
fi

if [[ -z "${download_url}" ]]; then
  fail "Could not find linux-amd64.tar.gz asset in latest sing-box release"
fi
ok "Latest release asset resolved: ${download_url}"

step "Downloading and installing latest sing-box binary"
workdir="$(mktemp -d /tmp/atlas-singbox-XXXXXX)"
archive_path="${workdir}/sing-box-linux-amd64.tar.gz"
trap 'rm -rf "${workdir}"' EXIT

curl -fL "${download_url}" -o "${archive_path}" || fail "Failed to download latest sing-box archive"
tar -xzf "${archive_path}" -C "${workdir}" || fail "Failed to extract sing-box archive"

binary_source="$(find "${workdir}" -type f -name 'sing-box' | head -n 1)"
if [[ -z "${binary_source}" ]]; then
  fail "sing-box binary was not found in extracted archive"
fi

install -m 0755 "${binary_source}" "${SINGBOX_BIN_PATH}"
ok "Installed sing-box binary at ${SINGBOX_BIN_PATH}"

step "Preparing baseline sing-box config"
mkdir -p "${SINGBOX_CONFIG_DIR}"
if [[ ! -f "${SINGBOX_CONFIG_PATH}" ]]; then
  cat > "${SINGBOX_CONFIG_PATH}" <<'EOF'
{
  "log": {
    "level": "info"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
  ok "Created baseline sing-box config at ${SINGBOX_CONFIG_PATH}"
else
  ok "Existing sing-box config preserved at ${SINGBOX_CONFIG_PATH}"
fi

step "Writing sing-box systemd service"
cat > "${SINGBOX_SERVICE_FILE}" <<'EOF'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1 || true
if systemctl restart sing-box; then
  if systemctl is-active --quiet sing-box; then
    ok "sing-box service is active"
  else
    warn "sing-box restart completed but service is not active"
  fi
else
  warn "Failed to restart sing-box. Verify ${SINGBOX_CONFIG_PATH}"
fi

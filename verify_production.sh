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

echo "=== Atlas Production Verification ==="

OPENVPN_SERVER_DIR="/etc/openvpn/server"
PKI_DIR="${OPENVPN_SERVER_DIR}/pki"
CA_CERT="${PKI_DIR}/ca.crt"
TA_KEY="${OPENVPN_SERVER_DIR}/ta.key"

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

echo ""
echo "=== Verification Summary ==="
echo -e "${GREEN}OK:${NC} ${OK_COUNT}"
echo -e "${RED}ERROR:${NC} ${ERR_COUNT}"

if [[ "$ERR_COUNT" -gt 0 ]]; then
  exit 1
fi

exit 0

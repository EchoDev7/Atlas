# PROJECT STATE REPORT

## Executive Summary

Atlas is a web-based VPN control plane built on FastAPI + SQLite with a static Alpine.js frontend, designed to operate as a lightweight self-hosted management panel. The current implementation is beyond skeleton phase and includes:

- Authentication and admin security controls (JWT login, password management, login rate-limiting, audit logging).
- OpenVPN lifecycle and user management (settings, certificate-based provisioning, service controls, config generation).
- WireGuard lifecycle and user provisioning (key management, peer synchronization, diagnostics).
- DNSTT tunnel orchestration (install/build, key generation, server/client setup, transport strategies, telemetry, diagnostics).
- Dynamic Policy-Based Routing (PBR) dashboard with CRUD + kernel synchronization.
- Operational APIs (system service actions, backups, restore, logs, terminal access, time/NTP controls).

At runtime, Atlas behaves as a unified control surface where the frontend modifies persisted settings in SQLite, backend routers validate and apply changes, and runtime managers enforce networking state (OpenVPN/WireGuard/DNSTT/PBR) on the host OS.

---

## Database Schema

Atlas uses SQLAlchemy models with SQLite migration logic in `backend/database.py` (`init_db`). The schema is evolved in-place via `ALTER TABLE` and backfills.

### Core Tables

1. `admins`
   - Purpose: panel administrators.
   - Critical columns: `username`, `hashed_password`, `is_active`, `last_login`.

2. `general_settings` (singleton)
   - Purpose: global system/network/tunnel config.
   - Critical columns:
     - Network/system: `server_address`, `public_ipv4_address`, `public_ipv6_address`, `wan_interface`, `server_system_dns_primary`, `server_system_dns_secondary`.
     - Security/panel: `admin_allowed_ips`, `login_max_failed_attempts`, `login_block_duration_minutes`, `panel_domain`, `panel_https_port`, `subscription_domain`, `subscription_https_port`, `force_https`.
     - Tunnel orchestration: `is_tunnel_enabled`, `tunnel_mode`, `tunnel_architecture`, `foreign_server_ip`, `foreign_server_port`, `foreign_ssh_user`, `foreign_ssh_password`.
     - DNSTT runtime: `dnstt_domain`, `dnstt_active_domain`, `dnstt_dns_resolver`, `dnstt_resolver_strategy`, `dnstt_duplication_mode`, `dnstt_mtu_mode`, `dnstt_mtu*`, `dnstt_transport_*`, `dnstt_telemetry`, `dnstt_telemetry_history`, `dnstt_pubkey`, `dnstt_privkey`.

3. `openvpn_settings` (singleton)
   - Purpose: OpenVPN server behavior and transport/obfuscation tuning.
   - Critical columns: `port`, `protocol`, `ipv4_network`, `ipv4_netmask`, `data_ciphers`, `tls_mode`, `tun_mtu`, `mssfix`, `obfuscation_mode`, `proxy_*`, `stunnel_port`, `ws_*`.

4. `wireguard_settings` (singleton)
   - Purpose: WireGuard server interface parameters.
   - Critical columns: `interface_name`, `listen_port`, `address_range`, `endpoint_address`, `server_private_key`, `server_public_key`.

5. `vpn_users`
   - Purpose: canonical subscriber/user entity across protocols.
   - Critical columns:
     - Identity: `username`, `password`.
     - Access limits: `traffic_limit_bytes`, `traffic_used_bytes`, `access_start_at`, `access_expires_at`, `max_concurrent_connections`, `current_connections`, `is_*_exceeded`, `is_expired`, `is_enabled`.
     - WireGuard identity: `wg_private_key`, `wg_public_key`, `wg_allocated_ip`.
     - Legacy compatibility: `data_limit_gb`, `expiry_date`, `max_devices`.

6. `vpn_configs`
   - Purpose: per-user per-protocol config records.
   - Critical columns: `user_id`, `protocol`, `is_active`, protocol-specific fields (OpenVPN cert fields, WireGuard key/allowed IPs, Sing-box placeholders).

7. `vpn_clients`
   - Purpose: OpenVPN-oriented client entity used by legacy/parallel management flows.
   - Critical columns: `name`, `protocol`, `status`, cert metadata, usage counters.

8. `routing_rules`
   - Purpose: dynamic PBR policy store.
   - Critical columns:
     - Rule identity: `rule_name`, `status`.
     - Match/action: `ingress_iface`, `dest_cidr`, `fwmark`, `proxy_port`, `protocol`.
     - iproute linkage: `table_id`, `table_name`.

9. `audit_logs`
   - Purpose: immutable admin action trail.
   - Critical columns: `admin_username`, `action`, `resource_type`, `resource_id`, `ip_address`, `success`, `details`, `created_at`.

### Migration Model

- `init_db()` creates missing tables and applies additive migrations.
- Routing migrations explicitly ensure `dest_cidr`, `description`, `protocol`, `table_id`, `table_name`, `status` exist and are backfilled.
- OpenVPN/WireGuard/General settings tables are aggressively normalized with defaults and compatibility transformations.

---

## Network Architecture

### Control Plane vs Data Plane

- Control plane: FastAPI routers + SQLite persistence.
- Data plane: Linux networking primitives (`iptables`, `ip rule`, `rt_tables`), OpenVPN/WireGuard daemons, DNSTT processes/systemd units.

### PBR Flow (Ingress -> PBRManager -> Egress)

1. Ingress traffic arrives on a VPN interface (`tun*`, `wg*`, wildcard groups like `tun+`, `wg+`, `ppp+`).
2. A routing rule from `routing_rules` defines match + action:
   - Match: ingress interface + optional destination CIDR (`dest_cidr`) + protocol.
   - Action: fwmark + redirect to local proxy port.
3. `PBRManager.apply_all_active_rules()`:
   - Flushes prior Atlas-managed NAT/MANGLE/iprule state (using rule comments/prefix guards).
   - Ensures routing table entry in `/etc/iproute2/rt_tables` (`atlas_pbr_*`).
   - Adds `ip rule fwmark <N> lookup <table>`.
   - Adds `iptables -t mangle PREROUTING ... -j MARK --set-mark <N>`.
   - Adds `iptables -t nat PREROUTING ... -j REDIRECT --to-ports <proxy_port>`.
4. Redirected packets land on local tunnel/proxy listeners (DNSTT/OpenVPN-adjacent local services depending on mode).
5. Egress leaves through selected tunnel path to external DNS/Internet destinations.

### DNSTT Orchestrator Interaction

- DNSTT manager (`DNSTTTunnel`) supports standalone and relay architecture.
- Key lifecycle:
  - Generates/loads domain-scoped key files (`*_server.key`, `*_server.pub`).
  - Persists key material into `general_settings`.
- Daemon lifecycle:
  - Creates/updates systemd units (`dnstt-server`, `dnstt-client`, optional optimizer/multiplexer).
  - Applies DNS/NAT redirection rules needed for transport operation.
- Resolver/transport strategies:
  - `failover`, `least-latency`, `round-robin`, and duplication mode.
  - Collects telemetry and writes strategy/latency history to DB JSON columns.

---

## API Endpoints (High-Level)

### `auth` router (`/api/auth`)
- Login/token issuance, current admin profile, admin password change.
- Includes IP-based login throttling with DB-backed limits.

### `settings` router (`/api/settings`)
- General settings CRUD.
- OpenVPN settings CRUD.
- WireGuard settings CRUD.
- DNSTT install/generate/runtime endpoints, diagnostics, MTU probe, client profile generation.
- Server public IP lookup and SSL issuance stream.

### `routing` router (`/api/routing`)
- Interface discovery (`/interfaces`) with static + live interfaces.
- Live proxy listener discovery (`/proxy-ports`).
- Next fwmark suggestion (`/next-fwmark`).
- Routing rule CRUD and kernel reapply (`/rules/reapply`).

### `vpn_users` router (`/api/users`)
- Full user CRUD, runtime metrics, password operations.
- Protocol-specific config generation/download/revoke.
- Limit checks and runtime disconnect controls.

### `openvpn` router (`/api/openvpn`)
- OpenVPN client CRUD, cert revoke/delete, config generation/download.
- Service status/control and runtime health.

### `system` router (`/api/system`)
- Backup/restore, time/NTP controls, service actions, service logs.
- WireGuard diagnostics and placeholder tunnel command execution.

### `terminal` router (`/api/terminal`)
- Local and foreign terminal command execution (audited).

### `dashboard` router (`/api/dashboard`)
- Aggregated operational overview (users, traffic, service/runtime health).

### `logs` router (`/api/logs`)
- Paginated/filterable audit log retrieval.

---

## Frontend Architecture (Routing-Critical)

The `frontend/settings.html` Alpine app is the primary control UI.

### Routing UI Layer

- Dedicated tab: `Routing (PBR)`.
- Table view over `routingRules`.
- Modal for create/edit using `routingRuleDraft`.
- Actions:
  - Create/update: `submitRoutingRule()`.
  - Delete: `deleteRoutingRule()`.
  - Enable/disable: `toggleRoutingRuleStatus()`.
  - Kernel sync: `reapplyRoutingRules()`.

### Data Fetch + Fallback Model

- Interfaces loaded from `/api/routing/interfaces` -> `routingInterfaces`.
- Proxy ports loaded from `/api/routing/proxy-ports` -> `routingProxyPorts`.
- Built-in defensive fallbacks:
  - Interface fallback: `['tun+']`.
  - Proxy fallback: `[{ port: 7100, label: '7100 (Default DNSTT)' }]`.
- New-rule fwmark path:
  - preferred: `/api/routing/next-fwmark`
  - fallback: client-side `computeNextRoutingFwmark()`.

### UX Safety

- Required field checks before submit.
- API error normalization through `getApiErrorMessage()`.
- Unauthorized path always clears token and redirects to `/login`.

---

## Known Constraints / Future Hooks (Telegram Bot Integration)

The upcoming Telegram Sales & Management Bot can safely integrate at these seams:

1. User/subscription lifecycle
   - Reuse `vpn_users` domain (create user, set limits, expiry, reset credentials).
   - Hook into `audit_logs` for bot-originated actions (`resource_type=telegram_bot` suggested).

2. Credential delivery
   - Reuse existing config endpoints and generators:
     - OpenVPN: download/config payload endpoints.
     - WireGuard: generated `.conf` payload path.
   - Bot can package/download links or direct payload messages.

3. Routing-aware upsell/business logic
   - Use `routing_rules` and `general_settings.tunnel_mode` to expose available egress products/plans.

4. Operational health hooks
   - Consume `/api/dashboard/overview`, DNSTT diagnostics, service status APIs for support automation.

5. Security constraints
   - Bot must use an internal service identity, not admin JWT reuse.
   - Never expose `foreign_ssh_password`, `dnstt_privkey`, or raw private materials in bot responses.

6. Consistency safeguards
   - DB is the source of truth; bot writes should trigger existing runtime sync mechanisms instead of direct shell mutation.
   - For routing changes, invoke the same router flow so `_apply_runtime_or_rollback` protections remain active.

---

## Relationship Map (Mental Model)

- Frontend (`settings.html`) -> REST API routers -> SQLAlchemy models/SQLite.
- Router mutations -> runtime managers (`OpenVPNManager`, `WireGuardManager`, `DNSTTTunnel`, `PBRManager`) -> host/network state.
- `PBRManager` is the kernel policy applicator; `routing_rules` is its declarative input.
- `TunnelManager` selects active tunnel implementation from `general_settings.tunnel_mode`.
- `general_settings` is the orchestration spine connecting UI, tunnel behavior, DNS/SSL/system controls, and remote relay metadata.

This is the current authoritative architecture baseline for regression-safe future development.

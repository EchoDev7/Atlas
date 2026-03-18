# Changelog

All notable changes to this project are documented in this file.

## [v6.0.0] - 2026-03-18

### 🚀 Core Upgrades
- Upgraded Sing-box integration to fully support `1.12+` DNS schema.
- Removed legacy DNS server structures and migrated to rule-driven resolver behavior.

### 🛡️ Security & Stability
- Hardened TLS handling across Sing-box protocols using absolute certificate paths.
- Enforced path-first certificate routing for `custom_domain` mode to avoid inline key corruption issues.
- Added resolver defaults required by modern Sing-box deprecation migration.

### 🌐 Client Compatibility
- Improved ALPN handling and TLS parameter consistency for strict clients.
- Preserved fingerprint-aware URI generation and transport-specific query construction.

### 🔧 OpenConnect
- Fixed `ocserv` startup failures by ensuring generated configs include required `socket-file` directive.

### 🧹 Maintenance
- Cleaned up legacy TLS helper code paths superseded by path-based certificate workflow.

## [v2.0.0] - 2026-03-09

### 🚀 Major Features
- **Unified VPN User Architecture** finalized for OpenVPN and WireGuard under shared user lifecycle management.
- **WireGuard Stateless Runtime Engine** completed with asynchronous runtime polling and restart-safe traffic delta accounting.
- **Protocol-aware operational controls** expanded in panel Server Operations:
  - WireGuard reset action
  - WireGuard service logs view
  - WireGuard diagnostics endpoint and UI panel
- **Cross-protocol runtime orchestration** hardened through scheduler-driven reconciliation and centralized protocol registry usage.

### 🛡️ Security & Stability
- Enforced IPv4 forwarding safeguards during WireGuard apply/sync paths.
- Hardened WireGuard NAT/FORWARD runtime rule enforcement after reload operations.
- Added WAN interface detection and fallback strategy for robust masquerade rule application.
- Improved service-action safety by syncing WireGuard peers before start/restart operations.
- Reinforced multi-protocol kill-switch behavior and concurrency-safe state reconciliation using async lock-protected background jobs.

### 🐛 Bug Fixes
- Fixed WireGuard "connected but no internet" regressions tied to runtime NAT rule drift after sync/restart.
- Fixed empty peer runtime scenarios by adding backward-compatible peer-material fallback from active legacy config fields.
- Fixed service-level reset behavior where stale config state could bring WireGuard up without peers.
- Improved runtime observability for handshake/NAT/route triage via diagnostics payload and panel rendering.

### 🧹 Maintenance
- Removed obsolete skeleton router files (`backend/routers/singbox.py`, `backend/routers/wireguard.py`).
- Performed safe repository cleanup pass and documented outcomes in `CODEBASE_CLEANUP_REPORT_2026-03-09.md`.
- Release metadata bumped to **Atlas v2.0.0** across backend and UI display.

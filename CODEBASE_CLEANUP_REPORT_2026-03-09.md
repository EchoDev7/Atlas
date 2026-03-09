# Atlas Codebase Cleanup Report (2026-03-09)

## Scope
This cleanup was performed with a **stability-first** strategy because the panel is in active use.
Focus areas:
- WireGuard/OpenVPN integration paths
- service operations and runtime sync
- dead-code and low-risk cleanup candidates

## What Was Audited
- Backend routers: `vpn_users.py`, `system.py`, `settings.py`, `openvpn.py`
- Core protocol managers: `core/wireguard.py`, `core/openvpn.py`
- Scheduler/runtime reconciliation: `services/scheduler_service.py`
- Protocol plugin registry: `services/protocols/registry.py`
- Frontend server-ops page: `frontend/settings.html`
- Main app route mapping and static serving: `backend/main.py`

## Key Findings
1. WireGuard runtime/networking path is now healthy (NAT + ip_forward + service operations + diagnostics).
2. Root cause for zero-handshake period was peer sync/data consistency, and it has been fixed in recent patches.
3. Some code smells are present, but many are not safe to remove immediately without broader regression testing.
4. OpenVPN router had small import-level dead code (safe to remove).

## Changes Applied In This Cleanup Pass
### 1) Safe dead-code removal (implemented)
- Removed unused imports from `backend/routers/openvpn.py`:
  - `List` (unused)
  - `VPNClientResponse` (unused)

This change is behavior-neutral and low risk.

## Important Existing Hardening (already shipped in recent fixes)
- WireGuard NAT/PostUp/PostDown stabilization and runtime firewall enforcement
- WAN interface fallback handling
- WireGuard service logs + reset in Server Operations
- WireGuard diagnostics endpoint and panel block
- Pre-restart WireGuard sync in service action path
- Legacy WireGuard peer material fallback in sync

## Deferred Cleanup (kept intentionally to avoid regressions)
1. Full removal or merge of legacy OpenVPN client model/router (`vpn_client` paths)
   - Requires API contract review and migration plan.
2. Large frontend template consolidation
   - Needs UI regression pass and route/static serving review.
3. Broad refactor of protocol service abstractions
   - Recommended before adding next protocols, but should be done in a dedicated branch with tests.

## Recommendation for Next Protocol Additions
Use a strict protocol plugin boundary:
- keep protocol-specific runtime logic in manager/service plugin classes
- keep shared user lifecycle in `vpn_users` with protocol registry dispatch
- require per-protocol health/sync diagnostics endpoint before production enablement
- include schema migration + fallback readers for legacy rows

## Risk Statement
This cleanup pass intentionally applied only **low-risk, behavior-neutral** changes to avoid destabilizing production behavior.

## Validation
- Python syntax check passes for modified backend files.
- No route contract changes were introduced in this cleanup pass.

# ATLAS ABSOLUTE IMMUTABLE PROTOCOL LAWS

These laws are non-negotiable and permanently binding for all current and future Atlas engineering work.

## LAW 1: STRICT PLUGIN ARCHITECTURE

The system is fundamentally plugin-based. Every new protocol or feature MUST be implemented as an isolated, modular plugin. Core files must never be polluted with protocol-specific hardcoded logic.

## LAW 2: 100% DYNAMIC IMPLEMENTATION

Hardcoding is strictly forbidden. UI elements (status headers, buttons, dropdowns), backend settings, and shell scripts MUST be dynamic. When a new protocol is added to the registry, the system (frontend and backend) must automatically render its settings, actions, and UI without requiring manual HTML/Bash copy-pasting.

## LAW 3: THE BENCHMARK PATTERN

Every new protocol must strictly follow the established golden benchmark (OpenVPN/WireGuard). Whatever the benchmark does (database relations, global settings, installation/update hooks, routing rules, restart actions), the new protocol MUST replicate flawlessly and uniformly.

## LAW 4: CLIENT MANAGEMENT PARITY

The User/Client management section MUST strictly adhere to the benchmark for any new protocol. This includes user creation, real-time Online/Offline status tracking, UI badges, quota enforcement, and disconnection logic. No exceptions.

---

### Enforcement Clause

- These 4 laws are permanent architecture policy.
- They apply automatically to every future protocol task without reminder.
- Any implementation violating these laws must be rejected and refactored before merge.
